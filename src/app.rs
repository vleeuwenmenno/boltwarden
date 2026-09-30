use crate::backend::{AppBackend, BackendError};
use crate::config::{self, AppSettings};
use crate::icons::IconCache;
use crate::model::{BwItem, BwItemDetail, SshAgentStatus, SyncStatus, TotpCode};
use crate::ui::auth::{AuthAction, AuthState, draw_auth};
use crate::ui::search::{SearchAction, SearchState, SearchView, draw_search};
use crate::ui::ssh_approval::{SshApprovalAction, SshApprovalUiState, draw_ssh_approval};
use crate::ui::summary::{SummaryAction, SummaryState, draw_summary};
use crate::ui::theme::theme;
use crate::ui::two_factor::{TwoFactorAction, TwoFactorState, draw_two_factor};
use eframe::egui;
use egui::Context;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const UNFOCUS_HIDE_GRACE: Duration = Duration::from_millis(350);
/// How long the window must stay unfocused before it hides. Short focus blips (a
/// notification, Hyprland reshuffling focus while the popup maps) must not close it.
const UNFOCUS_HIDE_DELAY: Duration = Duration::from_millis(400);
const RESTORE_RECENT_ITEM_WINDOW: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    Auth,
    TwoFactor,
    Search,
    SshApproval,
}

enum BwResponse {
    Login(Result<(), BackendError>),
    TwoFactor(Result<(), BackendError>),
    Search {
        query: String,
        result: Result<Vec<BwItem>, BackendError>,
        warning: Option<String>,
        status: SyncStatus,
        icons_url: Option<String>,
    },
    Detail {
        id: String,
        result: Result<BwItemDetail, BackendError>,
    },
    Totp {
        id: String,
        result: Result<TotpCode, BackendError>,
    },
    SshApprovalDecision(Result<(), String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopupCommand {
    Show,
    Hide,
    Toggle,
    SshApproval {
        auto_hide: bool,
    },
    Unlock {
        auto_hide: bool,
        inhibit_focus_hide: bool,
    },
    Quit,
}

pub struct App {
    backend: AppBackend,
    screen: Screen,
    auth_state: AuthState,
    two_factor_state: TwoFactorState,
    search_state: SearchState,
    ssh_approval_state: SshApprovalUiState,
    ssh_approval_return: Option<(Screen, bool)>,
    summary_state: SummaryState,
    icons: IconCache,
    rx: mpsc::Receiver<BwResponse>,
    tx: mpsc::Sender<BwResponse>,
    popup_rx: mpsc::Receiver<PopupCommand>,
    auth_auto_hide: bool,
    auth_inhibit_focus_hide: bool,
    settings: AppSettings,
    ssh_agent_status: SshAgentStatus,
    window_visible: bool,
    summary_open: bool,
    focus_hide_enabled_at: Instant,
    unfocused_since: Option<Instant>,
}

impl Default for App {
    fn default() -> Self {
        let (_tx, popup_rx) = mpsc::channel();
        Self::new(AppBackend::local(), popup_rx)
    }
}

impl App {
    fn poll_popup_commands(&mut self, ctx: &Context) {
        while let Ok(command) = self.popup_rx.try_recv() {
            match command {
                PopupCommand::Show => self.show_quick_access(ctx),
                PopupCommand::Hide => self.hide_quick_access(ctx),
                PopupCommand::Toggle => {
                    if self.window_visible {
                        self.hide_quick_access(ctx);
                    } else {
                        self.show_quick_access(ctx);
                    }
                }
                PopupCommand::SshApproval { auto_hide } => {
                    self.enter_ssh_approval(ctx, auto_hide);
                }
                PopupCommand::Unlock {
                    auto_hide,
                    inhibit_focus_hide,
                } => {
                    self.enter_unlock_prompt(ctx, auto_hide, inhibit_focus_hide);
                }
                PopupCommand::Quit => {
                    Self::exit_now();
                }
            }
        }
    }

    pub fn new(backend: AppBackend, popup_rx: mpsc::Receiver<PopupCommand>) -> Self {
        let (tx, rx) = mpsc::channel();
        let screen = if backend.has_session() {
            Screen::Search
        } else {
            Screen::Auth
        };
        let settings = config::load_settings();
        let ssh_agent_status = backend.ssh_agent_status(&settings);
        let mut app = Self {
            backend,
            screen,
            auth_state: AuthState::default(),
            two_factor_state: TwoFactorState::default(),
            search_state: SearchState::default(),
            ssh_approval_state: SshApprovalUiState::default(),
            ssh_approval_return: None,
            summary_state: SummaryState::default(),
            rx,
            tx,
            popup_rx,
            auth_auto_hide: false,
            auth_inhibit_focus_hide: false,
            icons: IconCache::new(settings.show_website_icons),
            settings,
            ssh_agent_status,
            window_visible: true,
            summary_open: false,
            focus_hide_enabled_at: Instant::now() + UNFOCUS_HIDE_GRACE,
            unfocused_since: None,
        };
        app.restore_recent_item_on_start();
        app
    }
}

impl App {
    fn spawn_login(&self, server_url: String, email: String, password: String, remember: bool) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let res = backend.login(&server_url, &email, &password, remember);
            let _ = tx.send(BwResponse::Login(res));
        });
    }

    fn spawn_two_factor(&self) {
        let tx = self.tx.clone();
        let provider = self.two_factor_state.selected_provider;
        let token = self.two_factor_state.token.clone();
        let remember = self.two_factor_state.remember;
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let res = match provider {
                Some(provider) => backend.complete_two_factor(provider, &token, remember),
                None => Err(BackendError::Message("missing two factor provider".into())),
            };
            let _ = tx.send(BwResponse::TwoFactor(res));
        });
    }

    fn spawn_search(&self, query: String) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let (res, warning, status, icons_url) = match backend.list_items(&query) {
                Ok(result) => (Ok(result.items), result.warning, result.status, result.icons_url),
                Err(error) => (Err(error), None, SyncStatus::default(), None),
            };
            let _ = tx.send(BwResponse::Search {
                query,
                result: res,
                warning,
                status,
                icons_url,
            });
        });
    }

    fn spawn_detail(&self, id: String) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let result = backend.get_item(&id);
            let _ = tx.send(BwResponse::Detail { id, result });
        });
    }

    fn spawn_totp(&self, id: String) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let result = backend.get_totp(&id);
            let _ = tx.send(BwResponse::Totp { id, result });
        });
    }

    fn spawn_ssh_approval_decision(&self, decision: crate::model::SshApprovalDecision) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let result = backend.decide_ssh_approval(decision).map(|_| ());
            let _ = tx.send(BwResponse::SshApprovalDecision(result));
        });
    }

    fn poll_responses(&mut self, ctx: &Context) {
        while let Ok(resp) = self.rx.try_recv() {
            match resp {
                BwResponse::Login(res) => {
                    self.auth_state.in_flight = false;
                    match res {
                        Ok(()) => {
                            self.screen = Screen::Search;
                            self.summary_open = false;
                            self.auth_state.password.clear();
                            self.auth_state.error = None;
                            self.auth_state.notice = None;
                            self.auth_inhibit_focus_hide = false;
                            self.search_state.reset_for_reopen();
                            self.ssh_agent_status = self.backend.ssh_agent_status(&self.settings);
                            if self.auth_auto_hide {
                                self.auth_auto_hide = false;
                                self.hide_quick_access(ctx);
                                return;
                            }
                        }
                        Err(e) => match e {
                            BackendError::TwoFactorRequired(providers) => {
                                self.two_factor_state.set_providers(providers);
                                self.auth_state.in_flight = false;
                                self.auth_state.error = None;
                                self.screen = Screen::TwoFactor;
                            }
                            other => {
                                self.auth_state.error = Some(other.to_string());
                            }
                        },
                    }
                }
                BwResponse::TwoFactor(res) => {
                    self.two_factor_state.in_flight = false;
                    match res {
                        Ok(()) => {
                            self.screen = Screen::Search;
                            self.summary_open = false;
                            self.auth_state.password.clear();
                            self.auth_state.notice = None;
                            self.auth_inhibit_focus_hide = false;
                            self.two_factor_state.token.clear();
                            self.two_factor_state.error = None;
                            self.search_state.reset_for_reopen();
                            self.ssh_agent_status = self.backend.ssh_agent_status(&self.settings);
                            if self.auth_auto_hide {
                                self.auth_auto_hide = false;
                                self.hide_quick_access(ctx);
                                return;
                            }
                        }
                        Err(e) => {
                            self.two_factor_state.error = Some(e.to_string());
                            self.two_factor_state.token.clear();
                            self.two_factor_state.focus_token = true;
                        }
                    }
                }
                BwResponse::Search {
                    query,
                    result,
                    warning,
                    status,
                    icons_url,
                } => {
                    self.icons.set_icons_url(icons_url);
                    // Clear in_flight before the stale check, otherwise needs_search() stays
                    // false and a query typed while this request ran would never be sent.
                    self.search_state.in_flight = false;
                    if query != self.search_state.query.trim() {
                        ctx.request_repaint();
                        continue;
                    }
                    match result {
                        Ok(items) => {
                            self.search_state.results = items;
                            self.search_state.selected = 0;
                            self.search_state.error = None;
                            self.search_state.warning = warning;
                            self.search_state.sync_status = Some(status);
                        }
                        Err(e) => {
                            self.search_state.error = Some(e.to_string());
                            self.search_state.warning = None;
                        }
                    }
                }
                BwResponse::Detail { id, result } => {
                    // A reply for an item the user already navigated away from must not
                    // overwrite the item that is open now.
                    if self.summary_state.detail_id.as_deref() != Some(id.as_str()) {
                        continue;
                    }
                    self.summary_state.in_flight = false;
                    match result {
                        Ok(detail) => {
                            self.summary_state.detail = Some(detail);
                            self.summary_state.error = None;
                            self.summary_state.selected_field = 0;
                            self.summary_state.reveal_fields.clear();
                        }
                        Err(e) => {
                            self.summary_state.error = Some(e.to_string());
                        }
                    }
                }
                BwResponse::Totp { id, result } => {
                    if self.summary_state.detail_id.as_deref() != Some(id.as_str()) {
                        continue;
                    }
                    self.summary_state.totp_in_flight = false;
                    match result {
                        Ok(code) => {
                            self.summary_state.totp = Some(code);
                            self.summary_state.totp_fetched_at = Some(Instant::now());
                        }
                        Err(_) => {
                            self.summary_state.totp = None;
                            self.summary_state.totp_fetched_at = Some(Instant::now());
                        }
                    }
                }
                BwResponse::SshApprovalDecision(result) => {
                    if let Err(e) = result {
                        self.search_state.warning =
                            Some(format!("could not resolve SSH approval: {e}"));
                    }
                }
            }
            ctx.request_repaint();
        }
    }

    fn hide_quick_access(&mut self, ctx: &Context) {
        debug_log("hide quick access");
        Self::hide_viewport_now(ctx);
        self.window_visible = false;
        self.summary_open = false;
        self.unfocused_since = None;
        self.summary_state.reveal_fields.clear();
        Self::exit_now();
    }

    fn hide_viewport_now(ctx: &Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        ctx.request_repaint();
    }

    fn exit_now() -> ! {
        unsafe {
            libc::_exit(0);
        }
    }

    fn show_quick_access(&mut self, ctx: &Context) {
        debug_log("show quick access");
        self.window_visible = true;
        self.auth_auto_hide = false;
        self.auth_inhibit_focus_hide = false;
        self.focus_hide_enabled_at = Instant::now() + UNFOCUS_HIDE_GRACE;
        self.unfocused_since = None;

        if self.backend.has_session() {
            self.screen = Screen::Search;
            self.summary_open = false;
            self.search_state.reset_for_reopen();
            self.restore_recent_item_on_start();
        }

        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn enter_ssh_approval(&mut self, ctx: &Context, auto_hide: bool) {
        debug_log("show SSH approval");
        self.window_visible = true;
        self.auth_auto_hide = false;
        self.auth_inhibit_focus_hide = false;
        self.focus_hide_enabled_at = Instant::now() + UNFOCUS_HIDE_GRACE;
        self.unfocused_since = None;
        if self.screen != Screen::SshApproval {
            self.ssh_approval_return = Some((self.screen.clone(), self.summary_open));
        }
        let request = self.backend.ssh_approval();
        self.ssh_approval_state
            .reset_for_request(request, auto_hide);
        if self.ssh_approval_state.request.is_none() {
            self.ssh_approval_state.status = self.backend.ssh_approval_status();
        }
        self.screen = Screen::SshApproval;
        self.summary_open = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn enter_unlock_prompt(&mut self, ctx: &Context, auto_hide: bool, inhibit_focus_hide: bool) {
        debug_log("show SSH unlock prompt");
        self.window_visible = true;
        self.auth_auto_hide = auto_hide;
        self.auth_inhibit_focus_hide = inhibit_focus_hide;
        self.focus_hide_enabled_at = Instant::now() + UNFOCUS_HIDE_GRACE;
        self.unfocused_since = None;
        self.screen = Screen::Auth;
        self.summary_open = false;
        self.auth_state = AuthState::default();
        self.auth_state.notice =
            Some("Vault is locked. Unlock to let the SSH agent list or use your keys.".into());
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn leave_ssh_approval(&mut self, ctx: &Context) {
        let auto_hide = self.ssh_approval_state.auto_hide;
        self.ssh_approval_state.request = None;
        if auto_hide {
            self.hide_quick_access(ctx);
            return;
        }
        if let Some((screen, summary_open)) = self.ssh_approval_return.take() {
            self.screen = screen;
            self.summary_open = summary_open;
        } else {
            self.screen = if self.backend.has_session() {
                Screen::Search
            } else {
                Screen::Auth
            };
            self.summary_open = false;
        }
        self.focus_hide_enabled_at = Instant::now() + UNFOCUS_HIDE_GRACE;
        self.unfocused_since = None;
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn resolve_ssh_approval_optimistically(
        &mut self,
        ctx: &Context,
        decision: crate::model::SshApprovalDecision,
    ) {
        let auto_hide = self.ssh_approval_state.auto_hide;
        self.ssh_approval_state.request = None;

        if auto_hide {
            Self::hide_viewport_now(ctx);
            let _ = self.backend.send_ssh_approval_decision(decision);
            Self::exit_now();
        }

        self.spawn_ssh_approval_decision(decision);

        if let Some((screen, summary_open)) = self.ssh_approval_return.take() {
            self.screen = screen;
            self.summary_open = summary_open;
        } else {
            self.screen = if self.backend.has_session() {
                Screen::Search
            } else {
                Screen::Auth
            };
            self.summary_open = false;
        }
        self.focus_hide_enabled_at = Instant::now() + UNFOCUS_HIDE_GRACE;
        self.unfocused_since = None;
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn escape_pressed(ctx: &Context) -> bool {
        ctx.input(|i| {
            i.key_pressed(egui::Key::Escape)
                || i.events.iter().any(|event| {
                    matches!(
                        event,
                        egui::Event::Key {
                            key: egui::Key::Escape,
                            pressed: true,
                            ..
                        }
                    )
                })
        })
    }

    fn viewport_focused(ctx: &Context) -> Option<bool> {
        ctx.input(|i| i.viewport().focused)
    }

    fn should_hide_after_focus_loss(&mut self, ctx: &Context) -> bool {
        // Only the search list hides on focus loss. Login, 2FA and SSH prompts stay up:
        // people switch to a phone, a password manager or a terminal while filling them in.
        if !self.window_visible
            || self.screen != Screen::Search
            || self.search_state.in_flight
            || self.auth_auto_hide
            || self.auth_inhibit_focus_hide
            || self.summary_open
            || self.search_state.view == SearchView::Settings
            || Instant::now() < self.focus_hide_enabled_at
        {
            self.unfocused_since = None;
            return false;
        }

        match Self::viewport_focused(ctx) {
            Some(false) => {
                let since = *self.unfocused_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= UNFOCUS_HIDE_DELAY {
                    debug_log("hide because viewport stayed unfocused");
                    return true;
                }
            }
            Some(true) => {
                self.unfocused_since = None;
            }
            None => {}
        }

        false
    }

    fn open_result(&mut self, idx: usize) {
        if let Some(item) = self.search_state.results.get(idx) {
            let item_id = item.id.clone();
            self.summary_state.detail = None;
            self.summary_state.in_flight = true;
            self.summary_state.detail_id = Some(item_id.clone());
            self.summary_state.totp = None;
            self.summary_state.totp_fetched_at = None;
            self.summary_state.totp_in_flight = false;
            self.summary_state.error = None;
            self.summary_open = true;
            self.unfocused_since = None;
            if self.settings.restore_recent_item {
                let recent_id = item_id.clone();
                std::thread::spawn(move || {
                    let _ = config::save_recent_item(&recent_id);
                });
            }
            self.spawn_detail(item_id);
        }
    }

    fn return_to_search(&mut self, ctx: &Context) {
        self.summary_open = false;
        self.summary_state.reveal_fields.clear();
        let _ = config::clear_recent_item();
        self.search_state.focus_search = true;
        self.focus_hide_enabled_at = Instant::now() + UNFOCUS_HIDE_GRACE;
        self.unfocused_since = None;
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn restore_recent_item_on_start(&mut self) {
        if self.screen != Screen::Search || !self.settings.restore_recent_item {
            return;
        }
        let Some(recent) = config::load_recent_item() else {
            return;
        };
        if !config::recent_item_is_fresh(&recent, RESTORE_RECENT_ITEM_WINDOW) {
            let _ = config::clear_recent_item();
            return;
        }

        self.search_state.reset_for_reopen();
        self.search_state.focus_search = false;
        self.summary_state = SummaryState::default();
        self.summary_state.detail_id = Some(recent.id.clone());
        self.summary_state.in_flight = true;
        self.summary_open = true;
        self.unfocused_since = None;
        self.spawn_detail(recent.id);
    }

    fn refresh_summary_totp_if_needed(&mut self) {
        if self.summary_state.needs_totp_refresh() {
            if let Some(id) = self.summary_state.detail_id.clone() {
                self.summary_state.totp_in_flight = true;
                self.spawn_totp(id);
            }
        }
    }

    fn save_and_apply_settings(&mut self) {
        match self.backend.apply_settings(&self.settings) {
            Ok(status) => {
                self.ssh_agent_status = status;
                self.search_state.warning = None;
            }
            Err(e) => {
                self.search_state.warning = Some(format!("could not save settings: {e}"));
                self.ssh_agent_status = self.backend.ssh_agent_status(&self.settings);
            }
        }
    }
}

impl eframe::App for App {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        theme().bg.to_normalized_gamma_f32()
    }

    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.poll_popup_commands(ctx);

        if ctx.input(|i| i.viewport().close_requested()) {
            debug_log("viewport close requested");
            Self::exit_now();
        }

        self.poll_responses(ctx);
        self.icons.poll(ctx);

        // Screens with their own Escape handling must not hide the whole window.
        let escape_handled_by_screen = match self.screen {
            Screen::TwoFactor | Screen::SshApproval => true,
            Screen::Auth => self.auth_state.confirm_forget,
            Screen::Search => self.summary_open || self.search_state.view == SearchView::Settings,
        };
        if self.window_visible && !escape_handled_by_screen && Self::escape_pressed(ctx) {
            debug_log("hide because escape was pressed");
            self.hide_quick_access(ctx);
            return;
        }

        if self.should_hide_after_focus_loss(ctx) {
            self.hide_quick_access(ctx);
            return;
        }

        match self.screen {
            Screen::Auth => self.update_auth(ctx),
            Screen::TwoFactor => self.update_two_factor(ctx),
            Screen::SshApproval => self.update_ssh_approval(ctx),
            Screen::Search if self.summary_open => self.update_summary(ctx),
            Screen::Search => self.update_search(ctx),
        }
        self.icons.start_queued(ctx);
        self.schedule_repaint(ctx);
    }
}

impl App {
    fn update_auth(&mut self, ctx: &Context) {
        let Some(action) = draw_auth(ctx, &mut self.auth_state) else {
            return;
        };
        match action {
            AuthAction::Login => {
                self.auth_state.in_flight = true;
                self.auth_state.error = None;
                self.spawn_login(
                    self.auth_state.server_url.trim().to_string(),
                    self.auth_state.email.trim().to_string(),
                    self.auth_state.password.clone(),
                    self.auth_state.remember,
                );
            }
            AuthAction::ForgetUser => {
                if let Err(e) = self.backend.clear_saved_session() {
                    self.auth_state.error = Some(format!("could not forget saved user: {e}"));
                    self.auth_state.confirm_forget = false;
                } else {
                    let _ = config::clear_recent_item();
                    self.auth_state.reset_to_full_login();
                }
            }
        }
    }

    fn update_two_factor(&mut self, ctx: &Context) {
        match draw_two_factor(ctx, &mut self.two_factor_state) {
            Some(TwoFactorAction::Verify) => {
                self.two_factor_state.in_flight = true;
                self.two_factor_state.error = None;
                self.spawn_two_factor();
            }
            Some(TwoFactorAction::Back) => {
                self.two_factor_state.token.clear();
                self.two_factor_state.error = None;
                self.auth_state.focus_password = true;
                self.screen = Screen::Auth;
            }
            None => {}
        }
    }

    fn update_ssh_approval(&mut self, ctx: &Context) {
        match draw_ssh_approval(
            ctx,
            &mut self.ssh_approval_state,
            self.settings.show_keyboard_shortcuts,
        ) {
            Some(SshApprovalAction::Decide(decision)) => {
                self.resolve_ssh_approval_optimistically(ctx, decision);
            }
            Some(SshApprovalAction::Back) => self.leave_ssh_approval(ctx),
            None => {}
        }
    }

    fn update_summary(&mut self, ctx: &Context) {
        self.search_state.focus_search = false;
        self.refresh_summary_totp_if_needed();
        match draw_summary(
            ctx,
            &mut self.summary_state,
            self.settings.show_keyboard_shortcuts,
            &mut self.icons,
        ) {
            Some(SummaryAction::Copied) if self.settings.close_after_copy => {
                self.hide_quick_access(ctx);
            }
            Some(SummaryAction::Back) => self.return_to_search(ctx),
            _ => {}
        }
    }

    fn update_search(&mut self, ctx: &Context) {
        self.search_state.reset_results_for_empty_query();
        if self.search_state.needs_search() {
            self.search_state.in_flight = true;
            self.search_state.error = None;
            self.search_state.mark_queried();
            self.spawn_search(self.search_state.query.trim().to_string());
        }

        let Some(action) = draw_search(
            ctx,
            &mut self.search_state,
            &self.settings,
            &self.ssh_agent_status,
            &mut self.icons,
        ) else {
            return;
        };
        match action {
            SearchAction::OpenResult(idx) => self.open_result(idx),
            SearchAction::SetKeyboardShortcuts(show) => {
                self.settings.show_keyboard_shortcuts = show;
                self.save_and_apply_settings();
            }
            SearchAction::SetCloseAfterCopy(close) => {
                self.settings.close_after_copy = close;
                self.save_and_apply_settings();
            }
            SearchAction::SetShowWebsiteIcons(show) => {
                self.settings.show_website_icons = show;
                self.icons.set_enabled(show);
                if !show {
                    // Opting out also forgets which sites were looked up.
                    std::thread::spawn(|| {
                        let _ = crate::icons::clear_disk_cache();
                    });
                }
                self.save_and_apply_settings();
            }
            SearchAction::SetRestoreRecentItem(restore) => {
                self.settings.restore_recent_item = restore;
                if !restore {
                    let _ = config::clear_recent_item();
                }
                self.save_and_apply_settings();
            }
            SearchAction::SetLockOnSystemLock(lock) => {
                self.settings.lock_on_system_lock = lock;
                self.save_and_apply_settings();
            }
            SearchAction::SetLockAfterIdleTimeout(lock) => {
                self.settings.lock_after_idle_timeout = lock;
                self.save_and_apply_settings();
            }
            SearchAction::SetIdleLockTimeoutMinutes(minutes) => {
                self.settings.idle_lock_timeout_minutes = minutes.clamp(1, 1440);
                self.save_and_apply_settings();
            }
            SearchAction::SetSshAgentEnabled(enabled) => {
                self.settings.ssh_agent_enabled = enabled;
                self.save_and_apply_settings();
            }
            SearchAction::SetSshAgentSocketPath(path) => {
                self.settings.ssh_agent_socket_path = path;
                self.save_and_apply_settings();
            }
            SearchAction::LockVault => {
                if let Err(e) = self.backend.lock_vault() {
                    self.search_state.warning = Some(format!("could not lock vault: {e}"));
                } else {
                    let _ = config::clear_recent_item();
                    self.screen = Screen::Auth;
                    self.auth_state = AuthState::default();
                    self.two_factor_state = TwoFactorState::default();
                    self.search_state.reset_for_reopen();
                    self.summary_open = false;
                    // Drop the decrypted item (password, keys) along with the session.
                    self.summary_state = SummaryState::default();
                    self.ssh_agent_status = self.backend.ssh_agent_status(&self.settings);
                }
            }
        }
    }

    /// egui only redraws on input; ask for frames only when something changes on its own.
    fn schedule_repaint(&self, ctx: &Context) {
        if let Some(after) = self
            .summary_state
            .repaint_after()
            .filter(|_| self.summary_open)
        {
            ctx.request_repaint_after(after);
        }
        if self.screen == Screen::SshApproval {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        // Background work reports back over a channel, which does not wake egui.
        if self.search_state.in_flight
            || self.summary_state.in_flight
            || self.summary_state.totp_in_flight
            || self.auth_state.in_flight
            || self.two_factor_state.in_flight
        {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
        // Poll for the daemon's stdin commands and the unfocus timer.
        ctx.request_repaint_after(Duration::from_millis(250));
    }
}

fn debug_log(message: &str) {
    if std::env::var_os("BWQA_DEBUG").is_some() {
        eprintln!("[bw-quick-access] {message}");
    }
}
