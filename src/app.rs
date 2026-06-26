use crate::backend::{AppBackend, BackendError};
use crate::config::{self, AppSettings};
use crate::model::{BwItem, BwItemDetail, SshAgentStatus, SyncStatus};
use crate::ui::auth::{draw_auth, AuthAction, AuthState};
use crate::ui::footer::draw_footer;
use crate::ui::search::{
    draw_search_panel, search_window_height, SearchAction, SearchState, SearchView, SEARCH_HEIGHT,
    SEARCH_WIDTH,
};
use crate::ui::ssh_approval::{
    draw_ssh_approval, SshApprovalAction, SshApprovalUiState, SSH_APPROVAL_HEIGHT,
    SSH_APPROVAL_WIDTH,
};
use crate::ui::summary::{draw_summary, SummaryAction, SummaryState};
use crate::ui::two_factor::{draw_two_factor, TwoFactorAction, TwoFactorState};
use eframe::egui;
use egui::Context;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const UNFOCUS_HIDE_GRACE: Duration = Duration::from_millis(350);
const UNFOCUS_FALLBACK_DELAY: Duration = Duration::from_millis(120);
const RESTORE_RECENT_ITEM_WINDOW: Duration = Duration::from_secs(30);
const SUMMARY_WINDOW_WIDTH: f32 = 720.0;
const SUMMARY_WINDOW_HEIGHT: f32 = 640.0;
const SUMMARY_OUTER_MARGIN: f32 = 14.0;
const SUMMARY_FOOTER_GAP: f32 = 6.0;
const SUMMARY_FOOTER_TOTAL_HEIGHT: f32 = 34.0;

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
    },
    Detail(Result<BwItemDetail, BackendError>),
    Totp(Result<String, BackendError>),
    SshApprovalDecision(Result<(), String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopupCommand {
    Show,
    Hide,
    Toggle,
    SshApproval { auto_hide: bool },
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
    rx: mpsc::Receiver<BwResponse>,
    tx: mpsc::Sender<BwResponse>,
    popup_rx: mpsc::Receiver<PopupCommand>,
    settings: AppSettings,
    ssh_agent_status: SshAgentStatus,
    last_inner_size: Option<egui::Vec2>,
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
            settings,
            ssh_agent_status,
            last_inner_size: None,
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
            let (res, warning, status) = match backend.list_items(&query) {
                Ok(result) => (Ok(result.items), result.warning, result.status),
                Err(error) => (Err(error), None, SyncStatus::default()),
            };
            let _ = tx.send(BwResponse::Search {
                query,
                result: res,
                warning,
                status,
            });
        });
    }

    fn spawn_detail(&self, id: String) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let res = backend.get_item(&id);
            let _ = tx.send(BwResponse::Detail(res));
        });
    }

    fn spawn_totp(&self, id: String) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let res = backend.get_totp(&id);
            let _ = tx.send(BwResponse::Totp(res));
        });
    }

    fn spawn_ssh_approval_decision(
        &self,
        decision: crate::model::SshApprovalDecision,
    ) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let result = backend
                .decide_ssh_approval(decision)
                .map(|_| ());
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
                            self.last_inner_size = None;
                            self.auth_state.password.clear();
                            self.auth_state.error = None;
                            self.search_state.reset_for_reopen();
                            self.ssh_agent_status = self.backend.ssh_agent_status(&self.settings);
                        }
                        Err(e) => {
                            match e {
                                BackendError::TwoFactorRequired(providers) => {
                                    self.two_factor_state.set_providers(providers);
                                    self.auth_state.in_flight = false;
                                    self.auth_state.error = None;
                                    self.screen = Screen::TwoFactor;
                                }
                                other => {
                                    self.auth_state.error = Some(other.to_string());
                                }
                            }
                        }
                    }
                }
                BwResponse::TwoFactor(res) => {
                    self.two_factor_state.in_flight = false;
                    match res {
                        Ok(()) => {
                            self.screen = Screen::Search;
                            self.summary_open = false;
                            self.last_inner_size = None;
                            self.auth_state.password.clear();
                            self.two_factor_state.token.clear();
                            self.two_factor_state.error = None;
                            self.search_state.reset_for_reopen();
                            self.ssh_agent_status = self.backend.ssh_agent_status(&self.settings);
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
                } => {
                    if query != self.search_state.query.trim() {
                        ctx.request_repaint();
                        continue;
                    }
                    self.search_state.in_flight = false;
                    match result {
                        Ok(items) => {
                            self.search_state.results = items;
                            self.search_state.selected = 0;
                            self.search_state.error = None;
                            self.search_state.warning = warning;
                            self.search_state.sync_status = Some(status);
                            self.last_inner_size = None;
                        }
                        Err(e) => {
                            self.search_state.error = Some(e.to_string());
                            self.search_state.warning = None;
                            self.last_inner_size = None;
                        }
                    }
                }
                BwResponse::Detail(res) => {
                    self.summary_state.in_flight = false;
                    match res {
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
                BwResponse::Totp(res) => {
                    self.summary_state.totp_in_flight = false;
                    match res {
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
        self.last_inner_size = None;
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
        self.focus_hide_enabled_at = Instant::now() + UNFOCUS_HIDE_GRACE;
        self.unfocused_since = None;
        self.last_inner_size = None;
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

    fn leave_ssh_approval(&mut self, ctx: &Context) {
        let auto_hide = self.ssh_approval_state.auto_hide;
        self.ssh_approval_state.request = None;
        self.last_inner_size = None;
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
        self.last_inner_size = None;

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

    fn focus_lost_event(ctx: &Context) -> bool {
        ctx.input(|i| {
            i.events.iter().any(|event| {
                matches!(event, egui::Event::WindowFocused(false))
            })
        })
    }

    fn viewport_focused(ctx: &Context) -> Option<bool> {
        ctx.input(|i| i.viewport().focused)
    }

    fn should_hide_after_focus_loss(&mut self, ctx: &Context) -> bool {
        if !self.window_visible
            || self.screen == Screen::SshApproval
            || self.summary_open
            || self.search_state.view == SearchView::Settings
            || Instant::now() < self.focus_hide_enabled_at
        {
            self.unfocused_since = None;
            return false;
        }

        if Self::focus_lost_event(ctx) {
            debug_log("hide because focus-lost event was received");
            return true;
        }

        match Self::viewport_focused(ctx) {
            Some(false) => {
                let since = *self.unfocused_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= UNFOCUS_FALLBACK_DELAY {
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

    fn target_window_size(&self) -> egui::Vec2 {
        match self.screen {
            Screen::Auth => {
                if self.auth_state.has_saved_session {
                    let error_height = if self.auth_state.error.is_some() {
                        34.0
                    } else {
                        0.0
                    };
                    egui::vec2(SEARCH_WIDTH, SEARCH_HEIGHT + error_height)
                } else {
                    egui::vec2(SEARCH_WIDTH, 540.0)
                }
            }
            Screen::TwoFactor => egui::vec2(620.0, 260.0),
            Screen::SshApproval => egui::vec2(SSH_APPROVAL_WIDTH, SSH_APPROVAL_HEIGHT),
            Screen::Search if self.summary_open => {
                let shortcut_height = if self.settings.show_keyboard_shortcuts {
                    SUMMARY_FOOTER_GAP + SUMMARY_FOOTER_TOTAL_HEIGHT
                } else {
                    0.0
                };
                egui::vec2(
                    SUMMARY_WINDOW_WIDTH,
                    SUMMARY_WINDOW_HEIGHT - SUMMARY_FOOTER_GAP - SUMMARY_FOOTER_TOTAL_HEIGHT
                        + shortcut_height,
                )
            }
            Screen::Search => egui::vec2(
                SEARCH_WIDTH,
                search_window_height(self.settings.show_keyboard_shortcuts),
            ),
        }
    }

    fn apply_window_size(&mut self, ctx: &Context) {
        let size = self.target_window_size();
        let actual_size = ctx.input(|i| i.viewport().inner_rect.map(|rect| rect.size()));
        trace_ui(format!(
            "pid={} label=window screen={:?} query_len={} results={} should_show={} requested_size={:.1}x{:.1} actual_size={}",
            std::process::id(),
            self.screen,
            self.search_state.query.chars().count(),
            self.search_state.results.len(),
            self.search_state.should_show_dropdown(),
            size.x,
            size.y,
            actual_size
                .map(|actual| format!("{:.1}x{:.1}", actual.x, actual.y))
                .unwrap_or_else(|| "unknown".to_string()),
        ));

        let needs_resize = actual_size.map_or_else(
            || {
                self.last_inner_size.is_none_or(|last| {
                    (last.x - size.x).abs() > 0.5 || (last.y - size.y).abs() > 0.5
                })
            },
            |actual| (actual.x - size.x).abs() > 0.5 || (actual.y - size.y).abs() > 0.5,
        );

        if needs_resize {
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
            self.last_inner_size = Some(size);
        }
    }

    fn apply_parent_viewport_state(&self, ctx: &Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
            egui::viewport::WindowLevel::AlwaysOnTop,
        ));
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
            self.last_inner_size = None;
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
        self.last_inner_size = None;
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
        self.last_inner_size = None;
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
        self.last_inner_size = None;
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
        self.root_panel_fill().to_normalized_gamma_f32()
    }

    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        apply_visuals(ctx);
        self.poll_popup_commands(ctx);

        if ctx.input(|i| i.viewport().close_requested()) {
            debug_log("viewport close requested");
            Self::exit_now();
        }

        self.poll_responses(ctx);

        if self.window_visible
            && !self.summary_open
            && self.screen != Screen::SshApproval
            && Self::escape_pressed(ctx)
        {
            debug_log("hide because escape was pressed");
            self.hide_quick_access(ctx);
            return;
        }

        if self.should_hide_after_focus_loss(ctx) {
            self.hide_quick_access(ctx);
            return;
        }

        if self.window_visible {
            self.apply_window_size(ctx);
        }
        self.apply_parent_viewport_state(ctx);
        if self.summary_open {
            self.refresh_summary_totp_if_needed();
        }
        let mut root_summary_back = false;
        let mut root_summary_copied = false;

        let root_frame = egui::Frame::new().fill(self.root_panel_fill());

        egui::CentralPanel::default()
            .frame(root_frame)
            .show(ctx, |ui| {
                match self.screen {
                    Screen::Auth => {
                        if let Some(action) = draw_auth(ctx, ui, &mut self.auth_state) {
                            match action {
                                AuthAction::Login => {
                                    self.auth_state.in_flight = true;
                                    self.auth_state.error = None;
                                    self.spawn_login(
                                        self.auth_state.server_url.clone(),
                                        self.auth_state.email.clone(),
                                        self.auth_state.password.clone(),
                                        self.auth_state.remember,
                                    );
                                }
                                AuthAction::ForgetUser => {
                                    if let Err(e) = self.backend.clear_saved_session() {
                                        self.auth_state.error =
                                            Some(format!("could not forget saved user: {e}"));
                                    } else {
                                        let _ = config::clear_recent_item();
                                        self.auth_state.reset_to_full_login();
                                    }
                                }
                                AuthAction::Quit => {
                                    self.hide_quick_access(ctx);
                                }
                            }
                        }
                        if !self.auth_state.has_saved_session {
                            draw_footer(ui, &[("⏎", "Login"), ("Esc", "Hide")]);
                        }
                    }
                    Screen::TwoFactor => {
                        if let Some(action) =
                            draw_two_factor(ctx, ui, &mut self.two_factor_state)
                        {
                            match action {
                                TwoFactorAction::Verify => {
                                    self.two_factor_state.in_flight = true;
                                    self.two_factor_state.error = None;
                                    self.spawn_two_factor();
                                }
                                TwoFactorAction::Back => {
                                    self.two_factor_state.token.clear();
                                    self.two_factor_state.error = None;
                                    self.screen = Screen::Auth;
                                }
                            }
                        }
                        draw_footer(ui, &[("⏎", "Verify"), ("Esc", "Hide")]);
                    }
                    Screen::SshApproval => {
                        if let Some(action) = draw_ssh_approval(
                            ctx,
                            ui,
                            &mut self.ssh_approval_state,
                            self.settings.show_keyboard_shortcuts,
                        ) {
                            match action {
                                SshApprovalAction::Decide(decision) => {
                                    self.resolve_ssh_approval_optimistically(ctx, decision);
                                }
                                SshApprovalAction::Back => {
                                    self.leave_ssh_approval(ctx);
                                }
                            }
                        }
                    }
                    Screen::Search => {
                        if self.summary_open {
                            self.search_state.focus_search = false;

                            ui.add_space(SUMMARY_OUTER_MARGIN);
                            ui.horizontal(|ui| {
                                ui.add_space(SUMMARY_OUTER_MARGIN);
                                ui.vertical(|ui| {
                                    let shortcut_height = if self.settings.show_keyboard_shortcuts {
                                        SUMMARY_FOOTER_GAP + SUMMARY_FOOTER_TOTAL_HEIGHT
                                    } else {
                                        0.0
                                    };
                                    let content_width =
                                        (ui.available_width() - SUMMARY_OUTER_MARGIN).max(320.0);
                                    let panel_height = (ui.available_height()
                                        - SUMMARY_OUTER_MARGIN
                                        - shortcut_height)
                                        .max(260.0);

                                    ui.allocate_ui_with_layout(
                                        egui::vec2(content_width, panel_height),
                                        egui::Layout::top_down(egui::Align::Min),
                                        |ui| {
                                            egui::Frame::new()
                                                .fill(egui::Color32::from_rgb(18, 20, 26))
                                                .stroke(egui::Stroke::new(
                                                    1.0,
                                                    egui::Color32::from_rgb(38, 44, 55),
                                                ))
                                                .inner_margin(egui::Margin::same(14))
                                                .corner_radius(8.0)
                                                .show(ui, |ui| {
                                                    ui.set_min_size(egui::vec2(
                                                        content_width - 28.0,
                                                        panel_height - 28.0,
                                                    ));
                                                    if let Some(action) = draw_summary(
                                                        ctx,
                                                        ui,
                                                        &mut self.summary_state,
                                                    ) {
                                                        match action {
                                                            SummaryAction::Back => {
                                                                root_summary_back = true
                                                            }
                                                            SummaryAction::Copied => {
                                                                root_summary_copied = true
                                                            }
                                                        }
                                                    }
                                                });
                                        },
                                    );

                                    if self.settings.show_keyboard_shortcuts {
                                        ui.add_space(SUMMARY_FOOTER_GAP);
                                        ui.allocate_ui_with_layout(
                                            egui::vec2(content_width, SUMMARY_FOOTER_TOTAL_HEIGHT),
                                            egui::Layout::top_down(egui::Align::Min),
                                            |ui| {
                                                draw_footer(
                                                    ui,
                                                    &[
                                                        ("↑↓", "Field"),
                                                        ("⏎", "Copy"),
                                                        ("👁", "Reveal"),
                                                        ("←", "Back"),
                                                    ],
                                                );
                                            },
                                        );
                                    }
                                });
                            });
                            return;
                        }
                        self.search_state.reset_results_for_empty_query();

                        if self.search_state.needs_search() {
                            self.search_state.in_flight = true;
                            self.search_state.error = None;
                            self.search_state.mark_queried();
                            self.last_inner_size = None;
                            self.spawn_search(self.search_state.query.trim().to_string());
                        }

                        if let Some(action) = draw_search_panel(
                            ctx,
                            ui,
                            &mut self.search_state,
                            self.settings.show_keyboard_shortcuts,
                            self.settings.close_after_copy,
                            self.settings.restore_recent_item,
                            self.settings.ssh_agent_enabled,
                            &self.settings.ssh_agent_socket_path,
                            &self.ssh_agent_status,
                        ) {
                            match action {
                                SearchAction::OpenResult(idx) => {
                                    self.open_result(idx);
                                }
                                SearchAction::SetKeyboardShortcuts(show) => {
                                    self.settings.show_keyboard_shortcuts = show;
                                    self.save_and_apply_settings();
                                }
                                SearchAction::SetCloseAfterCopy(close) => {
                                    self.settings.close_after_copy = close;
                                    self.save_and_apply_settings();
                                }
                                SearchAction::SetRestoreRecentItem(restore) => {
                                    self.settings.restore_recent_item = restore;
                                    if !restore {
                                        let _ = config::clear_recent_item();
                                    }
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
                                        self.search_state.warning =
                                            Some(format!("could not lock vault: {e}"));
                                    } else {
                                        let _ = config::clear_recent_item();
                                        self.screen = Screen::Auth;
                                        self.auth_state = AuthState::default();
                                        self.two_factor_state = TwoFactorState::default();
                                        self.search_state.reset_for_reopen();
                                        self.summary_open = false;
                                        self.summary_state.reveal_fields.clear();
                                        self.last_inner_size = None;
                                        self.ssh_agent_status =
                                            self.backend.ssh_agent_status(&self.settings);
                                    }
                                }
                                SearchAction::Quit => {
                                    self.hide_quick_access(ctx);
                                }
                            }
                        }
                    }
                }
            });

        if root_summary_copied && self.settings.close_after_copy {
            self.hide_quick_access(ctx);
            return;
        }
        if root_summary_back {
            self.return_to_search(ctx);
        }

        // Periodic repaint for TOTP countdown
        if self.summary_open && self.summary_state.totp_fetched_at.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
        if self.screen == Screen::SshApproval {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
        if self.window_visible
            && !self.summary_open
            && self.screen != Screen::SshApproval
            && self.search_state.view != SearchView::Settings
            && Self::viewport_focused(ctx) == Some(false)
            && Instant::now() >= self.focus_hide_enabled_at
        {
            ctx.request_repaint_after(UNFOCUS_FALLBACK_DELAY);
        }
        if !self.window_visible {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

impl App {
    fn root_panel_fill(&self) -> egui::Color32 {
        match self.screen {
            Screen::Search => egui::Color32::TRANSPARENT,
            Screen::Auth if self.auth_state.has_saved_session => egui::Color32::TRANSPARENT,
            Screen::Auth | Screen::TwoFactor => egui::Color32::from_rgb(12, 15, 20),
            Screen::SshApproval => egui::Color32::TRANSPARENT,
        }
    }
}

fn apply_visuals(ctx: &Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::TRANSPARENT;
    visuals.window_fill = egui::Color32::from_rgb(18, 20, 26);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(28, 31, 38);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(38, 47, 62);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(42, 68, 104);
    visuals.selection.bg_fill = egui::Color32::from_rgb(54, 106, 172);
    visuals.override_text_color = Some(egui::Color32::from_rgb(232, 236, 244));
    ctx.set_visuals(visuals);
}

fn debug_log(message: &str) {
    if std::env::var_os("BWQA_DEBUG").is_some() {
        eprintln!("[bw-quick-access] {message}");
    }
}

fn trace_ui(line: String) {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let Ok(mut seen) = seen.lock() else {
        return;
    };
    if !seen.insert(line.clone()) {
        return;
    }
    drop(seen);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/bw-quick-access-ui.log")
    {
        let _ = std::io::Write::write_all(&mut file, format!("{timestamp} {line}\n").as_bytes());
    }
}
