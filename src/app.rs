use crate::backend::{AppBackend, BackendError};
use crate::config::{self, AppSettings};
use crate::icons::IconCache;
use crate::model::{
    BwItem, BwItemDetail, ItemAction, ItemDraft, ItemState, SshAgentStatus, SyncStatus, TotpCode,
};
use crate::ui::auth::{AuthAction, AuthState, draw_auth};
use crate::ui::edit::{EditAction, EditState, draw_edit};
use crate::ui::search::{SearchAction, SearchState, SearchView, draw_search};
use crate::ui::ssh_approval::{SshApprovalAction, SshApprovalUiState, draw_ssh_approval};
use crate::ui::summary::{SummaryAction, SummaryState, draw_summary};
use crate::ui::theme::theme;
use crate::ui::two_factor::{TwoFactorAction, TwoFactorState, draw_two_factor};
use eframe::egui;
use egui::Context;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

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
    QuickCopied {
        id: String,
        result: Result<(), BackendError>,
    },
    Synced(Result<SyncStatus, BackendError>),
    Login(Result<(), BackendError>),
    TwoFactor(Result<(), BackendError>),
    Search {
        query: String,
        state: ItemState,
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
    ItemAction {
        id: String,
        action: ItemAction,
        result: Result<(), BackendError>,
    },
    EditDraft {
        id: String,
        result: Result<ItemDraft, BackendError>,
    },
    Saved {
        id: String,
        result: Result<BwItemDetail, BackendError>,
    },
    Created(Result<BwItemDetail, BackendError>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopupCommand {
    VaultLocked,
    LockWarning,
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

struct CaptureUpdate {
    obscure: bool,
    persist: bool,
    result: Result<(), String>,
}

pub struct App {
    backend: AppBackend,
    reprompt_id: Option<String>,
    quick_copy_after_verify: bool,
    reprompt_password: String,
    reprompt_at: Option<Instant>,
    security_warning: Option<String>,
    screen: Screen,
    auth_state: AuthState,
    two_factor_state: TwoFactorState,
    search_state: SearchState,
    ssh_approval_state: SshApprovalUiState,
    ssh_approval_return: Option<(Screen, bool)>,
    summary_state: SummaryState,
    /// Open edit form for the item shown in the summary.
    edit_state: Option<EditState>,
    icons: IconCache,
    rx: mpsc::Receiver<BwResponse>,
    tx: mpsc::Sender<BwResponse>,
    popup_rx: mpsc::Receiver<PopupCommand>,
    auth_auto_hide: bool,
    auth_inhibit_focus_hide: bool,
    settings: AppSettings,
    capture_rx: Option<mpsc::Receiver<CaptureUpdate>>,
    ssh_agent_status: SshAgentStatus,
    window_visible: bool,
    summary_open: bool,
    confirm_close: bool,
    sync_in_flight: bool,
    last_sync_attempt: Instant,
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
                PopupCommand::VaultLocked => self.reset_locked(),
                PopupCommand::LockWarning => {
                    self.security_warning = self.backend.security_warning()
                }
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
                    self.exit_now();
                }
            }
        }
    }

    pub fn new(backend: AppBackend, popup_rx: mpsc::Receiver<PopupCommand>) -> Self {
        let mut settings = config::load_settings();
        if crate::demo::enabled() {
            settings.obscure_screen_capture = false;
        }
        let mut app = Self::with_settings(backend, popup_rx, settings);
        if crate::screen_capture::available() {
            app.apply_capture_preference(app.settings.obscure_screen_capture, false);
        }
        app
    }

    fn with_settings(
        backend: AppBackend,
        popup_rx: mpsc::Receiver<PopupCommand>,
        settings: AppSettings,
    ) -> Self {
        backend.revoke_item_grants();
        let (tx, rx) = mpsc::channel();
        let screen = if backend.has_session() {
            Screen::Search
        } else {
            Screen::Auth
        };
        let ssh_agent_status = backend.ssh_agent_status(&settings);
        let mut app = Self {
            security_warning: backend.security_warning(),
            reprompt_id: None,
            quick_copy_after_verify: false,
            reprompt_password: String::new(),
            reprompt_at: None,
            backend,
            screen,
            auth_state: AuthState::default(),
            two_factor_state: TwoFactorState::default(),
            search_state: SearchState::default(),
            ssh_approval_state: SshApprovalUiState::default(),
            ssh_approval_return: None,
            summary_state: SummaryState::default(),
            edit_state: None,
            rx,
            tx,
            popup_rx,
            auth_auto_hide: false,
            auth_inhibit_focus_hide: false,
            icons: IconCache::new(settings.show_website_icons),
            settings,
            capture_rx: None,
            ssh_agent_status,
            window_visible: true,
            summary_open: false,
            confirm_close: false,
            sync_in_flight: false,
            last_sync_attempt: Instant::now(),
            focus_hide_enabled_at: Instant::now() + UNFOCUS_HIDE_GRACE,
            unfocused_since: None,
        };
        app.search_state.start_list = app.settings.start_list;
        // Load the start list on the first frame, before anything is typed.
        app.search_state.force_refresh();
        app.restore_recent_item_on_start();
        app
    }
}

impl App {
    // Runs even when eframe skips drawing a minimized or hidden viewport.
    fn process_background(&mut self, ctx: &Context) {
        self.poll_capture_preference(ctx);
        self.poll_popup_commands(ctx);
        self.poll_responses(ctx);
        if self
            .reprompt_at
            .is_some_and(|at| at.elapsed() >= Duration::from_secs(55))
        {
            self.reprompt_at = None;
            self.reprompt_id = self.summary_state.detail_id.clone();
            if let Some(detail) = &mut self.summary_state.detail {
                detail.zeroize();
            }
            self.summary_state.detail = None;
            self.summary_state.reveal_fields.clear();
            self.summary_state.error =
                Some("Verify again to continue. Your unsaved edits are preserved.".into());
        }
        self.schedule_repaint(ctx);
    }

    fn reset_locked(&mut self) {
        // Replacing the channel also discards any response still held by an old worker.
        let (tx, rx) = mpsc::channel();
        self.tx = tx;
        self.rx = rx;
        self.screen = Screen::Auth;
        self.confirm_close = false;
        self.sync_in_flight = false;
        self.auth_state.password.zeroize();
        self.auth_state = AuthState::default();
        self.auth_state.notice =
            Some("Vault locked. Enter your master password to continue.".into());
        self.two_factor_state.token.zeroize();
        self.two_factor_state = TwoFactorState::default();
        self.search_state = SearchState::default();
        self.search_state.start_list = self.settings.start_list;
        self.summary_state = SummaryState::default();
        self.summary_open = false;
        self.edit_state = None;
        self.reprompt_id = None;
        self.quick_copy_after_verify = false;
        self.reprompt_password.zeroize();
        self.reprompt_at = None;
        self.ssh_approval_state = SshApprovalUiState::default();
        self.ssh_approval_return = None;
    }

    fn spawn_authorize_item(&mut self, id: String) {
        let mut password = std::mem::take(&mut self.reprompt_password);
        let backend = self.backend.clone();
        let tx = self.tx.clone();
        self.summary_state.in_flight = true;
        self.summary_state.error = None;
        std::thread::spawn(move || {
            let result = backend.authorize_item(&id, &password);
            password.zeroize();
            let _ = tx.send(BwResponse::Detail { id, result });
        });
    }

    fn spawn_login(&self, server_url: String, email: String, mut password: String, remember: bool) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let res = backend.login(&server_url, &email, &password, remember);
            password.zeroize();
            let _ = tx.send(BwResponse::Login(res));
        });
    }

    fn spawn_two_factor(&self) {
        let tx = self.tx.clone();
        let provider = self.two_factor_state.selected_provider;
        let token = zeroize::Zeroizing::new(self.two_factor_state.token.clone());
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

    fn spawn_quick_copy(&self, id: String) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let result = backend.get_item(&id).and_then(|detail| {
                let detail = zeroize::Zeroizing::new(detail);
                if detail
                    .password
                    .as_ref()
                    .is_none_or(|password| password.is_empty())
                {
                    return Err(BackendError::Message(
                        "This item has no password to copy".into(),
                    ));
                }
                backend
                    .copy_field(
                        &id,
                        usize::from(detail.username.is_some()),
                        detail.copy_version(),
                    )
                    .map_err(BackendError::Message)
            });
            let _ = tx.send(BwResponse::QuickCopied { id, result });
        });
    }

    fn spawn_sync(&mut self) {
        if self.sync_in_flight {
            return;
        }
        self.sync_in_flight = true;
        self.search_state.syncing = true;
        self.last_sync_attempt = Instant::now();
        let backend = self.backend.clone();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(BwResponse::Synced(backend.sync()));
        });
    }

    fn spawn_search(&self, query: String, state: ItemState) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let (res, warning, status, icons_url) = match backend.list_items(state, &query) {
                Ok(result) => (
                    Ok(result.items),
                    result.warning,
                    result.status,
                    result.icons_url,
                ),
                Err(error) => (Err(error), None, SyncStatus::default(), None),
            };
            let _ = tx.send(BwResponse::Search {
                query,
                state,
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

    fn spawn_item_action(&self, id: String, action: ItemAction) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let result = backend.apply_action(&id, action);
            let _ = tx.send(BwResponse::ItemAction { id, action, result });
        });
    }

    fn spawn_edit_draft(&self, id: String) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let result = backend.edit_draft(&id);
            let _ = tx.send(BwResponse::EditDraft { id, result });
        });
    }

    fn spawn_save(&self, id: String, draft: ItemDraft) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let draft = zeroize::Zeroizing::new(draft);
            let result = backend.save_item(&id, &draft);
            let _ = tx.send(BwResponse::Saved { id, result });
        });
    }

    fn spawn_create(&self, draft: ItemDraft) {
        let tx = self.tx.clone();
        let backend = self.backend.clone();
        std::thread::spawn(move || {
            let draft = zeroize::Zeroizing::new(draft);
            let result = backend.create_item(&draft);
            let _ = tx.send(BwResponse::Created(result));
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
                BwResponse::QuickCopied { id, result } => match result {
                    Ok(()) => {
                        self.quick_copy_after_verify = false;
                        self.search_state
                            .show_notice("Password copied; clipboard expires in 45 seconds");
                        if self.settings.close_after_copy {
                            self.hide_quick_access(ctx);
                        }
                    }
                    Err(BackendError::RepromptRequired) => {
                        self.summary_state = SummaryState::default();
                        self.summary_state.detail_id = Some(id.clone());
                        self.summary_open = true;
                        self.reprompt_id = Some(id);
                        self.quick_copy_after_verify = true;
                    }
                    Err(error) => self.search_state.error = Some(error.to_string()),
                },
                BwResponse::Synced(result) => {
                    self.sync_in_flight = false;
                    self.search_state.syncing = false;
                    match result {
                        Ok(status) => {
                            self.search_state.sync_status = Some(status);
                            self.search_state.force_refresh();
                            if self.summary_open
                                && self.edit_state.is_none()
                                && self.reprompt_id.is_none()
                            {
                                if let Some(id) = self.summary_state.detail_id.clone() {
                                    self.spawn_detail(id);
                                }
                            }
                        }
                        Err(error) => {
                            self.search_state.warning =
                                Some(format!("Sync failed; showing cached items: {error}"))
                        }
                    }
                }
                BwResponse::Login(res) => {
                    self.auth_state.in_flight = false;
                    match res {
                        Ok(()) => {
                            self.screen = Screen::Search;
                            self.summary_open = false;
                            self.auth_state.password.zeroize();
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
                            self.auth_state.password.zeroize();
                            self.auth_state.notice = None;
                            self.auth_inhibit_focus_hide = false;
                            self.two_factor_state.token.zeroize();
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
                            self.two_factor_state.token.zeroize();
                            self.two_factor_state.focus_token = true;
                        }
                    }
                }
                BwResponse::Search {
                    query,
                    state,
                    result,
                    warning,
                    status,
                    icons_url,
                } => {
                    self.icons.set_icons_url(icons_url);
                    // Clear in_flight before the stale check, otherwise needs_search() stays
                    // false and a query typed while this request ran would never be sent.
                    self.search_state.in_flight = false;
                    let current_state = self
                        .search_state
                        .view
                        .item_state()
                        .unwrap_or(ItemState::Active);
                    if query != self.search_state.query.trim() || state != current_state {
                        ctx.request_repaint();
                        continue;
                    }
                    match result {
                        Ok(items) => {
                            self.search_state.set_results(items);
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
                            if self.reprompt_id.take().is_some() {
                                self.reprompt_at = Some(Instant::now());
                            }
                            self.summary_state.detail = Some(detail);
                            self.summary_state.error = None;
                            self.summary_state.selected_field = 0;
                            self.summary_state.reveal_fields.clear();
                            if self.quick_copy_after_verify {
                                self.quick_copy_after_verify = false;
                                self.spawn_quick_copy(id.clone());
                            }
                        }
                        Err(e) => {
                            if let Some(detail) = &mut self.summary_state.detail {
                                detail.zeroize();
                            }
                            self.summary_state.detail = None;
                            if matches!(e, BackendError::RepromptRequired) {
                                self.reprompt_id = Some(id);
                            }
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
                BwResponse::ItemAction { id, action, result } => {
                    if self.summary_state.detail_id.as_deref() != Some(id.as_str()) {
                        continue;
                    }
                    self.summary_state.action_in_flight = false;
                    self.summary_state.confirm = None;
                    match result {
                        // Starring keeps the item open; reload it to show the new star.
                        Ok(())
                            if matches!(action, ItemAction::Favorite | ItemAction::Unfavorite) =>
                        {
                            self.search_state.force_refresh();
                            self.spawn_detail(id);
                        }
                        Ok(()) => {
                            self.search_state.show_notice(action.done_message());
                            self.search_state.force_refresh();
                            if self.summary_open {
                                self.return_to_search(ctx);
                            }
                        }
                        Err(e) => self.summary_state.error = Some(e.to_string()),
                    }
                }
                BwResponse::EditDraft { id, result } => {
                    let Some(edit) = self.edit_state.as_mut().filter(|edit| edit.id == id) else {
                        continue;
                    };
                    match result {
                        Ok(draft) => edit.set_draft(draft),
                        Err(e) => {
                            self.edit_state = None;
                            self.summary_state.error = Some(format!("could not edit: {e}"));
                        }
                    }
                }
                BwResponse::Saved { id, result } => {
                    let Some(edit) = self.edit_state.as_mut().filter(|edit| edit.id == id) else {
                        continue;
                    };
                    match result {
                        Ok(detail) => {
                            self.edit_state = None;
                            self.summary_state.detail = Some(detail);
                            self.summary_state.error = None;
                            self.summary_state.selected_field = 0;
                            self.summary_state.reveal_fields.clear();
                            self.summary_state.copied_field = None;
                            self.summary_state.totp = None;
                            self.summary_state.totp_fetched_at = None;
                            self.search_state.force_refresh();
                            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        }
                        Err(e) => {
                            edit.saving = false;
                            edit.error = Some(e.to_string());
                        }
                    }
                }
                BwResponse::Created(result) => {
                    let Some(edit) = self.edit_state.as_mut().filter(|edit| edit.creating) else {
                        continue;
                    };
                    match result {
                        Ok(detail) => {
                            self.edit_state = None;
                            self.summary_state = SummaryState::default();
                            self.summary_state.detail_id = Some(detail.id.clone());
                            self.summary_state.detail = Some(detail);
                            self.search_state.force_refresh();
                            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        }
                        Err(e) => {
                            edit.saving = false;
                            edit.error = Some(e.to_string());
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
        if self
            .edit_state
            .as_ref()
            .is_some_and(|edit| edit.saving || edit.is_dirty())
        {
            self.confirm_close = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            return;
        }
        debug_log("hide quick access");
        Self::hide_viewport_now(ctx);
        self.window_visible = false;
        self.summary_open = false;
        self.unfocused_since = None;
        self.summary_state.reveal_fields.clear();
        self.exit_now();
    }

    fn hide_viewport_now(ctx: &Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        ctx.request_repaint();
    }

    fn exit_now(&mut self) -> ! {
        // process::exit also skips Drop. Explicitly wipe UI-owned plaintext first.
        self.auth_state.password.zeroize();
        self.two_factor_state.token.zeroize();
        self.reprompt_password.zeroize();
        self.summary_state = SummaryState::default();
        self.edit_state = None;
        self.backend.revoke_item_grants();
        std::process::exit(0);
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
            self.exit_now();
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
            || self.summary_state.action_in_flight
            || self.edit_state.is_some()
            || self.search_state.view != SearchView::Results
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
            self.reprompt_id = None;
            self.reprompt_at = None;
            self.summary_state.detail = None;
            self.summary_state.in_flight = true;
            self.summary_state.detail_id = Some(item_id.clone());
            self.summary_state.totp = None;
            self.summary_state.totp_fetched_at = None;
            self.summary_state.totp_in_flight = false;
            self.summary_state.error = None;
            self.summary_state.confirm = None;
            self.summary_state.action_in_flight = false;
            self.edit_state = None;
            self.summary_open = true;
            self.unfocused_since = None;
            let remember = self.settings.restore_recent_item;
            let record_use = self.settings.start_list == config::StartList::RecentlyUsed;
            if remember || record_use {
                let recent_id = item_id.clone();
                std::thread::spawn(move || {
                    if remember {
                        let _ = config::save_recent_item(&recent_id);
                    }
                    if record_use {
                        let _ = config::record_item_use(&recent_id);
                    }
                });
            }
            self.spawn_detail(item_id);
        }
    }

    fn return_to_search(&mut self, ctx: &Context) {
        self.quick_copy_after_verify = false;
        self.reprompt_id = None;
        self.reprompt_at = None;
        self.reprompt_password.zeroize();
        self.backend.revoke_item_grants();
        self.summary_open = false;
        self.edit_state = None;
        self.summary_state = SummaryState::default();
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

    fn apply_capture_preference(&mut self, obscure: bool, persist: bool) {
        if self.capture_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.capture_rx = Some(rx);
        self.search_state.capture_pending = true;
        std::thread::spawn(move || {
            let _ = tx.send(CaptureUpdate {
                obscure,
                persist,
                result: crate::screen_capture::apply(obscure),
            });
        });
    }

    fn poll_capture_preference(&mut self, ctx: &Context) {
        let Some(rx) = &self.capture_rx else { return };
        let result = match rx.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => Some(CaptureUpdate {
                obscure: self.settings.obscure_screen_capture,
                persist: false,
                result: Err("screen capture worker stopped unexpectedly".into()),
            }),
        };
        if let Some(CaptureUpdate {
            obscure,
            persist,
            result,
        }) = result
        {
            self.capture_rx = None;
            self.search_state.capture_pending = false;
            match result {
                Ok(()) => {
                    self.settings.obscure_screen_capture = obscure;
                    if persist {
                        self.save_and_apply_settings();
                    }
                }
                Err(error) => {
                    self.search_state.warning =
                        Some(format!("Capture protection not confirmed: {error}"));
                }
            }
        } else {
            self.search_state.capture_pending = true;
            ctx.request_repaint_after(Duration::from_millis(50));
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

    fn logic(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.process_background(ctx);
    }

    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &root.ctx().clone();

        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.hide_quick_access(ctx);
        }

        self.icons.poll(ctx);
        if let Some(warning) = &self.security_warning {
            egui::Panel::top("security-warning").show(root, |ui| {
                ui.colored_label(crate::ui::theme::theme().warning, warning);
            });
        }

        // Screens with their own Escape handling must not hide the whole window.
        let escape_handled_by_screen = match self.screen {
            Screen::TwoFactor | Screen::SshApproval => true,
            Screen::Auth => self.auth_state.confirm_forget,
            Screen::Search => self.summary_open || self.search_state.view != SearchView::Results,
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

        if self.screen == Screen::Search
            && self.edit_state.is_none()
            && !self.summary_state.action_in_flight
        {
            let requested =
                ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::R));
            if requested || self.last_sync_attempt.elapsed() >= Duration::from_secs(60) {
                self.spawn_sync();
            }
        }
        if self.confirm_close {
            let busy = self.edit_state.as_ref().is_some_and(|edit| edit.saving);
            egui::CentralPanel::default().show(root, |_| {});
            let dialog = crate::ui::widgets::ConfirmDialog {
                title: "Close and discard changes?",
                body: if busy {
                    "Wait for the save to finish before closing."
                } else {
                    "Unsaved edits will be lost."
                },
                confirm_label: "Discard and close",
                danger: true,
                key: crate::ui::widgets::ConfirmKey::None,
                busy,
                error: None,
            };
            match crate::ui::widgets::confirm_dialog(ctx, &dialog) {
                Some(true) => {
                    self.edit_state = None;
                    self.confirm_close = false;
                    self.hide_quick_access(ctx);
                }
                Some(false) => self.confirm_close = false,
                None => {}
            }
            self.schedule_repaint(ctx);
            return;
        }
        match self.screen {
            Screen::Auth => self.update_auth(root),
            Screen::TwoFactor => self.update_two_factor(root),
            Screen::SshApproval => self.update_ssh_approval(root),
            Screen::Search if self.summary_open && self.reprompt_id.is_some() => {
                self.update_summary(root)
            }
            Screen::Search if self.summary_open && self.edit_state.is_some() => {
                self.update_edit(root)
            }
            Screen::Search if self.summary_open => self.update_summary(root),
            Screen::Search => self.update_search(root),
        }
        self.icons.start_queued(ctx);
        self.schedule_repaint(ctx);
    }
}

impl App {
    fn update_auth(&mut self, root: &mut egui::Ui) {
        let Some(action) = draw_auth(root, &mut self.auth_state) else {
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
                    let _ = config::clear_item_usage();
                    self.auth_state.reset_to_full_login();
                }
            }
        }
    }

    fn update_two_factor(&mut self, root: &mut egui::Ui) {
        match draw_two_factor(root, &mut self.two_factor_state) {
            Some(TwoFactorAction::Verify) => {
                self.two_factor_state.in_flight = true;
                self.two_factor_state.error = None;
                self.spawn_two_factor();
            }
            Some(TwoFactorAction::Back) => {
                self.two_factor_state.token.zeroize();
                self.two_factor_state.error = None;
                self.auth_state.focus_password = true;
                self.screen = Screen::Auth;
            }
            None => {}
        }
    }

    fn update_ssh_approval(&mut self, root: &mut egui::Ui) {
        let ctx = &root.ctx().clone();
        match draw_ssh_approval(
            root,
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

    fn update_summary(&mut self, root: &mut egui::Ui) {
        let ctx = &root.ctx().clone();
        if let Some(id) = self.reprompt_id.clone() {
            let mut verify = false;
            let mut cancel = false;
            egui::CentralPanel::default().show(root, |ui| {
                ui.heading("Verify master password");
                ui.label(
                    "This item requires your master password before it can be viewed or edited.",
                );
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.reprompt_password)
                        .password(true)
                        .hint_text("Master password")
                        .id_source("item-reprompt"),
                );
                if !ctx.memory(|m| m.has_focus(response.id)) && !self.summary_state.in_flight {
                    response.request_focus();
                }
                if let Some(error) = &self.summary_state.error {
                    ui.colored_label(egui::Color32::RED, error);
                }
                verify = ui
                    .add_enabled(
                        !self.summary_state.in_flight && !self.reprompt_password.is_empty(),
                        egui::Button::new("Verify"),
                    )
                    .clicked()
                    || (ctx.input(|i| i.key_pressed(egui::Key::Enter))
                        && !self.summary_state.in_flight
                        && !self.reprompt_password.is_empty());
                cancel = ui.button("Cancel").clicked()
                    || ctx.input(|i| i.key_pressed(egui::Key::Escape));
            });
            if cancel {
                if self.edit_state.as_ref().is_some_and(|edit| edit.is_dirty()) {
                    self.confirm_close = true;
                } else {
                    self.return_to_search(ctx);
                }
            } else if verify {
                self.spawn_authorize_item(id);
            }
            return;
        }
        self.search_state.focus_search = false;
        self.refresh_summary_totp_if_needed();
        let copy_id = self.summary_state.detail_id.clone().unwrap_or_default();
        let copy_version = self
            .summary_state
            .detail
            .as_ref()
            .map(|detail| detail.copy_version());
        match draw_summary(
            root,
            &mut self.summary_state,
            self.settings.show_keyboard_shortcuts,
            false,
            &mut self.icons,
            &mut |index| {
                self.backend
                    .copy_field(&copy_id, index, copy_version.ok_or("No item open")?)
            },
        ) {
            Some(SummaryAction::Copied) if self.settings.close_after_copy => {
                self.hide_quick_access(ctx);
            }
            Some(SummaryAction::Back) => self.return_to_search(ctx),
            Some(SummaryAction::Edit) => {
                if let Some(id) = self.summary_state.detail_id.clone() {
                    self.summary_state.error = None;
                    let mut edit = EditState::loading(id.clone());
                    edit.folders = self.backend.folders().unwrap_or_default();
                    self.edit_state = Some(edit);
                    self.spawn_edit_draft(id);
                }
            }
            Some(SummaryAction::Item(action)) => {
                if let Some(id) = self.summary_state.detail_id.clone() {
                    self.summary_state.error = None;
                    self.summary_state.action_in_flight = true;
                    self.spawn_item_action(id, action);
                }
            }
            Some(SummaryAction::Copied) => {}
            None => {}
        }
    }

    fn update_edit(&mut self, root: &mut egui::Ui) {
        let ctx = &root.ctx().clone();
        let Some(edit) = self.edit_state.as_mut() else {
            return;
        };
        match draw_edit(root, edit, self.settings.show_keyboard_shortcuts) {
            Some(EditAction::Save(draft)) => {
                edit.saving = true;
                edit.error = None;
                if edit.creating {
                    self.spawn_create(draft);
                } else {
                    let id = edit.id.clone();
                    self.spawn_save(id, draft);
                }
            }
            // A new item has no summary to fall back to.
            Some(EditAction::Cancel) if edit.creating => self.return_to_search(ctx),
            Some(EditAction::Cancel) => {
                self.edit_state = None;
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            }
            None => {}
        }
    }

    fn update_search(&mut self, root: &mut egui::Ui) {
        let ctx = &root.ctx().clone();
        self.search_state.reset_results_for_empty_query();
        if self.search_state.needs_search() {
            self.search_state.in_flight = true;
            self.search_state.error = None;
            self.search_state.mark_queried();
            let state = self
                .search_state
                .view
                .item_state()
                .unwrap_or(ItemState::Active);
            self.spawn_search(self.search_state.query.trim().to_string(), state);
        }

        let Some(action) = draw_search(
            root,
            &mut self.search_state,
            &self.settings,
            &self.ssh_agent_status,
            &mut self.icons,
        ) else {
            return;
        };
        match action {
            SearchAction::QuickCopy(idx) => {
                if let Some(item) = self.search_state.results.get(idx) {
                    self.spawn_quick_copy(item.id.clone());
                }
            }
            SearchAction::Sync => self.spawn_sync(),
            SearchAction::OpenResult(idx) => self.open_result(idx),
            SearchAction::SetStartList(list) => {
                self.settings.start_list = list;
                self.search_state.start_list = list;
                self.search_state.force_refresh();
                // Opened items are only remembered while "Recently used" is chosen.
                if list != config::StartList::RecentlyUsed {
                    let _ = config::clear_item_usage();
                }
                self.save_and_apply_settings();
            }
            SearchAction::OpenWindow => match self.backend.open_window() {
                Ok(()) => self.hide_quick_access(ctx),
                Err(e) => self.search_state.warning = Some(e),
            },
            SearchAction::NewItem => {
                self.summary_state = SummaryState::default();
                self.summary_open = true;
                let mut edit = EditState::create();
                edit.folders = self.backend.folders().unwrap_or_default();
                self.edit_state = Some(edit);
                self.unfocused_since = None;
            }
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
            SearchAction::SetObscureScreenCapture(obscure) => {
                self.apply_capture_preference(obscure, true);
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
                    self.reset_locked();
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
        if self.sync_in_flight
            || self.search_state.in_flight
            || self.summary_state.in_flight
            || self.summary_state.totp_in_flight
            || self.auth_state.in_flight
            || self.two_factor_state.in_flight
            || self.summary_state.action_in_flight
            || self
                .edit_state
                .as_ref()
                .is_some_and(|edit| edit.saving || edit.draft.is_none())
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

#[cfg(test)]
mod security_tests {
    use super::*;
    #[test]
    fn locking_clears_secrets_and_disconnects_stale_workers() {
        let (commands, receiver) = mpsc::channel();
        let backend = AppBackend::demo();
        let mut app = App::with_settings(
            backend,
            receiver,
            AppSettings {
                show_website_icons: false,
                restore_recent_item: false,
                ..AppSettings::default()
            },
        );
        app.auth_state.password = "sensitive".into();
        app.reprompt_password = "sensitive".into();
        app.summary_open = true;
        app.edit_state = Some(EditState::create());
        let stale_worker = app.tx.clone();
        stale_worker.send(BwResponse::Login(Ok(()))).unwrap();
        commands.send(PopupCommand::VaultLocked).unwrap();
        let ctx = Context::default();
        app.window_visible = false;
        app.process_background(&ctx);
        assert_eq!(app.screen, Screen::Auth);
        assert!(app.auth_state.password.is_empty());
        assert!(app.reprompt_password.is_empty());
        assert!(app.edit_state.is_none());
        assert!(!app.summary_open);
        assert!(app.summary_state.detail.is_none());
        assert!(stale_worker.send(BwResponse::Login(Ok(()))).is_err());
    }
    #[test]
    fn hiding_dirty_editor_requests_confirmation() {
        let (_, receiver) = mpsc::channel();
        let mut app = App::with_settings(
            AppBackend::demo(),
            receiver,
            AppSettings {
                show_website_icons: false,
                restore_recent_item: false,
                ..AppSettings::default()
            },
        );
        let mut edit = EditState::create();
        edit.draft.as_mut().unwrap().name = "Unsaved item".into();
        app.edit_state = Some(edit);
        app.summary_open = true;
        app.hide_quick_access(&Context::default());
        assert!(app.confirm_close);
        assert!(app.window_visible);
        assert_eq!(
            app.edit_state
                .as_ref()
                .unwrap()
                .draft
                .as_ref()
                .unwrap()
                .name,
            "Unsaved item"
        );
    }
}
