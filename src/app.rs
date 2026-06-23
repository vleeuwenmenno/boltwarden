use crate::backend::{AppBackend, BackendError};
use crate::model::{BwItem, BwItemDetail, SyncStatus};
use crate::ui::auth::{draw_auth, AuthAction, AuthState};
use crate::ui::footer::draw_footer;
use crate::ui::search::{draw_search, SearchAction, SearchState};
use crate::ui::summary::{draw_summary, SummaryAction, SummaryState};
use crate::ui::two_factor::{draw_two_factor, TwoFactorAction, TwoFactorState};
use eframe::egui;
use egui::Context;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const UNFOCUS_HIDE_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq)]
enum Screen {
    Auth,
    TwoFactor,
    Search,
    Summary,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopupCommand {
    Show,
    Hide,
    Toggle,
    Quit,
}

pub struct App {
    backend: AppBackend,
    screen: Screen,
    centered_viewport: bool,
    auth_state: AuthState,
    two_factor_state: TwoFactorState,
    search_state: SearchState,
    summary_state: SummaryState,
    rx: mpsc::Receiver<BwResponse>,
    tx: mpsc::Sender<BwResponse>,
    popup_rx: mpsc::Receiver<PopupCommand>,
    last_inner_size: Option<egui::Vec2>,
    window_visible: bool,
    unfocus_hide_enabled_at: Option<Instant>,
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
                PopupCommand::Quit => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
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
        Self {
            backend,
            screen,
            centered_viewport: false,
            auth_state: AuthState::default(),
            two_factor_state: TwoFactorState::default(),
            search_state: SearchState::default(),
            summary_state: SummaryState::default(),
            rx,
            tx,
            popup_rx,
            last_inner_size: None,
            window_visible: true,
            unfocus_hide_enabled_at: Some(Instant::now() + UNFOCUS_HIDE_GRACE),
        }
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

    fn poll_responses(&mut self, ctx: &Context) {
        while let Ok(resp) = self.rx.try_recv() {
            match resp {
                BwResponse::Login(res) => {
                    self.auth_state.in_flight = false;
                    match res {
                        Ok(()) => {
                            self.screen = Screen::Search;
                            self.auth_state.password.clear();
                            self.auth_state.error = None;
                            self.search_state.query.clear();
                            self.search_state.force_refresh();
                            self.search_state.focus_search = true;
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
                            self.auth_state.password.clear();
                            self.two_factor_state.token.clear();
                            self.two_factor_state.error = None;
                            self.search_state.query.clear();
                            self.search_state.force_refresh();
                            self.search_state.focus_search = true;
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
            }
            ctx.request_repaint();
        }
    }

    fn hide_quick_access(&mut self, ctx: &Context) {
        self.window_visible = false;
        self.unfocus_hide_enabled_at = None;
        self.summary_state.reveal_fields.clear();
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    fn show_quick_access(&mut self, ctx: &Context) {
        self.window_visible = true;
        self.unfocus_hide_enabled_at = Some(Instant::now() + UNFOCUS_HIDE_GRACE);
        self.last_inner_size = None;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        if let Some(command) = egui::ViewportCommand::center_on_screen(ctx) {
            ctx.send_viewport_cmd(command);
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);

        if self.backend.has_session() {
            self.screen = Screen::Search;
            self.search_state.query.clear();
            self.search_state.reset_results_for_empty_query();
            self.search_state.focus_search = true;
        }
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

    fn focus_lost(ctx: &Context) -> bool {
        ctx.input(|i| {
            i.events.iter().any(|event| {
                matches!(event, egui::Event::WindowFocused(false))
            })
        })
    }

    fn unfocus_hide_enabled(&self) -> bool {
        self.unfocus_hide_enabled_at
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    fn apply_window_size(&mut self, ctx: &Context) {
        let size = match self.screen {
            Screen::Auth => egui::vec2(720.0, 540.0),
            Screen::TwoFactor => egui::vec2(620.0, 260.0),
            Screen::Search => {
                let row_count = self.search_state.results.len().min(6) as f32;
                let status_rows = if self.search_state.in_flight
                    || self.search_state.error.is_some()
                    || self.search_state.warning.is_some()
                    || (!self.search_state.query.trim().is_empty()
                        && self.search_state.results.is_empty()
                        && !self.search_state.last_query.is_empty())
                {
                    1.0
                } else {
                    0.0
                };
                egui::vec2(720.0, 104.0 + row_count * 56.0 + status_rows * 28.0)
            }
            Screen::Summary => egui::vec2(720.0, 460.0),
        };

        if self
            .last_inner_size
            .is_none_or(|last| (last.x - size.x).abs() > 0.5 || (last.y - size.y).abs() > 0.5)
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
            if let Some(command) = egui::ViewportCommand::center_on_screen(ctx) {
                ctx.send_viewport_cmd(command);
            }
            self.last_inner_size = Some(size);
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.poll_popup_commands(ctx);

        if ctx.input(|i| i.viewport().close_requested()) {
            return;
        }

        if !self.centered_viewport {
            if let Some(command) = egui::ViewportCommand::center_on_screen(ctx) {
                ctx.send_viewport_cmd(command);
                self.centered_viewport = true;
            }
        }

        self.poll_responses(ctx);

        if self.window_visible && Self::escape_pressed(ctx) {
            self.hide_quick_access(ctx);
            return;
        }

        if self.window_visible && self.unfocus_hide_enabled() && Self::focus_lost(ctx) {
            self.hide_quick_access(ctx);
            return;
        }
        if let Some(deadline) = self
            .unfocus_hide_enabled_at
            .filter(|deadline| Instant::now() < *deadline)
        {
            ctx.request_repaint_after(deadline.saturating_duration_since(Instant::now()));
        }

        if self.window_visible {
            self.apply_window_size(ctx);
        }

        egui::CentralPanel::default().show(ctx, |ui| {
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
                                    self.auth_state.reset_to_full_login();
                                }
                            }
                            AuthAction::Quit => {
                                self.hide_quick_access(ctx);
                            }
                        }
                    }
                    draw_footer(ui, &[
                        ("⏎", "Login"),
                        ("Esc", "Hide"),
                    ]);
                }
                Screen::TwoFactor => {
                    if let Some(action) = draw_two_factor(ctx, ui, &mut self.two_factor_state) {
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
                    draw_footer(ui, &[
                        ("⏎", "Verify"),
                        ("Esc", "Hide"),
                    ]);
                }
                Screen::Search => {
                    self.search_state.reset_results_for_empty_query();

                    // Trigger search if needed
                    if self.search_state.needs_search() {
                        self.search_state.in_flight = true;
                        self.search_state.error = None;
                        self.search_state.mark_queried();
                        self.spawn_search(self.search_state.query.trim().to_string());
                    }

                    if let Some(action) = draw_search(ctx, ui, &mut self.search_state) {
                        match action {
                            SearchAction::Open(idx) => {
                                if let Some(item) = self.search_state.results.get(idx) {
                                    self.summary_state.detail = None;
                                    self.summary_state.in_flight = true;
                                    self.summary_state.detail_id = Some(item.id.clone());
                                    self.summary_state.totp = None;
                                    self.summary_state.totp_fetched_at = None;
                                    self.summary_state.totp_in_flight = false;
                                    self.spawn_detail(item.id.clone());
                                    self.screen = Screen::Summary;
                                }
                            }
                            SearchAction::Quit => {
                                self.hide_quick_access(ctx);
                            }
                        }
                    }
                    draw_footer(ui, &[
                        ("↑↓", "Navigate"),
                        ("→/⏎", "Open"),
                        ("Esc", "Hide"),
                    ]);
                }
                Screen::Summary => {
                    // TOTP refresh
                    if self.summary_state.needs_totp_refresh() {
                        if let Some(id) = self.summary_state.detail_id.clone() {
                            self.summary_state.totp_in_flight = true;
                            self.spawn_totp(id);
                        }
                    }
                    if let Some(action) = draw_summary(ctx, ui, &mut self.summary_state) {
                        match action {
                            SummaryAction::Back => {
                                self.screen = Screen::Search;
                                self.search_state.focus_search = true;
                            }
                        }
                    }
                    draw_footer(ui, &[
                        ("↑↓", "Field"),
                        ("⏎", "Copy"),
                        ("👁", "Reveal"),
                        ("←", "Back"),
                        ("Esc", "Hide"),
                    ]);
                }
            }
        });

        // Periodic repaint for TOTP countdown
        if self.screen == Screen::Summary && self.summary_state.totp_fetched_at.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
        if !self.window_visible {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
