use crate::config;
use crate::ui::theme::theme;
use crate::ui::widgets;
use egui::{Context, RichText};

const DEFAULT_SERVER: &str = "https://vault.bitwarden.com";
const FORM_WIDTH: f32 = 440.0;

pub struct AuthState {
    pub server_url: String,
    pub email: String,
    pub password: String,
    pub remember: bool,
    pub error: Option<String>,
    pub in_flight: bool,
    pub has_saved_session: bool,
    pub confirm_forget: bool,
    /// Initial focus still has to be placed (password when the email is known, else email).
    pub focus_password: bool,
    pub notice: Option<String>,
}

impl Default for AuthState {
    fn default() -> Self {
        let saved = config::load_saved_session();
        let has_saved_session = saved.is_some();
        Self {
            server_url: saved
                .as_ref()
                .map(|session| session.server_url.clone())
                .unwrap_or_else(default_server),
            email: saved
                .as_ref()
                .map(|session| session.email.clone())
                .unwrap_or_default(),
            password: String::new(),
            remember: true,
            error: None,
            in_flight: false,
            has_saved_session,
            confirm_forget: false,
            focus_password: true,
            notice: None,
        }
    }
}

impl AuthState {
    pub fn reset_to_full_login(&mut self) {
        *self = Self {
            server_url: default_server(),
            has_saved_session: false,
            ..Self::default()
        };
        self.email.clear();
    }

    fn can_submit(&self) -> bool {
        !self.in_flight
            && !self.server_url.trim().is_empty()
            && !self.email.trim().is_empty()
            && !self.password.is_empty()
    }
}

fn default_server() -> String {
    std::env::var("BW_SERVER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_SERVER.to_string())
}

pub fn draw_auth(root: &mut egui::Ui, state: &mut AuthState) -> Option<AuthAction> {
    let ctx = &root.ctx().clone();
    let mut action = None;
    let t = theme();

    let hints: &[(&str, &str)] = if state.has_saved_session {
        &[("⏎", "Unlock"), ("Esc", "Hide")]
    } else {
        &[("⏎", "Log in"), ("Tab", "Next field"), ("Esc", "Hide")]
    };
    egui::Panel::bottom("footer")
        .frame(widgets::footer_frame())
        .show(root, |ui| widgets::footer(ui, hints, None));

    if state.has_saved_session {
        draw_unlock_header(root, state, &mut action);
    } else {
        egui::Panel::top("header")
            .frame(widgets::header_frame())
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(t.icon("\u{f023}", "🔐"))
                            .size(t.title())
                            .color(t.accent),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Bitwarden")
                            .size(t.title())
                            .color(t.text_strong),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(RichText::new("Log in to your vault").color(t.text_faint));
                    });
                });
            });
    }

    egui::CentralPanel::default()
        .frame(widgets::body_frame())
        .show(root, |ui| {
            if state.has_saved_session {
                draw_unlock_body(ui, state);
            } else {
                draw_login_form(ui, state, &mut action);
            }
        });

    if state.confirm_forget {
        draw_forget_dialog(ctx, state, &mut action);
    }

    if ctx.input(|i| i.key_pressed(egui::Key::Enter)) && state.can_submit() && !state.confirm_forget
    {
        action = Some(AuthAction::Login);
    }
    action
}

fn draw_unlock_header(root: &mut egui::Ui, state: &mut AuthState, action: &mut Option<AuthAction>) {
    let t = theme();
    egui::Panel::top("header")
        .frame(widgets::header_frame())
        .show(root, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(t.icon("\u{f023}", "🔐"))
                        .size(t.input())
                        .color(t.accent),
                );
                ui.add_space(6.0);
                let trailing = 96.0;
                let id = egui::Id::new("saved-session-password");
                let hint = if state.email.trim().is_empty() {
                    "Master password".to_string()
                } else {
                    format!("Master password for {}", state.email.trim())
                };
                let response = ui.add_sized(
                    [(ui.available_width() - trailing).max(120.0), 32.0],
                    egui::TextEdit::singleline(&mut state.password)
                        .id(id)
                        .font(t.font(t.input()))
                        .text_color(t.text_strong)
                        .hint_text(RichText::new(hint).color(t.text_faint))
                        .password(true)
                        .frame(egui::Frame::NONE)
                        .vertical_align(egui::Align::Center),
                );
                if state.focus_password {
                    response.request_focus();
                    state.focus_password = false;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if state.in_flight {
                        ui.add(egui::Spinner::new().color(t.text_muted));
                    } else if widgets::button(ui, "Unlock", true, state.can_submit()).clicked() {
                        *action = Some(AuthAction::Login);
                    }
                });
            });
        });
}

fn draw_unlock_body(ui: &mut egui::Ui, state: &mut AuthState) {
    let t = theme();
    ui.add_space((ui.available_height() / 2.0 - 70.0).max(8.0));
    ui.vertical_centered(|ui| {
        ui.label(
            RichText::new(t.icon("\u{f2bd}", "👤"))
                .size(t.title() + 10.0)
                .color(t.text_faint),
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new(state.email.trim())
                .size(t.title())
                .color(t.text_strong),
        );
        ui.label(RichText::new(state.server_url.trim()).color(t.text_faint));
        if let Some(notice) = &state.notice {
            ui.add_space(10.0);
            ui.label(RichText::new(notice).color(t.warning));
        }
        if let Some(error) = &state.error {
            ui.add_space(10.0);
            widgets::error_line(ui, error);
        }
        ui.add_space(18.0);
        if widgets::button(ui, "Use another account", false, !state.in_flight).clicked() {
            state.confirm_forget = true;
        }
    });
}

fn draw_login_form(ui: &mut egui::Ui, state: &mut AuthState, action: &mut Option<AuthAction>) {
    let t = theme();
    let side = ((ui.available_width() - FORM_WIDTH) / 2.0).max(0.0);
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.add_space(side);
        ui.vertical(|ui| {
            ui.set_width(FORM_WIDTH);
            if let Some(notice) = &state.notice {
                ui.label(RichText::new(notice).color(t.warning));
                ui.add_space(8.0);
            }

            widgets::field_label(ui, "Server");
            widgets::text_input(
                ui,
                egui::Id::new("login-server"),
                &mut state.server_url,
                DEFAULT_SERVER,
                false,
                t.body(),
            );
            ui.add_space(8.0);

            widgets::field_label(ui, "Email");
            let email = widgets::text_input(
                ui,
                egui::Id::new("login-email"),
                &mut state.email,
                "you@example.com",
                false,
                t.body(),
            );
            ui.add_space(8.0);

            widgets::field_label(ui, "Master password");
            let password = widgets::text_input(
                ui,
                egui::Id::new("login-password"),
                &mut state.password,
                "Your master password",
                true,
                t.body(),
            );
            if state.focus_password {
                if state.email.trim().is_empty() {
                    email.request_focus();
                } else {
                    password.request_focus();
                }
                state.focus_password = false;
            }

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.checkbox(
                    &mut state.remember,
                    RichText::new("Remember this device").color(t.text),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if state.in_flight {
                        ui.add(egui::Spinner::new().color(t.text_muted));
                    } else if widgets::button(ui, "Log in", true, state.can_submit()).clicked() {
                        *action = Some(AuthAction::Login);
                    }
                });
            });

            if let Some(error) = &state.error {
                ui.add_space(8.0);
                widgets::error_line(ui, error);
            }
        });
    });
}

fn draw_forget_dialog(ctx: &Context, state: &mut AuthState, action: &mut Option<AuthAction>) {
    let dialog = widgets::ConfirmDialog {
        title: "Use another account?",
        body: "This removes the saved unlock session for this account from this device.",
        confirm_label: "Forget account",
        danger: true,
        key: widgets::ConfirmKey::None,
        busy: false,
        error: None,
    };
    match widgets::confirm_dialog(ctx, &dialog) {
        Some(true) => *action = Some(AuthAction::ForgetUser),
        Some(false) => state.confirm_forget = false,
        None => {}
    }
}

pub enum AuthAction {
    Login,
    ForgetUser,
}
