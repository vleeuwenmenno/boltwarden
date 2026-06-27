use crate::config;
use crate::ui::search::{SEARCH_HEIGHT, SEARCH_HORIZONTAL_MARGIN, SEARCH_TOP_MARGIN};
use egui::{Context, Ui};

pub struct AuthState {
    pub server_url: String,
    pub email: String,
    pub password: String,
    pub remember: bool,
    pub error: Option<String>,
    pub in_flight: bool,
    pub has_saved_session: bool,
    pub confirm_forget: bool,
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
                .or_else(|| {
                    std::env::var("BW_SERVER")
                        .ok()
                        .filter(|value| !value.trim().is_empty())
                })
                .unwrap_or_else(|| "https://vault.bitwarden.com".to_string()),
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
        self.server_url = std::env::var("BW_SERVER")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "https://vault.bitwarden.com".to_string());
        self.email.clear();
        self.password.clear();
        self.remember = true;
        self.error = None;
        self.in_flight = false;
        self.has_saved_session = false;
        self.confirm_forget = false;
        self.focus_password = true;
        self.notice = None;
    }
}

pub fn draw_auth(ctx: &Context, ui: &mut Ui, state: &mut AuthState) -> Option<AuthAction> {
    let mut action = None;

    if state.has_saved_session {
        draw_saved_session_unlock(ui, state, &mut action);
        draw_auth_tail(ctx, ui, state, &mut action);
        return action;
    }

    ui.add_space(28.0);

    let frame_width = 616.0;
    let left_pad = ((ui.available_width() - frame_width) / 2.0).max(0.0);
    ui.horizontal(|ui| {
        ui.add_space(left_pad);
        egui::Frame::new()
            .fill(egui::Color32::from_rgb(18, 20, 26))
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(52, 58, 70),
            ))
            .inner_margin(egui::Margin::symmetric(28, 24))
            .corner_radius(8.0)
            .shadow(egui::epaint::Shadow {
                offset: [0, 8],
                blur: 24,
                spread: 0,
                color: egui::Color32::from_black_alpha(96),
            })
            .show(ui, |ui| {
                ui.set_width(560.0);
                ui.vertical_centered(|ui| {
                    ui.heading("🔐 Bitwarden");
                    if let Some(notice) = &state.notice {
                        ui.add_space(6.0);
                        ui.label(
                            egui::RichText::new(notice)
                                .small()
                                .color(egui::Color32::from_rgb(162, 174, 192)),
                        );
                    }
                    ui.add_space(22.0);

                    ui.set_max_width(460.0);
                    input_with_label(
                        ui,
                        "Server",
                        &mut state.server_url,
                        false,
                        "https://vault.example.com",
                    );
                    ui.add_space(10.0);
                    input_with_label(ui, "Email", &mut state.email, false, "you@example.com");
                    ui.add_space(10.0);
                    input_with_label(ui, "Master password", &mut state.password, true, "");

                    ui.add_space(12.0);
                    ui.checkbox(&mut state.remember, "Remember this device");

                    ui.add_space(14.0);
                    let enabled = !state.in_flight
                        && !state.server_url.is_empty()
                        && !state.email.is_empty()
                        && !state.password.is_empty();
                    ui.add_enabled_ui(enabled, |ui| {
                        let btn = ui.add_sized([460.0, 38.0], egui::Button::new("Login"));
                        if btn.clicked() {
                            action = Some(AuthAction::Login);
                        }
                    });
                    if ui.input(|i| i.key_pressed(egui::Key::Enter))
                        && !state.email.is_empty()
                        && !state.password.is_empty()
                        && !state.server_url.is_empty()
                        && !state.in_flight
                    {
                        action = Some(AuthAction::Login);
                    }
                });
            });
    });

    draw_auth_tail(ctx, ui, state, &mut action);
    action
}

fn draw_saved_session_unlock(
    ui: &mut Ui,
    state: &mut AuthState,
    action: &mut Option<AuthAction>,
) {
    ui.set_min_size(egui::vec2(ui.available_width(), SEARCH_HEIGHT));
    ui.add_space(SEARCH_TOP_MARGIN);

    ui.horizontal(|ui| {
        ui.add_space(SEARCH_HORIZONTAL_MARGIN);

        let bar_width = (ui.available_width() - SEARCH_HORIZONTAL_MARGIN).max(280.0);
        let stroke_color = if state.in_flight {
            egui::Color32::from_rgb(68, 78, 94)
        } else {
            egui::Color32::from_rgb(93, 158, 242)
        };

        egui::Frame::new()
            .fill(egui::Color32::from_rgb(18, 20, 26))
            .stroke(egui::Stroke::new(1.0, stroke_color))
            .inner_margin(egui::Margin::symmetric(14, 7))
            .corner_radius(8.0)
            .show(ui, |ui| {
                ui.set_width(bar_width - 28.0);
                ui.set_height(38.0);
                ui.horizontal_centered(|ui| {
                    ui.label(
                        egui::RichText::new("🔐")
                            .size(20.0)
                            .color(egui::Color32::from_rgb(162, 174, 192)),
                    );
                    ui.add_space(8.0);

                    let right_controls_width = 146.0;
                    let input_width = (ui.available_width() - right_controls_width).max(120.0);
                    let hint = if state.email.trim().is_empty() {
                        "Master password".to_string()
                    } else {
                        format!("Unlock {}", state.email.trim())
                    };
                    let input = ui.add_sized(
                        [input_width, 36.0],
                        egui::TextEdit::singleline(&mut state.password)
                            .id(egui::Id::new("saved-session-password"))
                            .font(egui::FontId::proportional(23.0))
                            .margin(egui::Margin::symmetric(2, 4))
                            .vertical_align(egui::Align::Center)
                            .password(true)
                            .hint_text(hint)
                            .frame(false),
                    );
                    if state.focus_password {
                        input.request_focus();
                        state.focus_password = false;
                    }

                    ui.add_space(8.0);
                    if state.in_flight {
                        ui.add_space(55.0);
                        ui.spinner();
                    } else {
                        let enabled = !state.server_url.is_empty()
                            && !state.email.is_empty()
                            && !state.password.is_empty();
                        ui.add_enabled_ui(enabled, |ui| {
                            if ui.add_sized([72.0, 32.0], egui::Button::new("Unlock")).clicked() {
                                *action = Some(AuthAction::Login);
                            }
                        });
                    }

                    let forget = egui::Button::new(
                        egui::RichText::new("Forget")
                            .small()
                            .color(egui::Color32::from_rgb(178, 126, 126)),
                    )
                    .frame(false);
                    if ui.add_sized([54.0, 28.0], forget).clicked() {
                        state.confirm_forget = true;
                    }
                });
            });
    });

    if let Some(notice) = &state.notice {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add_space(SEARCH_HORIZONTAL_MARGIN + 6.0);
            ui.label(
                egui::RichText::new(notice)
                    .small()
                    .color(egui::Color32::from_rgb(162, 174, 192)),
            );
        });
    }

    if ui.input(|i| i.key_pressed(egui::Key::Enter))
        && !state.email.is_empty()
        && !state.password.is_empty()
        && !state.server_url.is_empty()
        && !state.in_flight
    {
        *action = Some(AuthAction::Login);
    }
}

fn draw_auth_tail(
    ctx: &Context,
    ui: &mut Ui,
    state: &mut AuthState,
    action: &mut Option<AuthAction>,
) {
    if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
        *action = Some(AuthAction::Quit);
    }

    if let Some(e) = &state.error {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add_space(SEARCH_HORIZONTAL_MARGIN + 6.0);
            ui.colored_label(egui::Color32::from_rgb(232, 112, 112), format!("⚠ {e}"));
        });
    }

    if state.confirm_forget {
        egui::Window::new("Forget saved user?")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_width(340.0);
                ui.label("This removes the saved unlock session from this device.");
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        state.confirm_forget = false;
                    }
                    if ui
                        .add(egui::Button::new("Forget user").fill(egui::Color32::from_rgb(
                            120, 45, 45,
                        )))
                        .clicked()
                    {
                        *action = Some(AuthAction::ForgetUser);
                    }
                });
            });
    }
}

fn input_with_label(ui: &mut Ui, label: &str, value: &mut String, password: bool, hint: &str) {
    const INPUT_WIDTH: f32 = 460.0;

    ui.horizontal(|ui| {
        let left_pad = ((ui.available_width() - INPUT_WIDTH) / 2.0).max(0.0);
        ui.add_space(left_pad);
        ui.vertical(|ui| {
            ui.set_width(INPUT_WIDTH);
            ui.label(
                egui::RichText::new(label)
                    .small()
                    .color(egui::Color32::from_rgb(145, 145, 145)),
            );
            ui.add_sized(
                [INPUT_WIDTH, 34.0],
                egui::TextEdit::singleline(value)
                    .font(egui::FontId::proportional(18.0))
                    .margin(egui::Margin::symmetric(8, 4))
                    .vertical_align(egui::Align::Center)
                    .password(password)
                    .hint_text(hint),
            );
        });
    });
}

pub enum AuthAction {
    Login,
    ForgetUser,
    Quit,
}
