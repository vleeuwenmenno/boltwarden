use crate::config;
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
    }
}

pub fn draw_auth(ctx: &Context, ui: &mut Ui, state: &mut AuthState) -> Option<AuthAction> {
    let mut action = None;
    ui.vertical_centered(|ui| {
        ui.add_space(34.0);
        ui.heading(if state.has_saved_session {
            "🔐 Welcome back"
        } else {
            "🔐 Bitwarden"
        });
        ui.add_space(22.0);

        ui.set_max_width(460.0);
        if state.has_saved_session {
            ui.label(
                egui::RichText::new(&state.email)
                    .color(egui::Color32::from_rgb(150, 150, 150)),
            );
            ui.add_space(16.0);
        } else {
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
        }
        input_with_label(ui, "Master password", &mut state.password, true, "");

        if !state.has_saved_session {
            ui.add_space(12.0);
            ui.checkbox(&mut state.remember, "Remember this device");
        }

        ui.add_space(14.0);
        let enabled =
            !state.in_flight
                && !state.server_url.is_empty()
                && !state.email.is_empty()
                && !state.password.is_empty();
        ui.add_enabled_ui(enabled, |ui| {
            let label = if state.has_saved_session { "Unlock" } else { "Login" };
            let btn = ui.add_sized([460.0, 38.0], egui::Button::new(label));
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

        if state.has_saved_session {
            ui.add_space(8.0);
            let forget = egui::Button::new(
                egui::RichText::new("Forget user")
                    .small()
                    .color(egui::Color32::from_rgb(170, 120, 120)),
            )
            .frame(false);
            if ui.add(forget).clicked() {
                state.confirm_forget = true;
            }
        }
    });

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
                        action = Some(AuthAction::ForgetUser);
                    }
                });
            });
    }

    if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
        action = Some(AuthAction::Quit);
    }

    if let Some(e) = &state.error {
        ui.colored_label(egui::Color32::from_rgb(220, 80, 80), format!("⚠ {e}"));
    }

    if state.in_flight {
        ui.spinner();
    }

    action
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
