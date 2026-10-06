use crate::bw::TwoFactorProvider;
use crate::ui::shortcuts as sc;
use crate::ui::theme::theme;
use crate::ui::widgets;
use egui::RichText;

pub struct TwoFactorState {
    pub providers: Vec<TwoFactorProvider>,
    pub selected_provider: Option<TwoFactorProvider>,
    scrolled_to: Option<TwoFactorProvider>,
    pub token: String,
    pub remember: bool,
    pub error: Option<String>,
    pub in_flight: bool,
    pub focus_token: bool,
}

impl Default for TwoFactorState {
    fn default() -> Self {
        Self {
            providers: Vec::new(),
            selected_provider: None,
            scrolled_to: None,
            token: String::new(),
            remember: true,
            error: None,
            in_flight: false,
            focus_token: true,
        }
    }
}

impl TwoFactorState {
    pub fn set_providers(&mut self, providers: Vec<TwoFactorProvider>) {
        self.selected_provider = providers.iter().copied().find(|p| p.supports_code_entry());
        self.providers = providers;
        self.scrolled_to = None;
        self.token.clear();
        self.error = None;
        self.in_flight = false;
        self.focus_token = true;
    }

    fn can_submit(&self) -> bool {
        !self.in_flight
            && self
                .selected_provider
                .is_some_and(|p| p.supports_code_entry())
            && !self.token.trim().is_empty()
    }
}

pub fn draw_two_factor(root: &mut egui::Ui, state: &mut TwoFactorState) -> Option<TwoFactorAction> {
    let ctx = &root.ctx().clone();
    let mut action = None;
    let t = theme();

    egui::Panel::bottom("footer")
        .frame(widgets::footer_frame())
        .show(root, |ui| {
            widgets::footer(
                ui,
                &[
                    (sc::ENTER, "Verify"),
                    (sc::UP_DOWN, "Method"),
                    (sc::ESCAPE, "Back"),
                ],
                None,
            )
        });
    widgets::header(root, "header", |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(t.icon("\u{f132}", "🛡"))
                    .size(t.title())
                    .color(t.accent),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new("Two-step login")
                    .size(t.title())
                    .color(t.text_strong),
            );
        });
    });

    ctx.input(|input| {
        let count = state.providers.len();
        if count > 1 {
            let current = state
                .selected_provider
                .and_then(|selected| state.providers.iter().position(|p| *p == selected))
                .unwrap_or(0);
            if input.key_pressed(egui::Key::ArrowDown) {
                state.selected_provider = Some(state.providers[(current + 1) % count]);
            }
            if input.key_pressed(egui::Key::ArrowUp) {
                state.selected_provider = Some(state.providers[(current + count - 1) % count]);
            }
        }
    });

    egui::CentralPanel::default()
        .frame(widgets::body_frame())
        .show(root, |ui| {
            let side = ((ui.available_width() - 440.0) / 2.0).max(0.0);
            ui.add_space(6.0);
            egui::ScrollArea::vertical().id_salt("two-factor-scroll").show(ui, |ui| { ui.horizontal(|ui| {
                ui.add_space(side);
                ui.vertical(|ui| {
                    ui.set_width(440.0);
                    if state.providers.len() > 1 {
                        widgets::field_label(ui, "Method");
                        for provider in state.providers.clone() {
                            let selected = state.selected_provider == Some(provider);
                            let (rect, response) = widgets::row(ui, selected, 34.0);
                            widgets::paint_row_content(
                                ui,
                                rect,
                                if selected { "●" } else { "○" },
                                None,
                                provider.label(),
                                None,
                                None,
                                selected,
                            );
                            response.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::RadioButton, ui.is_enabled(), selected, provider.label()));
                            if selected && state.scrolled_to != Some(provider) {
                                response.scroll_to_me(None);
                                state.scrolled_to = Some(provider);
                            }
                            if response.clicked() {
                                state.selected_provider = Some(provider);
                                state.focus_token = true;
                            }
                        }
                        ui.add_space(10.0);
                    }

                    if !state.selected_provider.is_some_and(|p| p.supports_code_entry()) {
                        ui.label("This login method is not supported here. Use an authenticator or YubiKey OTP method, or sign in with the official Bitwarden app.");
                        if widgets::button(ui, "Back", false, !state.in_flight).clicked() { action = Some(TwoFactorAction::Back); }
                        return;
                    }
                    let label = state
                        .selected_provider
                        .map(|provider| format!("Code from {}", provider.label()))
                        .unwrap_or_else(|| "Code".into());
                    widgets::field_label(ui, &label);
                    let response = widgets::text_input(
                        ui,
                        egui::Id::new("two-factor-token"),
                        &mut state.token,
                        "123456",
                        false,
                        t.input(),
                    );
                    if state.focus_token && !state.in_flight {
                        response.request_focus();
                        state.focus_token = false;
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
                            } else if widgets::button(ui, "Verify", true, state.can_submit())
                                .clicked()
                            {
                                action = Some(TwoFactorAction::Verify);
                            }
                            if widgets::button(ui, "Back", false, !state.in_flight).clicked() {
                                action = Some(TwoFactorAction::Back);
                            }
                        });
                    });

                    if let Some(error) = &state.error {
                        ui.add_space(8.0);
                        widgets::error_line(ui, error);
                    }
                });
            }); });
        });

    if ctx.input(|i| i.key_pressed(egui::Key::Enter)) && state.can_submit() {
        action = Some(TwoFactorAction::Verify);
    }
    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) && !state.in_flight {
        action = Some(TwoFactorAction::Back);
    }

    action
}

pub enum TwoFactorAction {
    Verify,
    Back,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyboard_keeps_selected_method_visible_when_list_overflows() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut state = TwoFactorState::default();
        state.set_providers(vec![
            TwoFactorProvider::Authenticator,
            TwoFactorProvider::Email,
            TwoFactorProvider::Duo,
            TwoFactorProvider::Yubikey,
            TwoFactorProvider::Remember,
            TwoFactorProvider::OrganizationDuo,
            TwoFactorProvider::WebAuthn,
            TwoFactorProvider::RecoveryCode,
        ]);
        state.focus_token = false;
        let mut time = 0.0;
        for key in [None, Some(egui::Key::ArrowUp), Some(egui::Key::ArrowDown)] {
            let mut bounds = None;
            for tick in 0..20 {
                time += 0.05;
                let mut input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(680., 280.),
                    )),
                    time: Some(time),
                    ..Default::default()
                };
                if let Some(key) = key
                    && tick < 2
                {
                    input.events.push(egui::Event::Key {
                        key,
                        physical_key: None,
                        pressed: tick == 0,
                        repeat: false,
                        modifiers: egui::Modifiers::NONE,
                    });
                }
                let mut out = ctx.run_ui(input, |root| {
                    draw_two_factor(root, &mut state);
                });
                out.textures_delta.clear();
                for (_, node) in out.platform_output.accesskit_update.unwrap().nodes {
                    if node.label() == state.selected_provider.map(|p| p.label()) {
                        bounds = node.bounds();
                    }
                }
            }
            let bounds = bounds.expect("selected method has accessibility bounds");
            assert!(
                bounds.y0 >= 40. && bounds.y1 <= 255.,
                "selected method must remain in viewport: {bounds:?}"
            );
        }
    }

    #[test]
    fn setting_providers_requests_token_focus_once() {
        let mut state = TwoFactorState {
            focus_token: false,
            ..TwoFactorState::default()
        };
        state.set_providers(vec![TwoFactorProvider::Authenticator]);

        assert!(state.focus_token);
        assert_eq!(
            state.selected_provider,
            Some(TwoFactorProvider::Authenticator)
        );
        assert!(state.token.is_empty());
    }
    #[test]
    fn unsupported_methods_cannot_be_submitted_as_codes() {
        let mut state = TwoFactorState::default();
        state.set_providers(vec![
            TwoFactorProvider::WebAuthn,
            TwoFactorProvider::Authenticator,
        ]);
        assert_eq!(
            state.selected_provider,
            Some(TwoFactorProvider::Authenticator)
        );
        state.token = "123456".into();
        assert!(state.can_submit());
        for provider in [
            TwoFactorProvider::WebAuthn,
            TwoFactorProvider::Duo,
            TwoFactorProvider::Email,
            TwoFactorProvider::Unknown(99),
        ] {
            state.selected_provider = Some(provider);
            assert!(!state.can_submit());
        }
    }
}
