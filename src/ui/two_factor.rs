use crate::bw::TwoFactorProvider;
use crate::ui::theme::theme;
use crate::ui::widgets;
use egui::{Context, RichText};

pub struct TwoFactorState {
    pub providers: Vec<TwoFactorProvider>,
    pub selected_provider: Option<TwoFactorProvider>,
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
        self.selected_provider = providers.first().copied();
        self.providers = providers;
        self.token.clear();
        self.error = None;
        self.in_flight = false;
        self.focus_token = true;
    }

    fn can_submit(&self) -> bool {
        !self.in_flight && self.selected_provider.is_some() && !self.token.trim().is_empty()
    }
}

pub fn draw_two_factor(ctx: &Context, state: &mut TwoFactorState) -> Option<TwoFactorAction> {
    let mut action = None;
    let t = theme();

    egui::TopBottomPanel::bottom("footer")
        .frame(widgets::footer_frame())
        .show(ctx, |ui| {
            widgets::footer(
                ui,
                &[("⏎", "Verify"), ("↑↓", "Method"), ("Esc", "Back")],
                None,
            )
        });
    egui::TopBottomPanel::top("header")
        .frame(widgets::header_frame())
        .show(ctx, |ui| {
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
        .show(ctx, |ui| {
            let side = ((ui.available_width() - 440.0) / 2.0).max(0.0);
            ui.add_space(6.0);
            ui.horizontal(|ui| {
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
                                provider.label(),
                                None,
                                None,
                                selected,
                            );
                            if response.clicked() {
                                state.selected_provider = Some(provider);
                                state.focus_token = true;
                            }
                        }
                        ui.add_space(10.0);
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
            });
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
}
