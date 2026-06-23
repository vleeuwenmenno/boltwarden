use crate::bw::TwoFactorProvider;
use egui::{Context, Ui};

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
}

pub fn draw_two_factor(
    _ctx: &Context,
    ui: &mut Ui,
    state: &mut TwoFactorState,
) -> Option<TwoFactorAction> {
    let mut action = None;
    ui.vertical_centered(|ui| {
        ui.add_space(40.0);
        ui.heading("Two-factor verification");
        ui.add_space(20.0);
    });

    if !state.providers.is_empty() {
        ui.label("Provider:");
        for provider in &state.providers {
            ui.radio_value(&mut state.selected_provider, Some(*provider), provider.label());
        }
    }

    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label("Code:");
        let response = ui.add(
            egui::TextEdit::singleline(&mut state.token)
                .password(false)
                .desired_width(220.0),
        );
        if state.focus_token && !state.in_flight {
            response.request_focus();
            state.focus_token = false;
        }
    });

    ui.checkbox(&mut state.remember, "Remember this device");

    ui.add_space(10.0);

    ui.horizontal(|ui| {
        let can_submit = !state.in_flight
            && !state.providers.is_empty()
            && state.selected_provider.is_some()
            && !state.token.trim().is_empty();
        if ui
            .add_enabled(can_submit, egui::Button::new("Verify"))
            .clicked()
        {
            action = Some(TwoFactorAction::Verify);
        }
        if ui.button("Back").clicked() {
            action = Some(TwoFactorAction::Back);
        }
    });

    if ui.input(|i| i.key_pressed(egui::Key::Enter))
        && !state.in_flight
        && !state.providers.is_empty()
        && state.selected_provider.is_some()
        && !state.token.trim().is_empty()
    {
        action = Some(TwoFactorAction::Verify);
    }
    if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
        action = Some(TwoFactorAction::Back);
    }

    if let Some(error) = &state.error {
        ui.colored_label(egui::Color32::from_rgb(220, 80, 80), format!("⚠ {error}"));
    }

    if state.in_flight {
        ui.spinner();
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
        let mut state = TwoFactorState::default();
        state.focus_token = false;
        state.set_providers(vec![TwoFactorProvider::Authenticator]);

        assert!(state.focus_token);
        assert_eq!(state.selected_provider, Some(TwoFactorProvider::Authenticator));
        assert!(state.token.is_empty());
    }
}
