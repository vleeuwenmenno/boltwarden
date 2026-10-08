use crate::browser_approval::{BrowserApprovalDecision, BrowserApprovalRequest};
use crate::ui::{theme::theme, widgets};
use eframe::egui;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const INPUT_GUARD: Duration = Duration::from_millis(600);

#[derive(Default)]
pub struct BrowserApprovalUiState {
    pub request: Option<BrowserApprovalRequest>,
    pub password: String,
    pub error: Option<String>,
    pub in_flight: bool,
    pub auto_hide: bool,
    pub shown_at: Option<Instant>,
    pub last_poll: Option<Instant>,
    pub selected_id: Option<String>,
    selection_request: Option<String>,
    scroll_to_selection: bool,
}

impl Drop for BrowserApprovalUiState {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl BrowserApprovalUiState {
    fn sync_selection(&mut self) {
        let Some(request) = &self.request else {
            self.selected_id = None;
            self.selection_request = None;
            self.scroll_to_selection = false;
            self.password.zeroize();
            self.error = None;
            return;
        };
        if self.selection_request.as_ref() != Some(&request.id) {
            self.selected_id = request.choices.first().map(|choice| choice.id.clone());
            self.selection_request = Some(request.id.clone());
            self.scroll_to_selection = true;
            self.password.zeroize();
            self.error = None;
        }
    }

    fn select(&mut self, id: &str) -> bool {
        if self.selected_id.as_deref() == Some(id) {
            return false;
        }
        self.selected_id = Some(id.to_owned());
        self.scroll_to_selection = true;
        self.password.zeroize();
        self.error = None;
        // A key/click that changes accounts cannot also approve the new account.
        self.shown_at = Some(Instant::now());
        true
    }

    pub fn decision(&mut self, approved: bool) -> Option<BrowserApprovalDecision> {
        self.sync_selection();
        let request = self.request.as_ref()?;
        let requires_password = if approved {
            request
                .requires_password_for(self.selected_id.as_deref())
                .ok()?
        } else {
            false
        };
        Some(BrowserApprovalDecision {
            request_id: request.id.clone(),
            approved,
            selected_id: if approved {
                self.selected_id.clone()
            } else {
                None
            },
            use_other_device: false,
            password: if approved && requires_password {
                std::mem::take(&mut self.password)
            } else {
                self.password.zeroize();
                String::new()
            },
        })
    }
}

pub enum BrowserApprovalAction {
    Decide(BrowserApprovalDecision),
    Back,
}

pub fn draw_browser_approval(
    root: &mut egui::Ui,
    state: &mut BrowserApprovalUiState,
) -> Option<BrowserApprovalAction> {
    let ctx = root.ctx().clone();
    let t = theme();
    state.sync_selection();
    let mut action = None;
    let mut ready =
        !state.in_flight && state.shown_at.is_some_and(|at| at.elapsed() >= INPUT_GUARD);
    let mut selection_changed = false;
    let mut approve_requested = false;
    let mut quick_approve = false;
    let Some(request) = state.request.clone() else {
        egui::CentralPanel::default()
            .frame(widgets::body_frame())
            .show(root, |ui| {
                widgets::empty_state(
                    ui,
                    "",
                    "Browser request ended · try again from the browser",
                    false,
                );
                if ui.button("Back").clicked() || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                    action = Some(BrowserApprovalAction::Back);
                }
            });
        return action;
    };
    if !state.in_flight && !request.choices.is_empty() {
        let step = ctx.input_mut(|input| {
            if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                1
            } else if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                -1
            } else {
                0
            }
        });
        if step != 0 {
            let index = request
                .choices
                .iter()
                .position(|choice| Some(&choice.id) == state.selected_id.as_ref())
                .unwrap_or(0);
            let index = (index as isize + step).rem_euclid(request.choices.len() as isize) as usize;
            selection_changed = state.select(&request.choices[index].id);
            if selection_changed {
                ready = false;
            }
        }
    }
    let requires_password = request
        .requires_password_for(state.selected_id.as_deref())
        .unwrap_or(true);
    egui::Panel::bottom("browser-approval-footer")
        .frame(widgets::footer_frame())
        .show(root, |ui| {
            let hints: &[(&str, &str)] = if request.choices.len() > 1 {
                &[("↑↓", "account"), ("Enter", "approve"), ("Esc", "deny")]
            } else {
                &[("Enter", "approve"), ("Esc", "deny")]
            };
            widgets::footer(
                ui,
                hints,
                state.in_flight.then_some(("Verifying…", t.text_muted)),
            );
        });
    egui::Panel::bottom("browser-approval-actions")
        .frame(widgets::header_frame())
        .show(root, |ui| {
            if requires_password {
                widgets::field_label(ui, "Master password");
                let response = widgets::text_input(
                    ui,
                    egui::Id::new("browser-master-password"),
                    &mut state.password,
                    "Verify for this request",
                    true,
                    t.body(),
                );
                if state.shown_at.is_some_and(|at| at.elapsed() < INPUT_GUARD) {
                    response.request_focus();
                }
                ui.add_space(8.0);
            }
            if let Some(error) = &state.error {
                widgets::error_line(ui, error);
            }
            ui.horizontal(|ui| {
                let label = request
                    .action_label
                    .as_deref()
                    .unwrap_or(if requires_password {
                        "Verify and fill"
                    } else {
                        "Approve pairing"
                    });
                if ui.add_enabled(ready, egui::Button::new(label)).clicked()
                    || (ready
                        && ctx
                            .input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Enter)))
                {
                    approve_requested = true;
                }
                if request.allow_fallback
                    && ui
                        .add_enabled(ready, egui::Button::new("Other device"))
                        .clicked()
                {
                    if let Some(mut decision) = state.decision(false) {
                        decision.use_other_device = true;
                        action = Some(BrowserApprovalAction::Decide(decision));
                    }
                }
                if ui
                    .add_enabled(
                        !state.in_flight,
                        egui::Button::new(egui::RichText::new("Deny").color(t.danger)),
                    )
                    .clicked()
                    || (!state.in_flight
                        && ctx
                            .input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)))
                {
                    action = state.decision(false).map(BrowserApprovalAction::Decide);
                }
            });
        });
    widgets::header(root, "browser-approval-header", |ui| {
        ui.horizontal(|ui| {
            widgets::logo(ui, t.input() + 4.0);
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(&request.title)
                    .font(t.font(t.input()))
                    .color(t.text_strong),
            );
        });
        ui.add_space(8.0);
        ui.label(egui::RichText::new(&request.description).color(t.text_muted));
    });
    // Mouse selection happens after the action area is painted. Keep its scroll
    // request for the next frame, when a newly required password field has resized
    // the list. Keyboard changes happen before this point and scroll immediately.
    let scroll_to_selection = std::mem::take(&mut state.scroll_to_selection);
    egui::CentralPanel::default()
        .frame(widgets::body_frame())
        .show(root, |ui| {
            if let Some(fingerprint) = &request.fingerprint {
                ui.label("Verify that this fingerprint matches the extension:");
                ui.monospace(fingerprint);
            }
            egui::ScrollArea::vertical()
                .id_salt("browser-approval-choices")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.add_enabled_ui(!state.in_flight, |ui| {
                        for choice in &request.choices {
                            let selected = state.selected_id.as_ref() == Some(&choice.id);
                            let (rect, response) = widgets::row(ui, selected, widgets::ROW_HEIGHT);
                            // Hovering a choice that needs no password offers a one-click
                            // approve button, so the bottom button is not the only way in.
                            let quick_button = request
                                .action_label
                                .as_deref()
                                .filter(|_| {
                                    ui.rect_contains_pointer(rect)
                                        && request.requires_password_for(Some(&choice.id))
                                            == Ok(false)
                                })
                                .map(|label| {
                                    let galley = ui.painter().layout_no_wrap(
                                        label.to_owned(),
                                        t.font(t.body()),
                                        t.text_strong,
                                    );
                                    let size = egui::vec2(
                                        galley.size().x + 2.0 * ui.spacing().button_padding.x,
                                        (widgets::ROW_HEIGHT - 12.0).min(rect.height()),
                                    );
                                    let button_rect = egui::Rect::from_min_size(
                                        egui::pos2(
                                            rect.right() - 8.0 - size.x,
                                            rect.center().y - size.y / 2.0,
                                        ),
                                        size,
                                    );
                                    (label, button_rect)
                                });
                            let content_rect = quick_button.map_or(rect, |(_, button_rect)| {
                                rect.with_max_x(button_rect.left() - 4.0)
                            });
                            widgets::paint_row_content(
                                ui,
                                content_rect,
                                t.item_icon("login"),
                                None,
                                &choice.label,
                                Some(&choice.description),
                                None,
                                selected,
                            );
                            response.widget_info(|| {
                                egui::WidgetInfo::selected(
                                    egui::WidgetType::SelectableLabel,
                                    ui.is_enabled(),
                                    selected,
                                    format!("{} · {}", choice.label, choice.description),
                                )
                            });
                            if selected && scroll_to_selection {
                                response.scroll_to_me(None);
                            }
                            let quick_clicked = quick_button.is_some_and(|(label, button_rect)| {
                                ui.put(
                                    button_rect,
                                    egui::Button::new(label).sense(if ready {
                                        egui::Sense::click()
                                    } else {
                                        egui::Sense::hover()
                                    }),
                                )
                                .clicked()
                            });
                            if quick_clicked {
                                // The button names its row, so it approves that choice
                                // directly instead of re-arming the selection guard.
                                state.selected_id = Some(choice.id.clone());
                                quick_approve = true;
                            } else if response.clicked() {
                                selection_changed |= state.select(&choice.id);
                            }
                        }
                    });
                });
        });
    if quick_approve && action.is_none() {
        action = state.decision(true).map(BrowserApprovalAction::Decide);
    } else if selection_changed {
        // Choices paint after the footer; defer constructing an approval until
        // their clicks have been handled, including Enter in the same frame.
        ctx.input_mut(|input| {
            input.consume_key(egui::Modifiers::NONE, egui::Key::Enter);
        });
        ctx.request_repaint();
        ctx.request_repaint_after(INPUT_GUARD);
    } else if approve_requested && action.is_none() {
        action = state.decision(true).map(BrowserApprovalAction::Decide);
    }
    action
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_prompt() -> BrowserApprovalUiState {
        let mut state = BrowserApprovalUiState::default();
        state.request = Some(BrowserApprovalRequest {
            id: "accounts".into(),
            title: "Sign in".into(),
            description: String::new(),
            fingerprint: None,
            requires_password: false,
            action_label: Some("Sign in".into()),
            allow_fallback: true,
            choices: vec![
                crate::browser_approval::BrowserApprovalChoice {
                    id: "plain".into(),
                    label: "Plain".into(),
                    description: String::new(),
                    requires_password: false,
                },
                crate::browser_approval::BrowserApprovalChoice {
                    id: "protected".into(),
                    label: "Protected".into(),
                    description: String::new(),
                    requires_password: true,
                },
            ],
        });
        state.shown_at = Some(Instant::now() - Duration::from_secs(1));
        state.sync_selection();
        state
    }

    fn draw_keys(
        ctx: &egui::Context,
        state: &mut BrowserApprovalUiState,
        keys: &[egui::Key],
    ) -> Option<BrowserApprovalAction> {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(680.0, 420.0),
            )),
            events: keys
                .iter()
                .map(|key| egui::Event::Key {
                    key: *key,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                })
                .collect(),
            ..Default::default()
        };
        let mut action = None;
        ctx.run_ui(input, |root| {
            action = draw_browser_approval(root, state);
        })
        .textures_delta
        .clear();
        action
    }

    fn draw_events(
        ctx: &egui::Context,
        state: &mut BrowserApprovalUiState,
        events: Vec<egui::Event>,
    ) -> Option<BrowserApprovalAction> {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(680.0, 420.0),
            )),
            events,
            ..Default::default()
        };
        let mut action = None;
        ctx.run_ui(input, |root| {
            action = draw_browser_approval(root, state);
        })
        .textures_delta
        .clear();
        action
    }

    /// Hovers then clicks near the right edge of the window at height `y`.
    fn click_row_button(y: f32) -> Option<BrowserApprovalAction> {
        let ctx = egui::Context::default();
        let mut state = account_prompt();
        let pos = egui::pos2(640.0, y);
        let button = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        draw_events(&ctx, &mut state, vec![egui::Event::PointerMoved(pos)]);
        draw_events(&ctx, &mut state, vec![button(true), button(false)])
    }

    #[test]
    fn hover_button_approves_only_rows_without_a_password() {
        let approved: Vec<_> = (0..420)
            .step_by(4)
            .filter_map(|y| match click_row_button(y as f32) {
                Some(BrowserApprovalAction::Decide(decision)) if decision.approved => {
                    Some(decision.selected_id.clone())
                }
                _ => None,
            })
            .collect();
        assert!(approved.contains(&Some("plain".into())));
        assert!(!approved.contains(&Some("protected".into())));
    }

    #[test]
    fn changing_account_clears_password_error_and_rearms_input_guard() {
        let mut state = account_prompt();
        state.password = "must not follow the account".into();
        state.error = Some("Incorrect master password".into());
        assert!(state.select("protected"));
        assert!(state.password.is_empty());
        assert!(state.error.is_none());
        assert!(state.shown_at.unwrap().elapsed() < INPUT_GUARD);
        assert_eq!(
            state
                .request
                .as_ref()
                .unwrap()
                .requires_password_for(state.selected_id.as_deref()),
            Ok(true)
        );
        state.password = "verified for protected".into();
        assert_eq!(
            state.decision(true).unwrap().password,
            "verified for protected"
        );
        state.password = "must be erased when hiding password field".into();
        assert!(state.select("plain"));
        assert!(state.password.is_empty());
        // Even an unexpected hidden-field value is never sent for an optional account.
        state.password = "unexpected".into();
        assert!(state.decision(true).unwrap().password.is_empty());
        assert!(state.password.is_empty());
    }

    #[test]
    fn keyboard_account_change_and_enter_cannot_approve_in_the_same_frame() {
        let ctx = egui::Context::default();
        let mut state = account_prompt();
        state.password = "old password".into();
        state.error = Some("Old account error".into());
        assert!(draw_keys(&ctx, &mut state, &[egui::Key::ArrowDown, egui::Key::Enter]).is_none());
        assert_eq!(state.selected_id.as_deref(), Some("protected"));
        assert!(state.password.is_empty());
        assert!(state.error.is_none());
        let other_ctx = egui::Context::default();
        assert!(draw_keys(&other_ctx, &mut state, &[egui::Key::Enter]).is_none());
        state.shown_at = Some(Instant::now() - Duration::from_secs(1));
        state.password = "fresh password".into();
        let ready_ctx = egui::Context::default();
        assert!(
            matches!(draw_keys(&ready_ctx, &mut state, &[egui::Key::Enter]),
            Some(BrowserApprovalAction::Decide(decision)) if decision.approved && decision.selected_id.as_deref() == Some("protected") && decision.password == "fresh password")
        );
    }

    #[test]
    fn rapid_arrow_navigation_stays_responsive_while_approval_guard_is_active() {
        let mut state = account_prompt();
        assert!(
            draw_keys(
                &egui::Context::default(),
                &mut state,
                &[egui::Key::ArrowDown]
            )
            .is_none()
        );
        assert_eq!(state.selected_id.as_deref(), Some("protected"));
        assert!(state.shown_at.unwrap().elapsed() < INPUT_GUARD);
        assert!(
            draw_keys(
                &egui::Context::default(),
                &mut state,
                &[egui::Key::ArrowDown, egui::Key::Enter]
            )
            .is_none()
        );
        assert_eq!(state.selected_id.as_deref(), Some("plain"));
        assert!(draw_keys(&egui::Context::default(), &mut state, &[egui::Key::ArrowUp]).is_none());
        assert_eq!(state.selected_id.as_deref(), Some("protected"));
    }

    #[test]
    fn account_selection_cannot_carry_into_a_new_request_and_denial_clears_password() {
        use crate::browser_approval::BrowserApprovalChoice;
        let mut state = BrowserApprovalUiState::default();
        state.request = Some(BrowserApprovalRequest {
            id: "first".into(),
            title: "Sign in".into(),
            description: String::new(),
            fingerprint: None,
            requires_password: true,
            choices: vec![BrowserApprovalChoice {
                id: "first-choice".into(),
                label: "Account".into(),
                description: String::new(),
                requires_password: false,
            }],
            action_label: Some("Sign in".into()),
            allow_fallback: true,
        });
        assert_eq!(
            state.decision(true).unwrap().selected_id.as_deref(),
            Some("first-choice")
        );
        state.request.as_mut().unwrap().id = "second".into();
        state.request.as_mut().unwrap().choices[0].id = "second-choice".into();
        assert_eq!(
            state.decision(true).unwrap().selected_id.as_deref(),
            Some("second-choice")
        );
        state.password = "secret".into();
        let decision = state.decision(false).unwrap();
        assert!(decision.password.is_empty());
        assert!(decision.selected_id.is_none());
        assert!(state.password.is_empty());
    }

    #[test]
    fn initiating_enter_cannot_approve_a_new_pairing_prompt() {
        let ctx = egui::Context::default();
        let mut state = BrowserApprovalUiState::default();
        state.request = Some(BrowserApprovalRequest {
            id: "request-1".into(),
            title: "Pair browser".into(),
            description: "Test browser".into(),
            fingerprint: Some("ABCD:1234".into()),
            requires_password: false,
            choices: Vec::new(),
            action_label: None,
            allow_fallback: false,
        });
        state.shown_at = Some(Instant::now());
        let draw_enter = |state: &mut BrowserApprovalUiState| {
            let mut action = None;
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(680.0, 420.0),
                )),
                events: vec![egui::Event::Key {
                    key: egui::Key::Enter,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                ..Default::default()
            };
            let mut output = ctx.run_ui(input, |root| {
                action = draw_browser_approval(root, state);
            });
            output.textures_delta.clear();
            action
        };
        assert!(draw_enter(&mut state).is_none());
        state.shown_at = Some(Instant::now() - Duration::from_secs(1));
        assert!(
            matches!(draw_enter(&mut state), Some(BrowserApprovalAction::Decide(decision)) if decision.approved && decision.request_id == "request-1")
        );
    }
}
