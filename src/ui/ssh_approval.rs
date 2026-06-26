use crate::model::{
    SshApprovalDecision, SshApprovalRemember, SshApprovalRequest, SshApprovalStatus,
};
use crate::ui::footer::draw_footer;
use egui::{Context, Ui};

pub const SSH_APPROVAL_WIDTH: f32 = 640.0;
pub const SSH_APPROVAL_HEIGHT: f32 = 400.0;

#[derive(Default)]
pub struct SshApprovalUiState {
    pub request: Option<SshApprovalRequest>,
    pub status: Option<SshApprovalStatus>,
    pub selected_action: usize,
    pub error: Option<String>,
    pub auto_hide: bool,
}

impl SshApprovalUiState {
    pub fn reset_for_request(&mut self, request: Option<SshApprovalRequest>, auto_hide: bool) {
        self.request = request;
        self.status = None;
        self.selected_action = 0;
        self.error = None;
        self.auto_hide = auto_hide;
    }
}

pub enum SshApprovalAction {
    Decide(SshApprovalDecision),
    Back,
}

pub fn draw_ssh_approval(
    ctx: &Context,
    ui: &mut Ui,
    state: &mut SshApprovalUiState,
    show_shortcuts: bool,
) -> Option<SshApprovalAction> {
    let mut action = None;
    ui.add_space(14.0);
    ui.horizontal(|ui| {
        ui.add_space(20.0);
        ui.vertical(|ui| {
            let width = ui.available_width().max(320.0);
            egui::Frame::new()
                .fill(egui::Color32::from_rgb(18, 20, 26))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(58, 92, 142)))
                .inner_margin(egui::Margin::same(14))
                .corner_radius(8.0)
                .show(ui, |ui| {
                    ui.set_min_width(width - 28.0);
                    match state.request.clone() {
                        Some(request) => {
                            action = draw_pending_request(ctx, ui, state, &request);
                        }
                        None => {
                            if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
                                action = Some(SshApprovalAction::Back);
                            }
                            draw_status(ui, state);
                        }
                    }
                });
            if show_shortcuts {
                ui.add_space(8.0);
                draw_footer(
                    ui,
                    if state.request.is_some() {
                        &[
                            ("⏎", "Approve"),
                            ("←", "Choice"),
                            ("→", "Choice"),
                            ("Esc", "Deny"),
                        ]
                    } else {
                        &[("Esc", "Back")]
                    },
                );
            }
        });
    });
    action
}

fn draw_pending_request(
    ctx: &Context,
    ui: &mut Ui,
    state: &mut SshApprovalUiState,
    request: &SshApprovalRequest,
) -> Option<SshApprovalAction> {
    let mut action = None;
    handle_keys(ctx, state, request, &mut action);

    ui.horizontal(|ui| {
        draw_key_glyph(ui);
        ui.vertical(|ui| {
            ui.heading("Allow SSH key use?");
            ui.label(
                egui::RichText::new("A process wants to sign with a vault SSH key.")
                    .color(egui::Color32::from_rgb(154, 164, 180)),
            );
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                egui::RichText::new(format!("{}s", seconds_remaining(request)))
                    .strong()
                    .color(egui::Color32::from_rgb(245, 190, 92)),
            );
        });
    });
    ui.add_space(12.0);
    ui.separator();
    ui.add_space(12.0);

    detail_grid(ui, request);

    if let Some(error) = &state.error {
        ui.add_space(8.0);
        ui.label(egui::RichText::new(error).color(egui::Color32::from_rgb(245, 110, 110)));
    }

    ui.add_space(14.0);
    ui.horizontal(|ui| {
        let spacing = ui.spacing().item_spacing.x;
        let button_width = ((ui.available_width() - spacing * 3.0) / 4.0).clamp(92.0, 126.0);
        let choices = [
            ("Approve once", SshApprovalRemember::Once),
            ("15 min process", SshApprovalRemember::Process),
            ("15 min parent", SshApprovalRemember::Parent),
        ];
        for (idx, (label, remember)) in choices.iter().enumerate() {
            let button = egui::Button::new(*label)
                .fill(if state.selected_action == idx {
                    egui::Color32::from_rgb(54, 106, 172)
                } else {
                    egui::Color32::from_rgb(35, 40, 50)
                })
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(70, 82, 100)));
            if ui.add_sized([button_width, 30.0], button).clicked() {
                action = Some(decision(request, true, *remember));
            }
        }
        let deny = egui::Button::new("Deny")
            .fill(egui::Color32::from_rgb(70, 38, 46))
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(112, 58, 72)));
        if ui.add_sized([button_width, 30.0], deny).clicked() {
            action = Some(decision(request, false, SshApprovalRemember::Once));
        }
    });

    action
}

fn handle_keys(
    ctx: &Context,
    state: &mut SshApprovalUiState,
    request: &SshApprovalRequest,
    action: &mut Option<SshApprovalAction>,
) {
    ctx.input(|input| {
        for event in &input.events {
            let egui::Event::Key { key, pressed, .. } = event else {
                continue;
            };
            if !pressed {
                continue;
            }
            match key {
                egui::Key::Escape => {
                    *action = Some(decision(request, false, SshApprovalRemember::Once));
                }
                egui::Key::Enter => {
                    let remember = match state.selected_action {
                        1 => SshApprovalRemember::Process,
                        2 => SshApprovalRemember::Parent,
                        _ => SshApprovalRemember::Once,
                    };
                    *action = Some(decision(request, true, remember));
                }
                egui::Key::ArrowRight | egui::Key::Tab => {
                    state.selected_action = (state.selected_action + 1) % 3;
                }
                egui::Key::ArrowLeft => {
                    state.selected_action = (state.selected_action + 2) % 3;
                }
                _ => {}
            }
        }
    });
}

fn decision(
    request: &SshApprovalRequest,
    approved: bool,
    remember: SshApprovalRemember,
) -> SshApprovalAction {
    SshApprovalAction::Decide(SshApprovalDecision {
        request_id: request.id.clone(),
        approved,
        remember,
    })
}

fn draw_key_glyph(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(42.0, 42.0), egui::Sense::hover());
    let painter = ui.painter();
    painter.circle_filled(rect.center(), 18.0, egui::Color32::from_rgb(42, 68, 104));
    let color = egui::Color32::from_rgb(220, 230, 244);
    let stroke = egui::Stroke::new(2.0, color);
    let center = rect.center() + egui::vec2(-5.0, 0.0);
    painter.circle_stroke(center, 4.5, stroke);
    painter.line_segment([center + egui::vec2(4.5, 0.0), center + egui::vec2(16.0, 0.0)], stroke);
    painter.line_segment([center + egui::vec2(11.0, 0.0), center + egui::vec2(11.0, 5.0)], stroke);
    painter.line_segment([center + egui::vec2(15.5, 0.0), center + egui::vec2(15.5, 4.0)], stroke);
}

fn detail_grid(ui: &mut Ui, request: &SshApprovalRequest) {
    detail(ui, "Key", &request.key_name);
    detail(
        ui,
        "Fingerprint",
        request.fingerprint.as_deref().unwrap_or("Unavailable"),
    );
    detail(ui, "Algorithm", &request.algorithm);
    detail(
        ui,
        "Process",
        request.client.process_name.as_deref().unwrap_or("Unknown"),
    );
    detail(ui, "PID", &request.client.pid.to_string());
    detail(
        ui,
        "Command",
        request
            .client
            .command_line
            .as_deref()
            .unwrap_or("Unavailable"),
    );
    detail(
        ui,
        "Executable",
        request.client.executable.as_deref().unwrap_or("Unavailable"),
    );
    detail(ui, "CWD", request.client.cwd.as_deref().unwrap_or("Unavailable"));
    detail(
        ui,
        "Parent",
        request.client.parent_name.as_deref().unwrap_or("Unavailable"),
    );
}

fn detail(ui: &mut Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [82.0, 20.0],
            egui::Label::new(
                egui::RichText::new(label)
                    .monospace()
                    .color(egui::Color32::from_rgb(154, 164, 180)),
            ),
        );
        let value_width = (ui.available_width() - 2.0).max(80.0);
        ui.add_sized(
            [value_width, 20.0],
            egui::Label::new(
                egui::RichText::new(value)
                    .monospace()
                    .color(egui::Color32::from_rgb(224, 230, 240)),
            )
            .truncate(),
        )
        .on_hover_text(value);
    });
    ui.add_space(5.0);
}

fn draw_status(ui: &mut Ui, state: &SshApprovalUiState) {
    ui.vertical_centered(|ui| {
        ui.add_space(80.0);
        let text = state
            .status
            .as_ref()
            .map(|status| status.message.as_str())
            .unwrap_or("No SSH approval request is pending.");
        ui.heading(text);
        ui.add_space(8.0);
        if let Some(status) = &state.status {
            ui.label(
                egui::RichText::new(format!(
                    "{} · {}",
                    status.key_name,
                    status.process_name.as_deref().unwrap_or("unknown process")
                ))
                    .color(egui::Color32::from_rgb(154, 164, 180)),
            );
        }
    });
}

fn seconds_remaining(request: &SshApprovalRequest) -> u64 {
    let now = unix_millis_now();
    request
        .expires_at_unix_ms
        .saturating_sub(now)
        .div_ceil(1000)
}

fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
