use crate::model::{
    SshApprovalDecision, SshApprovalRemember, SshApprovalRequest, SshApprovalStatus,
};
use crate::ui::theme::theme;
use crate::ui::widgets;
use egui::{Context, RichText, Ui};
use std::time::{Duration, Instant};

/// Keys pressed this soon after the prompt appears are ignored, so an Enter meant for the
/// terminal that triggered the request cannot approve it by accident.
const INPUT_GUARD: Duration = Duration::from_millis(600);

#[derive(Default)]
pub struct SshApprovalUiState {
    pub request: Option<SshApprovalRequest>,
    pub status: Option<SshApprovalStatus>,
    pub selected_action: usize,
    pub error: Option<String>,
    pub auto_hide: bool,
    shown_at: Option<Instant>,
}

impl SshApprovalUiState {
    pub fn reset_for_request(&mut self, request: Option<SshApprovalRequest>, auto_hide: bool) {
        self.request = request;
        self.status = None;
        self.selected_action = 0;
        self.error = None;
        self.auto_hide = auto_hide;
        self.shown_at = Some(Instant::now());
    }

    fn input_ready(&self) -> bool {
        self.shown_at.is_none_or(|at| at.elapsed() >= INPUT_GUARD)
    }
}

pub enum SshApprovalAction {
    Decide(SshApprovalDecision),
    Back,
}

pub fn draw_ssh_approval(
    root: &mut egui::Ui,
    state: &mut SshApprovalUiState,
    show_shortcuts: bool,
) -> Option<SshApprovalAction> {
    let ctx = &root.ctx().clone();
    let t = theme();
    let mut action = None;
    let request = state.request.clone();

    if show_shortcuts {
        let hints: &[(&str, &str)] = if request.is_some() {
            &[
                ("⏎", "Confirm"),
                ("←", "Choice"),
                ("→", "Choice"),
                ("Esc", "Deny"),
            ]
        } else {
            &[("Esc", "Back")]
        };
        egui::Panel::bottom("footer")
            .frame(widgets::footer_frame())
            .show(root, |ui| widgets::footer(ui, hints, None));
    }

    widgets::header(root, "header", |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(t.icon("\u{f084}", "🔑"))
                    .size(t.title())
                    .color(t.warning),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new("Allow SSH key use?")
                    .size(t.title())
                    .color(t.text_strong),
            );
            if let Some(request) = &request {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("{}s", seconds_remaining(request))).color(t.warning),
                    );
                });
            }
        });
    });

    egui::CentralPanel::default()
        .frame(widgets::body_frame().inner_margin(egui::Margin::symmetric(16, 10)))
        .show(root, |ui| match &request {
            Some(request) => action = draw_pending_request(ctx, ui, state, request),
            None => {
                if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
                    action = Some(SshApprovalAction::Back);
                }
                draw_status(ui, state);
            }
        });
    action
}

fn draw_pending_request(
    ctx: &Context,
    ui: &mut Ui,
    state: &mut SshApprovalUiState,
    request: &SshApprovalRequest,
) -> Option<SshApprovalAction> {
    let t = theme();
    let mut action = None;
    if state.input_ready() {
        handle_keys(ctx, state, request, &mut action);
    } else {
        ctx.request_repaint_after(INPUT_GUARD);
    }

    detail_grid(ui, request);

    if let Some(error) = &state.error {
        ui.add_space(6.0);
        widgets::error_line(ui, error);
    }

    ui.add_space(12.0);
    ui.horizontal(|ui| {
        if widgets::button(ui, "Approve once", state.selected_action == 0, true).clicked() {
            action = Some(decision(request, true, SshApprovalRemember::Once));
        }
        if widgets::button(
            ui,
            "Remember process (15 min)",
            state.selected_action == 1,
            true,
        )
        .clicked()
        {
            action = Some(decision(request, true, SshApprovalRemember::Process));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let deny = ui.add(
                egui::Button::new(RichText::new("Deny").color(t.danger))
                    .fill(t.surface)
                    .stroke(egui::Stroke::new(1.0_f32, t.danger))
                    .corner_radius(t.rounding)
                    .min_size(egui::vec2(96.0, 32.0)),
            );
            if deny.clicked() {
                action = Some(decision(request, false, SshApprovalRemember::Once));
            }
        });
    });
    ui.add_space(6.0);
    ui.label(
        RichText::new("Remember applies only to this running process for up to 15 minutes.")
            .size(t.small())
            .color(t.text_faint),
    );

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
                        _ => SshApprovalRemember::Once,
                    };
                    *action = Some(decision(request, true, remember));
                }
                egui::Key::ArrowRight | egui::Key::ArrowLeft | egui::Key::Tab => {
                    state.selected_action = (state.selected_action + 1) % 2;
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

fn detail_grid(ui: &mut Ui, request: &SshApprovalRequest) {
    ui.spacing_mut().interact_size.y = 18.0;
    ui.spacing_mut().item_spacing.y = 5.0;
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
        request
            .client
            .executable
            .as_deref()
            .unwrap_or("Unavailable"),
    );
    detail(
        ui,
        "CWD",
        request.client.cwd.as_deref().unwrap_or("Unavailable"),
    );
    detail(
        ui,
        "Parent",
        request
            .client
            .parent_name
            .as_deref()
            .unwrap_or("Unavailable"),
    );
}

fn detail(ui: &mut Ui, label: &str, value: &str) {
    let t = theme();
    ui.horizontal(|ui| {
        ui.add_sized(
            [96.0, 18.0],
            egui::Label::new(RichText::new(label).size(t.small()).color(t.text_muted)),
        );
        ui.add(
            egui::Label::new(
                RichText::new(value)
                    .font(t.mono(t.small() + 1.0))
                    .color(t.text_strong),
            )
            .truncate(),
        )
        .on_hover_text(value);
    });
}

fn draw_status(ui: &mut Ui, state: &SshApprovalUiState) {
    let t = theme();
    let text = state
        .status
        .as_ref()
        .map(|status| status.message.as_str())
        .unwrap_or("No SSH approval request is pending.");
    widgets::empty_state(ui, t.icon("\u{f084}", "🔑"), text, false);
    if let Some(status) = &state.status {
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} · {}",
                    status.key_name,
                    status.process_name.as_deref().unwrap_or("unknown process")
                ))
                .color(t.text_faint),
            );
        });
    }
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
