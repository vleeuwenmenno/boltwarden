use crate::model::BwItemDetail;
use crate::clipboard;
use egui::{Context, Ui};
use std::time::Instant;

pub struct SummaryState {
    pub detail: Option<BwItemDetail>,
    pub detail_id: Option<String>,
    pub error: Option<String>,
    pub in_flight: bool,
    pub reveal_fields: std::collections::HashSet<usize>,
    pub selected_field: usize,
    pub copied_field: Option<(String, Instant)>,
    pub totp: Option<String>,
    pub totp_fetched_at: Option<Instant>,
    pub totp_in_flight: bool,
}

impl Default for SummaryState {
    fn default() -> Self {
        Self {
            detail: None,
            detail_id: None,
            error: None,
            in_flight: false,
            reveal_fields: Default::default(),
            selected_field: 0,
            copied_field: None,
            totp: None,
            totp_fetched_at: None,
            totp_in_flight: false,
        }
    }
}

impl SummaryState {
    pub fn total_fields(&self) -> usize {
        self.detail.as_ref().map(|d| {
            let mut n = 0;
            if d.username.is_some() { n += 1; }
            if d.password.is_some() { n += 1; }
            n += d.uris.len();
            if d.totp.is_some() { n += 1; }
            if d.notes.is_some() { n += 1; }
            n += d.custom_fields.len();
            n
        }).unwrap_or(0)
    }

    pub fn needs_totp_refresh(&self) -> bool {
        if self.totp_in_flight {
            return false;
        }
        if self.detail.as_ref().and_then(|d| d.totp.as_ref()).is_none() {
            return false;
        }
        match self.totp_fetched_at {
            None => true,
            Some(t) => t.elapsed() >= std::time::Duration::from_secs(30),
        }
    }
}

pub fn draw_summary(
    _ctx: &Context,
    ui: &mut Ui,
    state: &mut SummaryState,
) -> Option<SummaryAction> {
    let mut action = None;
    let mut copied = false;

    if state.in_flight && state.detail.is_none() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Loading entry...");
        });
        return None;
    }

    let detail = match &state.detail {
        Some(d) => d.clone(),
        None => {
            ui.label("No entry loaded.");
            return None;
        }
    };

    // Header
    ui.horizontal(|ui| {
        let icon = match detail.item_type.as_str() {
            "login" => "🔑",
            "secureNote" => "📝",
            "card" => "💳",
            "identity" => "👤",
            _ => "📦",
        };
        ui.label(icon);
        ui.heading(&detail.name);
    });
    if let Some(folder) = &detail.folder {
        ui.label(
            egui::RichText::new(format!("📁 {folder}"))
                .small()
                .color(egui::Color32::from_rgb(140, 140, 140)),
        );
    }
    ui.add_space(8.0);
    ui.separator();
    ui.add_space(8.0);

    let mut copy_selected = false;
    ui.input(|i| {
        for event in &i.events {
            let egui::Event::Key { key, pressed, .. } = event else {
                continue;
            };
            if !pressed {
                continue;
            }
            match key {
                egui::Key::Escape | egui::Key::ArrowLeft => action = Some(SummaryAction::Back),
                egui::Key::ArrowDown => {
                    state.selected_field =
                        (state.selected_field + 1) % state.total_fields().max(1);
                }
                egui::Key::ArrowUp => {
                    let total = state.total_fields().max(1);
                    state.selected_field = (state.selected_field + total - 1) % total;
                }
                egui::Key::Enter => copy_selected = true,
                _ => {}
            }
        }
    });

    let mut field_idx = 0usize;

    let copyable = |ui: &mut Ui,
                    label: &str,
                    value: &str,
                    hidden: bool,
                    state: &mut SummaryState,
                    idx: &mut usize|
     -> bool {
        let mut did_copy = false;
        let selected = *idx == state.selected_field;
        let bg = if selected {
            egui::Color32::from_rgb(50, 70, 110)
        } else {
            egui::Color32::TRANSPARENT
        };
        let frame = egui::Frame::new()
            .fill(bg)
            .inner_margin(egui::Margin::symmetric(6, 4))
            .corner_radius(4.0);

        let frame_response = frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add_sized(
                    [92.0, 28.0],
                    egui::Label::new(
                        egui::RichText::new(format!("{label}:"))
                            .color(egui::Color32::from_rgb(170, 170, 170))
                            .monospace(),
                    ),
                );

                let display_value = if hidden && !is_revealed(state, *idx) {
                    "•".repeat(value.len().min(20))
                } else {
                    value.to_string()
                };
                let controls_width = 34.0
                    + if hidden {
                        34.0 + ui.spacing().item_spacing.x
                    } else {
                        0.0
                    };
                let value_width = (ui.available_width() - controls_width).max(48.0);
                let mut display_text = display_value;

                let resp = ui.add_sized(
                    [value_width, 28.0],
                    egui::TextEdit::singleline(&mut display_text)
                        .font(egui::FontId::monospace(14.0))
                        .margin(egui::Margin::symmetric(6, 3))
                        .vertical_align(egui::Align::Center)
                        .desired_width(value_width)
                        .interactive(false),
                );

                if hidden {
                    let eye_txt = if is_revealed(state, *idx) { "🙈" } else { "👁" };
                    if ui.button(eye_txt).clicked() {
                        toggle_reveal(state, *idx);
                    }
                }

                let copy_btn = ui.button("📋");
                if copy_btn.clicked() || (selected && copy_selected) {
                    if clipboard::copy(value) {
                        state.copied_field = Some((label.to_string(), Instant::now()));
                        did_copy = true;
                    }
                }

                if resp.clicked() {
                    state.selected_field = *idx;
                }
            });
        });
        if selected {
            ui.scroll_to_rect(frame_response.response.rect, Some(egui::Align::Center));
        }

        *idx += 1;
        did_copy
    };

    let scroll_height = (ui.available_height() - 56.0).max(120.0);
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), scroll_height),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(scroll_height)
                .show(ui, |ui| {
            if let Some(u) = &detail.username {
                copied |= copyable(ui, "Username", u, false, state, &mut field_idx);
            }
            if let Some(p) = &detail.password {
                copied |= copyable(ui, "Password", p, true, state, &mut field_idx);
            }
            for uri in &detail.uris {
                copied |= copyable(ui, "URI", uri, false, state, &mut field_idx);
            }
            if detail.totp.is_some() {
                let totp_display = state.totp.clone().unwrap_or_else(|| "------".into());
                let remaining = totp_remaining(&state.totp_fetched_at);
                let selected = field_idx == state.selected_field;
                let bg = if selected {
                    egui::Color32::from_rgb(50, 70, 110)
                } else {
                    egui::Color32::TRANSPARENT
                };
                let frame = egui::Frame::new()
                    .fill(bg)
                    .inner_margin(egui::Margin::symmetric(6, 4))
                    .corner_radius(4.0);

                let frame_response = frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [92.0, 28.0],
                            egui::Label::new(
                                egui::RichText::new("TOTP:")
                                    .color(egui::Color32::from_rgb(170, 170, 170))
                                    .monospace(),
                            ),
                        );
                        let reserve_width = 72.0;
                        let value_width = (ui.available_width() - reserve_width).max(48.0);
                        let resp = ui.add_sized(
                            [value_width, 28.0],
                            egui::Label::new(
                                egui::RichText::new(&totp_display)
                                    .strong()
                                    .size(18.0),
                            ),
                        );
                        if let Some(r) = remaining {
                            ui.label(
                                egui::RichText::new(format!("{r}s"))
                                    .small()
                                    .color(egui::Color32::from_rgb(140, 140, 140)),
                            );
                        }
                        let copy_btn = ui.button("📋");
                        if copy_btn.clicked() || (selected && copy_selected) {
                            if !totp_display.is_empty() && totp_display != "------" {
                                if clipboard::copy(&totp_display) {
                                    state.copied_field = Some(("TOTP".into(), Instant::now()));
                                    copied = true;
                                }
                            }
                        }
                        if resp.clicked() {
                            state.selected_field = field_idx;
                        }
                    });
                });
                if selected {
                    ui.scroll_to_rect(frame_response.response.rect, Some(egui::Align::Center));
                }
                field_idx += 1;
            }
            for cf in &detail.custom_fields {
                copied |= copyable(
                    ui,
                    &cf.name,
                    &cf.value,
                    cf.hidden,
                    state,
                    &mut field_idx,
                );
            }
            if let Some(notes) = &detail.notes {
                copied |= copyable(ui, "Notes", notes, false, state, &mut field_idx);
            }
                });
        },
    );

    // Copied indicator
    if let Some((label, t)) = &state.copied_field {
        if t.elapsed() < std::time::Duration::from_secs(2) {
            ui.colored_label(
                egui::Color32::from_rgb(80, 200, 80),
                format!("✓ Copied {label}"),
            );
        }
    }

    if let Some(e) = &state.error {
        ui.colored_label(egui::Color32::from_rgb(220, 80, 80), format!("⚠ {e}"));
    }

    if copied {
        action = Some(SummaryAction::Copied);
    }

    action
}

fn is_revealed(state: &SummaryState, idx: usize) -> bool {
    state.reveal_fields.contains(&idx)
}

fn toggle_reveal(state: &mut SummaryState, idx: usize) {
    if !state.reveal_fields.insert(idx) {
        state.reveal_fields.remove(&idx);
    }
}

fn totp_remaining(fetched_at: &Option<Instant>) -> Option<u64> {
    let t = fetched_at.as_ref()?;
    let elapsed = t.elapsed().as_secs();
    if elapsed >= 30 {
        Some(0)
    } else {
        Some(30 - elapsed)
    }
}

pub enum SummaryAction {
    Back,
    Copied,
}
