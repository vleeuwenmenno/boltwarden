//! Shared building blocks so every screen uses the same header, rows, inputs and
//! footer, all colored from [`theme()`].

use crate::ui::theme::theme;
use egui::{Color32, Response, RichText, Ui};

/// Every screen uses the same fixed window size, so the popup never resizes (no
/// flicker, and Hyprland can keep it centered).
pub const WINDOW_SIZE: egui::Vec2 = egui::vec2(680.0, 460.0);
pub const ROW_HEIGHT: f32 = 44.0;

pub fn header_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(theme().bg)
        .inner_margin(egui::Margin::symmetric(16, 12))
}

/// Header background acts as a native window drag area. Child widgets keep their
/// own input, so dragging search text or clicking header buttons still works.
pub fn header<R>(
    root: &mut Ui,
    id: &'static str,
    add_contents: impl FnOnce(&mut Ui) -> R,
) -> egui::InnerResponse<R> {
    egui::Panel::top(id)
        .frame(egui::Frame::NONE)
        .show(root, |ui| {
            let contents =
                ui.scope_builder(egui::UiBuilder::new().sense(egui::Sense::drag()), |ui| {
                    header_frame()
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            add_contents(ui)
                        })
                        .inner
                });
            if contents
                .response
                .drag_started_by(egui::PointerButton::Primary)
            {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }
            contents
                .response
                .on_hover_cursor(egui::CursorIcon::Grab)
                .on_hover_text("Drag to move");
            contents.inner
        })
}

pub fn body_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(theme().bg)
        .inner_margin(egui::Margin::symmetric(8, 8))
}

pub fn footer_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(theme().bg)
        .inner_margin(egui::Margin::symmetric(12, 6))
}

/// A selectable list row. Paints hover/selection chrome and returns the rect to draw into.
pub fn row(ui: &mut Ui, selected: bool, height: f32) -> (egui::Rect, Response) {
    let t = theme();
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::click(),
    );
    let radius = t.rounding as f32;
    if selected {
        ui.painter().rect_filled(rect, radius, t.selected_bg);
        ui.painter().rect_stroke(
            rect,
            radius,
            egui::Stroke::new(1.0_f32, t.selected_border),
            egui::StrokeKind::Inside,
        );
    } else if response.hovered() {
        ui.painter().rect_filled(rect, radius, t.hover);
    }
    (rect, response)
}

/// Draws icon + title + secondary text into a row rect, Omarchy-menu style. `image`
/// (a website icon) replaces the glyph `icon` when it is available.
#[allow(clippy::too_many_arguments)]
pub fn paint_row_content(
    ui: &Ui,
    rect: egui::Rect,
    icon: &str,
    image: Option<&egui::TextureHandle>,
    title: &str,
    secondary: Option<&str>,
    trailing: Option<&str>,
    selected: bool,
) {
    paint_row_content_with_badge(
        ui, rect, icon, image, title, secondary, None, trailing, selected,
    );
}

/// A small rounded status label for list rows.
pub struct RowBadge<'a> {
    pub text: &'a str,
    pub color: Color32,
}

/// Like [`paint_row_content`], with a status badge between the text and `trailing`.
#[allow(clippy::too_many_arguments)]
pub fn paint_row_content_with_badge(
    ui: &Ui,
    rect: egui::Rect,
    icon: &str,
    image: Option<&egui::TextureHandle>,
    title: &str,
    secondary: Option<&str>,
    badge: Option<RowBadge<'_>>,
    trailing: Option<&str>,
    selected: bool,
) {
    let t = theme();
    let painter = ui.painter_at(rect);
    let title_color = if selected {
        t.selected_text
    } else {
        t.text_strong
    };
    let icon_center = egui::pos2(rect.left() + 20.0, rect.center().y);
    match image {
        Some(texture) => {
            painter.image(
                texture.id(),
                egui::Rect::from_center_size(icon_center, egui::vec2(20.0, 20.0)),
                egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                Color32::WHITE,
            );
        }
        None => {
            painter.text(
                icon_center,
                egui::Align2::CENTER_CENTER,
                icon,
                t.font(t.body()),
                if selected {
                    t.selected_text
                } else {
                    t.text_muted
                },
            );
        }
    }

    let text_left = rect.left() + 42.0;
    let trailing_width = trailing
        .map(|text| {
            let galley = painter.layout_no_wrap(text.to_owned(), t.font(t.small()), t.text_faint);
            let width = galley.size().x;
            painter.galley(
                egui::pos2(
                    rect.right() - 12.0 - width,
                    rect.center().y - galley.size().y / 2.0,
                ),
                galley,
                t.text_faint,
            );
            width + 24.0
        })
        .unwrap_or(12.0);
    let trailing_width = trailing_width
        + badge
            .map(|badge| {
                let galley =
                    painter.layout_no_wrap(badge.text.to_owned(), t.font(t.small()), badge.color);
                let size = galley.size() + egui::vec2(16.0, 4.0);
                let pill = egui::Rect::from_min_size(
                    egui::pos2(
                        rect.right() - trailing_width - size.x,
                        rect.center().y - size.y / 2.0,
                    ),
                    size,
                );
                painter.rect_filled(pill, size.y / 2.0, badge.color.gamma_multiply(0.14));
                painter.galley(pill.center() - galley.size() / 2.0, galley, badge.color);
                size.x + 12.0
            })
            .unwrap_or(0.0);

    let max_width = (rect.right() - trailing_width - text_left).max(40.0);
    let mut job = egui::text::LayoutJob {
        wrap: egui::text::TextWrapping::truncate_at_width(max_width),
        ..Default::default()
    };
    job.append(
        title,
        0.0,
        egui::TextFormat::simple(t.font(t.body()), title_color),
    );
    if let Some(secondary) = secondary.filter(|s| !s.is_empty()) {
        job.append(
            secondary,
            12.0,
            egui::TextFormat::simple(t.font(t.small()), t.text_muted),
        );
    }
    let galley = painter.layout_job(job);
    painter.galley(
        egui::pos2(text_left, rect.center().y - galley.size().y / 2.0),
        galley,
        title_color,
    );
}

/// A bordered single-line input. The border turns accent while focused; the hint is
/// drawn in the faint color so it can never be mistaken for a value.
pub fn text_input(
    ui: &mut Ui,
    id: egui::Id,
    value: &mut String,
    hint: &str,
    password: bool,
    size: f32,
) -> Response {
    let t = theme();
    let focused = ui.memory(|m| m.has_focus(id));
    egui::Frame::new()
        .fill(t.surface)
        .stroke(egui::Stroke::new(
            1.0_f32,
            if focused { t.accent } else { t.border },
        ))
        .corner_radius(t.rounding)
        .inner_margin(egui::Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::singleline(value)
                    .id(id)
                    .font(t.font(size))
                    .text_color(t.text_strong)
                    .hint_text(RichText::new(hint).color(t.text_faint))
                    .password(password)
                    .frame(egui::Frame::NONE)
                    .margin(egui::Margin::ZERO)
                    .desired_width(f32::INFINITY),
            )
        })
        .inner
}

/// A bordered multi-line input, styled like [`text_input`].
pub fn text_area(
    ui: &mut Ui,
    id: egui::Id,
    value: &mut String,
    hint: &str,
    rows: usize,
) -> Response {
    let t = theme();
    let focused = ui.memory(|m| m.has_focus(id));
    egui::Frame::new()
        .fill(t.surface)
        .stroke(egui::Stroke::new(
            1.0_f32,
            if focused { t.accent } else { t.border },
        ))
        .corner_radius(t.rounding)
        .inner_margin(egui::Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(value)
                    .id(id)
                    .font(t.font(t.body()))
                    .text_color(t.text_strong)
                    .hint_text(RichText::new(hint).color(t.text_faint))
                    .frame(egui::Frame::NONE)
                    .margin(egui::Margin::ZERO)
                    .desired_rows(rows)
                    .desired_width(f32::INFINITY),
            )
        })
        .inner
}

pub fn field_label(ui: &mut Ui, text: &str) {
    let t = theme();
    ui.label(RichText::new(text).size(t.small()).color(t.text_muted));
}

pub fn button(ui: &mut Ui, text: &str, primary: bool, enabled: bool) -> Response {
    sized_button(ui, text, primary, enabled, 96.0)
}

pub fn icon_button(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    sized_button(ui, text, false, enabled, 32.0)
}

fn sized_button(ui: &mut Ui, text: &str, primary: bool, enabled: bool, width: f32) -> Response {
    let t = theme();
    let (fill, stroke, color) = if primary {
        (t.selected_bg, t.accent, t.selected_text)
    } else {
        (t.surface, t.border, t.text)
    };
    ui.scope(|ui| {
        let widgets = &mut ui.visuals_mut().widgets;
        widgets.inactive.weak_bg_fill = fill;
        widgets.inactive.bg_fill = fill;
        widgets.inactive.bg_stroke = egui::Stroke::new(1.0, stroke);
        widgets.hovered.weak_bg_fill = t.hover;
        widgets.hovered.bg_fill = t.hover;
        widgets.hovered.bg_stroke = egui::Stroke::new(1.0, t.accent);
        widgets.active.weak_bg_fill = t.selected_bg;
        widgets.active.bg_fill = t.selected_bg;
        widgets.active.bg_stroke = egui::Stroke::new(1.5, t.accent);
        ui.add_enabled(
            enabled,
            egui::Button::new(RichText::new(text).color(color))
                .corner_radius(t.rounding)
                .min_size(egui::vec2(width, 32.0)),
        )
    })
    .inner
}

/// Secondary button in the danger color, for destructive confirmations.
pub fn danger_button(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    let t = theme();
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(text).color(t.danger))
            .fill(t.surface)
            .stroke(egui::Stroke::new(1.0_f32, t.danger))
            .corner_radius(t.rounding)
            .min_size(egui::vec2(96.0, 32.0)),
    )
}

/// Which key, besides clicking the button, confirms a [`confirm_dialog`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConfirmKey {
    None,
    Enter,
    /// For actions that cannot be undone, so a stray Enter does not trigger them.
    CtrlEnter,
}

pub struct ConfirmDialog<'a> {
    pub title: &'a str,
    pub body: &'a str,
    pub confirm_label: &'a str,
    pub danger: bool,
    pub key: ConfirmKey,
    pub busy: bool,
    pub error: Option<&'a str>,
}

/// A centered modal with Cancel and a confirm button. Returns `Some(true)` when the
/// action is confirmed and `Some(false)` when it is cancelled (button or Escape).
pub fn confirm_dialog(ctx: &egui::Context, dialog: &ConfirmDialog<'_>) -> Option<bool> {
    let t = theme();
    let mut result = None;
    if !dialog.busy {
        ctx.input_mut(|input| {
            if input.consume_key(egui::Modifiers::NONE, egui::Key::Escape) {
                result = Some(false);
            }
            let confirmed = match dialog.key {
                ConfirmKey::None => false,
                ConfirmKey::Enter => input.consume_key(egui::Modifiers::NONE, egui::Key::Enter),
                ConfirmKey::CtrlEnter => {
                    input.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter)
                }
            };
            if confirmed {
                result = Some(true);
            }
        });
    }
    egui::Window::new(dialog.title)
        .collapsible(false)
        .resizable(false)
        .title_bar(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .frame(
            egui::Frame::window(&ctx.global_style())
                .fill(t.bg)
                .stroke(egui::Stroke::new(
                    1.0_f32,
                    if dialog.danger { t.danger } else { t.accent },
                ))
                .inner_margin(egui::Margin::same(16)),
        )
        .show(ctx, |ui| {
            ui.set_width(360.0);
            ui.label(
                RichText::new(dialog.title)
                    .size(t.title())
                    .color(t.text_strong),
            );
            ui.add_space(6.0);
            ui.label(RichText::new(dialog.body).color(t.text_muted));
            if let Some(error) = dialog.error {
                ui.add_space(6.0);
                error_line(ui, error);
            }
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if button(ui, "Cancel", false, !dialog.busy).clicked() {
                    result = Some(false);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let confirm = if dialog.danger {
                        danger_button(ui, dialog.confirm_label, !dialog.busy)
                    } else {
                        button(ui, dialog.confirm_label, true, !dialog.busy)
                    };
                    if confirm.clicked() {
                        result = Some(true);
                    }
                    if dialog.busy {
                        ui.add(egui::Spinner::new().color(t.text_muted));
                    } else if dialog.key == ConfirmKey::CtrlEnter {
                        ui.label(RichText::new("Ctrl+⏎").size(t.small()).color(t.text_faint));
                    }
                });
            });
        });
    result
}

/// The app's mark in the accent color, `size` points square.
pub fn logo(ui: &mut Ui, size: f32) -> Response {
    let texture = crate::logo::texture(ui.ctx(), theme().accent);
    ui.add(egui::Image::new(&texture).fit_to_exact_size(egui::vec2(size, size)))
}

/// "2026-05-17T08:12:00.000Z" -> "17 May 2026". `None` for anything else.
pub fn format_date(iso: &str) -> Option<String> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let year = iso.get(0..4)?.parse::<u32>().ok()?;
    let month = iso.get(5..7)?.parse::<usize>().ok()?;
    let day = iso.get(8..10)?.parse::<u32>().ok()?;
    let name = MONTHS.get(month.checked_sub(1)?)?;
    Some(format!("{day} {name} {year}"))
}

pub fn error_line(ui: &mut Ui, text: &str) {
    let t = theme();
    ui.label(RichText::new(format!("{} {text}", t.icon("\u{f071}", "⚠"))).color(t.danger));
}

/// A settings row that picks one of several values; Space, Enter or a click moves to
/// the next value, shown on the right.
pub fn choice_row(
    ui: &mut Ui,
    selected: bool,
    title: &str,
    description: &str,
    value: &str,
) -> Response {
    let t = theme();
    let (rect, response) = row(ui, selected, ROW_HEIGHT + 4.0);
    response.widget_info(|| {
        egui::WidgetInfo::labeled(
            egui::WidgetType::Button,
            ui.is_enabled(),
            format!("{title}: {value}. {description}"),
        )
    });
    let painter = ui.painter_at(rect);
    painter.text(
        egui::pos2(rect.left() + 28.0, rect.center().y),
        egui::Align2::CENTER_CENTER,
        t.icon("\u{f0ca}", "☰"),
        t.font(t.body()),
        t.accent,
    );
    let left = rect.left() + 54.0;
    painter.text(
        egui::pos2(left, rect.top() + 7.0),
        egui::Align2::LEFT_TOP,
        title,
        t.font(t.body()),
        if selected {
            t.selected_text
        } else {
            t.text_strong
        },
    );
    painter.text(
        egui::pos2(left, rect.bottom() - 7.0),
        egui::Align2::LEFT_BOTTOM,
        description,
        t.font(t.small()),
        t.text_muted,
    );
    painter.text(
        egui::pos2(rect.right() - 14.0, rect.center().y),
        egui::Align2::RIGHT_CENTER,
        format!("{value}  {}", t.icon("\u{f105}", "›")),
        t.font(t.body()),
        t.accent,
    );
    response
}

/// A settings-style row with an on/off indicator, title and one-line description.
pub fn toggle_row(
    ui: &mut Ui,
    selected: bool,
    on: bool,
    title: &str,
    description: &str,
) -> Response {
    let t = theme();
    let (rect, response) = row(ui, selected, ROW_HEIGHT + 4.0);
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::Checkbox,
            ui.is_enabled(),
            on,
            format!("{title}. {description}"),
        )
    });
    let painter = ui.painter_at(rect);

    let track = egui::Rect::from_center_size(
        egui::pos2(rect.left() + 28.0, rect.center().y),
        egui::vec2(28.0, 14.0),
    );
    let radius = if t.rounding == 0 { 0.0 } else { 7.0 };
    painter.rect_filled(track, radius, if on { t.accent } else { t.surface });
    painter.rect_stroke(
        track,
        radius,
        egui::Stroke::new(1.0_f32, if on { t.accent } else { t.border }),
        egui::StrokeKind::Inside,
    );
    let knob_x = if on {
        track.right() - 7.0
    } else {
        track.left() + 7.0
    };
    let knob =
        egui::Rect::from_center_size(egui::pos2(knob_x, track.center().y), egui::vec2(10.0, 10.0));
    painter.rect_filled(
        knob,
        if t.rounding == 0 { 0.0 } else { 5.0 },
        if on { t.bg } else { t.text_muted },
    );

    let left = rect.left() + 54.0;
    painter.text(
        egui::pos2(left, rect.top() + 7.0),
        egui::Align2::LEFT_TOP,
        title,
        t.font(t.body()),
        if selected {
            t.selected_text
        } else {
            t.text_strong
        },
    );
    painter.text(
        egui::pos2(left, rect.bottom() - 7.0),
        egui::Align2::LEFT_BOTTOM,
        description,
        t.font(t.small()),
        t.text_muted,
    );
    response
}

pub fn empty_state(ui: &mut Ui, icon: &str, text: &str, spinner: bool) {
    let t = theme();
    ui.add_space((ui.available_height() / 2.0 - 30.0).max(8.0));
    ui.vertical_centered(|ui| {
        if spinner {
            ui.add(egui::Spinner::new().color(t.text_muted));
        } else {
            ui.label(
                RichText::new(icon)
                    .size(t.title() + 6.0)
                    .color(t.text_faint),
            );
        }
        ui.add_space(6.0);
        ui.label(RichText::new(text).color(t.text_muted));
    });
}

/// Footer with keyboard hints on the left and an optional status message on the right.
pub fn footer(
    ui: &mut Ui,
    hints: &[(&str, &str)],
    status: Option<(&str, Color32)>,
) -> Option<egui::Rect> {
    let t = theme();
    let height = 24.0;
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let painter = ui.painter_at(rect);

    let mut status_left = rect.right();
    let mut status_rect = None;
    if let Some((text, color)) = status {
        let galley = painter.layout_no_wrap(text.to_owned(), t.font(t.small()), color);
        status_left = rect.right() - galley.size().x;
        status_rect = Some(egui::Rect::from_min_max(
            egui::pos2(status_left, rect.top()),
            rect.right_bottom(),
        ));
        painter.galley(
            egui::pos2(status_left, rect.center().y - galley.size().y / 2.0),
            galley,
            color,
        );
    }

    let mut cursor = rect.left();
    for (key, label) in hints {
        let key_size = keycap_size(key);
        let label_galley =
            painter.layout_no_wrap((*label).to_owned(), t.font(t.small()), t.text_muted);
        let hint_width = key_size.x + 6.0 + label_galley.size().x;
        if cursor + hint_width > status_left - 12.0 {
            break;
        }
        let key_rect = egui::Rect::from_min_size(
            egui::pos2(cursor, rect.center().y - key_size.y / 2.0),
            key_size,
        );
        paint_keycap(&painter, key_rect, key);
        cursor += key_size.x + 6.0;
        painter.galley(
            egui::pos2(cursor, rect.center().y - label_galley.size().y / 2.0),
            label_galley.clone(),
            t.text_muted,
        );
        cursor += label_galley.size().x + 16.0;
    }
    status_rect
}

/// Draws `keys` as keycaps, right-aligned so the last one ends at `right_center`.
pub fn keycaps(painter: &egui::Painter, right_center: egui::Pos2, keys: &[&str]) {
    let mut right = right_center.x;
    for key in keys.iter().rev() {
        let size = keycap_size(key);
        let rect = egui::Rect::from_min_size(
            egui::pos2(right - size.x, right_center.y - size.y / 2.0),
            size,
        );
        paint_keycap(painter, rect, key);
        right = rect.left() - 4.0;
    }
}

fn keycap_size(key: &str) -> egui::Vec2 {
    match key {
        "↑↓" => egui::vec2(30.0, 20.0),
        "←↑↓→" => egui::vec2(46.0, 20.0),
        "⏎" => egui::vec2(26.0, 20.0),
        "←" | "→" => egui::vec2(22.0, 20.0),
        _ => egui::vec2(key.chars().count() as f32 * 7.0 + 12.0, 20.0),
    }
}

fn paint_keycap(painter: &egui::Painter, rect: egui::Rect, key: &str) {
    let t = theme();
    painter.rect_stroke(
        rect,
        t.rounding.min(4) as f32,
        egui::Stroke::new(1.0_f32, t.border),
        egui::StrokeKind::Inside,
    );
    let color = t.text;
    match key {
        "↑↓" => {
            arrow(
                painter,
                rect.center() + egui::vec2(-4.0, 0.0),
                egui::vec2(0.0, -4.5),
                color,
            );
            arrow(
                painter,
                rect.center() + egui::vec2(4.0, 0.0),
                egui::vec2(0.0, 4.5),
                color,
            );
        }
        "←↑↓→" => {
            for (offset, direction) in [
                (-14.0, egui::vec2(-4.5, 0.0)),
                (-4.0, egui::vec2(0.0, -4.5)),
                (4.0, egui::vec2(0.0, 4.5)),
                (14.0, egui::vec2(4.5, 0.0)),
            ] {
                arrow(
                    painter,
                    rect.center() + egui::vec2(offset, 0.0),
                    direction,
                    color,
                );
            }
        }
        "⏎" => enter_glyph(painter, rect, color),
        "←" => arrow(painter, rect.center(), egui::vec2(-5.0, 0.0), color),
        "→" => arrow(painter, rect.center(), egui::vec2(5.0, 0.0), color),
        _ => {
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                key,
                t.font(t.small() - 1.0),
                color,
            );
        }
    }
}

fn enter_glyph(painter: &egui::Painter, rect: egui::Rect, color: Color32) {
    let stroke = egui::Stroke::new(1.4_f32, color);
    let left = rect.left() + 7.0;
    let right = rect.right() - 7.0;
    let top = rect.top() + 6.0;
    let mid_y = rect.center().y + 2.5;
    painter.line_segment([egui::pos2(right, top), egui::pos2(right, mid_y)], stroke);
    painter.line_segment([egui::pos2(right, mid_y), egui::pos2(left, mid_y)], stroke);
    painter.line_segment(
        [egui::pos2(left, mid_y), egui::pos2(left + 3.5, mid_y - 3.0)],
        stroke,
    );
    painter.line_segment(
        [egui::pos2(left, mid_y), egui::pos2(left + 3.5, mid_y + 3.0)],
        stroke,
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn formats_server_dates() {
        assert_eq!(
            super::format_date("2026-05-17T08:12:00.000Z").as_deref(),
            Some("17 May 2026")
        );
        assert_eq!(super::format_date("2026-13-01"), None);
        assert_eq!(super::format_date("soon"), None);
    }
}

fn arrow(painter: &egui::Painter, center: egui::Pos2, delta: egui::Vec2, color: Color32) {
    let stroke = egui::Stroke::new(1.4_f32, color);
    let start = center - delta * 0.55;
    let end = center + delta * 0.55;
    painter.line_segment([start, end], stroke);
    let direction = delta.normalized();
    let perp = egui::vec2(-direction.y, direction.x);
    let back = end - direction * 3.5;
    painter.line_segment([end, back + perp * 3.0], stroke);
    painter.line_segment([end, back - perp * 3.0], stroke);
}
