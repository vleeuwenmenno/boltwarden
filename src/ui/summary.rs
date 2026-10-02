use crate::icons::{self, IconCache};
use crate::model::{BwItemDetail, ItemAction, ItemState, Passkey, TotpCode};
use crate::ui::theme::theme;
use crate::ui::widgets;
use egui::{RichText, Ui};
use std::time::{Duration, Instant};

const MASK: &str = "••••••••••••";
const LABEL_WIDTH: f32 = 128.0;
const COPIED_NOTICE: Duration = Duration::from_secs(2);

#[derive(Default)]
pub struct SummaryState {
    pub offline: bool,
    pub detail: Option<BwItemDetail>,
    pub detail_id: Option<String>,
    pub error: Option<String>,
    pub in_flight: bool,
    pub reveal_fields: std::collections::HashSet<usize>,
    revealed_at: Option<Instant>,
    pub selected_field: usize,
    pub copied_field: Option<(String, Instant)>,
    pub totp: Option<TotpCode>,
    pub totp_fetched_at: Option<Instant>,
    pub totp_in_flight: bool,
    /// Destructive action waiting for confirmation in a dialog.
    pub confirm: Option<ItemAction>,
    /// An archive/trash/restore/delete request is running.
    pub action_in_flight: bool,
    scrolled_to: Option<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldKind {
    Plain,
    Secret,
    Multiline,
    Totp,
    /// Shown for reference; a passkey has nothing to copy.
    Passkey,
}

struct Field<'a> {
    label: &'a str,
    value: std::borrow::Cow<'a, str>,
    kind: FieldKind,
}

/// The copyable fields of an item, in display order. Values borrow from the detail so
/// secrets are not copied into new strings every frame.
fn fields<'a>(detail: &'a BwItemDetail) -> Vec<Field<'a>> {
    let mut fields = Vec::new();
    let mut push =
        |label, value: std::borrow::Cow<'a, str>, kind| fields.push(Field { label, value, kind });
    if let Some(username) = &detail.username {
        push("Username", username.as_str().into(), FieldKind::Plain);
    }
    if let Some(password) = &detail.password {
        push("Password", password.as_str().into(), FieldKind::Secret);
    }
    if detail.totp.is_some() {
        push("One-time code", "".into(), FieldKind::Totp);
    }
    for passkey in &detail.passkeys {
        push(
            "Passkey",
            passkey_summary(passkey).into(),
            FieldKind::Passkey,
        );
    }
    for uri in &detail.uris {
        push("Website", uri.as_str().into(), FieldKind::Plain);
    }
    if let Some(ssh_key) = &detail.ssh_key {
        push(
            "Public key",
            ssh_key.public_key.as_str().into(),
            FieldKind::Plain,
        );
        if let Some(fingerprint) = &ssh_key.fingerprint {
            push("Fingerprint", fingerprint.as_str().into(), FieldKind::Plain);
        }
        push(
            "Private key",
            ssh_key.private_key.as_str().into(),
            FieldKind::Secret,
        );
    }
    for field in &detail.custom_fields {
        let kind = if field.hidden {
            FieldKind::Secret
        } else {
            FieldKind::Plain
        };
        push(field.name.as_str(), field.value.as_str().into(), kind);
    }
    if let Some(notes) = &detail.notes {
        push("Notes", notes.as_str().into(), FieldKind::Multiline);
    }
    fields
}

impl Drop for SummaryState {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(detail) = &mut self.detail {
            detail.zeroize();
        }
        if let Some(code) = &mut self.totp {
            code.code.zeroize();
        }
    }
}

impl SummaryState {
    pub fn needs_totp_refresh(&self) -> bool {
        if self.totp_in_flight {
            return false;
        }
        if self.detail.as_ref().and_then(|d| d.totp.as_ref()).is_none() {
            return false;
        }
        match (&self.totp, self.totp_fetched_at) {
            (Some(code), _) => !code.is_current(unix_now()),
            (None, None) => true,
            // Last fetch failed: retry every 30 seconds.
            (None, Some(t)) => t.elapsed() >= Duration::from_secs(30),
        }
    }

    /// How long until the view needs to redraw on its own (TOTP countdown, copied notice).
    pub fn repaint_after(&self) -> Option<Duration> {
        let copied = self
            .copied_field
            .as_ref()
            .and_then(|(_, at)| COPIED_NOTICE.checked_sub(at.elapsed()));
        let totp = self.totp.as_ref().map(|_| Duration::from_millis(500));
        match (copied, totp) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// Draws the item view. `embedded` is the vault window's detail pane: the item list
/// beside it owns the arrow keys and Escape, and there is no back button.
pub fn draw_summary(
    root: &mut egui::Ui,
    state: &mut SummaryState,
    show_shortcuts: bool,
    embedded: bool,
    icons: &mut IconCache,
    copy: &mut dyn FnMut(usize) -> Result<(), String>,
) -> Option<SummaryAction> {
    let ctx = &root.ctx().clone();
    let t = theme();
    let mut action = None;
    if state
        .revealed_at
        .is_some_and(|at| at.elapsed() >= Duration::from_secs(15))
    {
        state.reveal_fields.clear();
        state.revealed_at = None;
    }
    // Take the detail out of the state so rows can borrow it while the state is mutated.
    let detail = state.detail.take();
    let fields = detail.as_ref().map(fields).unwrap_or_default();

    let item_state = detail.as_ref().map(|detail| detail.state);
    let favorite = detail.as_ref().is_some_and(|detail| detail.favorite);
    // While a dialog is open or a request runs, keys belong to the dialog.
    let keys_enabled = state.confirm.is_none() && !state.action_in_flight;
    // Next to other inputs, letters are for typing unless nothing has focus.
    let letters_enabled = keys_enabled && !(embedded && ctx.memory(|m| m.focused().is_some()));

    let mut copy_selected = false;
    ctx.input(|input| {
        if !keys_enabled {
            return;
        }
        let total = fields.len().max(1);
        if let Some(item_state) = item_state
            && input.modifiers.is_none()
            && letters_enabled
            && !state.offline
        {
            if input.key_pressed(egui::Key::E) && item_state != ItemState::Deleted {
                action = Some(SummaryAction::Edit);
            }
            if input.key_pressed(egui::Key::F) && item_state != ItemState::Deleted {
                action = Some(SummaryAction::Item(if favorite {
                    ItemAction::Unfavorite
                } else {
                    ItemAction::Favorite
                }));
            }
            if input.key_pressed(egui::Key::A) {
                match item_state {
                    ItemState::Active => action = Some(SummaryAction::Item(ItemAction::Archive)),
                    ItemState::Archived => {
                        action = Some(SummaryAction::Item(ItemAction::Unarchive))
                    }
                    ItemState::Deleted => {}
                }
            }
            if input.key_pressed(egui::Key::R) && item_state == ItemState::Deleted {
                action = Some(SummaryAction::Item(ItemAction::Restore));
            }
            if input.key_pressed(egui::Key::Delete) {
                state.confirm = Some(if item_state == ItemState::Deleted {
                    ItemAction::DeleteForever
                } else {
                    ItemAction::Trash
                });
            }
        }
        if !embedded {
            if input.key_pressed(egui::Key::Escape) || input.key_pressed(egui::Key::ArrowLeft) {
                action = Some(SummaryAction::Back);
            }
            if input.key_pressed(egui::Key::ArrowDown) {
                state.selected_field = (state.selected_field + 1) % total;
            }
            if input.key_pressed(egui::Key::ArrowUp) {
                state.selected_field = (state.selected_field + total - 1) % total;
            }
        }
        if !letters_enabled {
            return;
        }
        if input.key_pressed(egui::Key::Enter) {
            copy_selected = true;
        }
        if input.key_pressed(egui::Key::Space)
            && fields
                .get(state.selected_field)
                .is_some_and(|field| field.kind == FieldKind::Secret)
        {
            toggle_reveal(state, state.selected_field);
        }
    });

    let status = if let Some(error) = &state.error {
        Some((error.clone(), t.danger))
    } else if state.action_in_flight {
        Some(("Working…".to_string(), t.text_muted))
    } else {
        state
            .copied_field
            .as_ref()
            .filter(|(_, at)| at.elapsed() < COPIED_NOTICE)
            .map(|(label, _)| (format!("Copied {label}"), t.success))
    };
    if show_shortcuts || status.is_some() {
        let hints: &[(&str, &str)] = match (show_shortcuts, item_state) {
            (false, _) => &[],
            (true, Some(ItemState::Deleted)) => &[
                ("↑↓", "Field"),
                ("⏎", "Copy"),
                ("R", "Restore"),
                ("Del", "Delete"),
                ("←", "Back"),
            ],
            (true, Some(ItemState::Archived)) => &[
                ("↑↓", "Field"),
                ("⏎", "Copy"),
                ("E", "Edit"),
                ("F", "Favorite"),
                ("A", "Unarchive"),
                ("Del", "Trash"),
                ("←", "Back"),
            ],
            (true, _) => &[
                ("↑↓", "Field"),
                ("⏎", "Copy"),
                ("E", "Edit"),
                ("F", "Favorite"),
                ("A", "Archive"),
                ("Del", "Trash"),
                ("←", "Back"),
            ],
        };
        // The window's list owns the arrows, and there is nothing to go back to.
        let hints = hints
            .iter()
            .copied()
            .filter(|(key, _)| !embedded || !matches!(*key, "↑↓" | "←"))
            .collect::<Vec<_>>();
        egui::Panel::bottom("footer")
            .frame(widgets::footer_frame())
            .show(root, |ui| {
                widgets::footer(
                    ui,
                    &hints,
                    status.as_ref().map(|(text, color)| (text.as_str(), *color)),
                )
            });
    }

    widgets::header(root, "header", |ui| {
        ui.horizontal(|ui| {
            if !embedded {
                let back = ui.add(
                    egui::Button::new(
                        RichText::new(t.icon("\u{f060}", "←"))
                            .size(t.title())
                            .color(t.text_muted),
                    )
                    .frame(false),
                );
                if back.clicked() {
                    action = Some(SummaryAction::Back);
                }
            }
            if let Some(detail) = &detail {
                let website_icon = icons::icon_host(&detail.uris).and_then(|host| icons.get(&host));
                match website_icon {
                    Some(texture) => {
                        ui.add(
                            egui::Image::new(&texture)
                                .fit_to_exact_size(egui::vec2(t.title(), t.title())),
                        );
                    }
                    None => {
                        ui.label(
                            RichText::new(t.item_icon(&detail.item_type))
                                .size(t.title())
                                .color(t.accent),
                        );
                    }
                }
                ui.add_space(6.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(&detail.name)
                            .size(t.title())
                            .color(t.text_strong),
                    )
                    .truncate(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(header_action) = draw_header_actions(
                        ui,
                        detail.state,
                        detail.favorite,
                        keys_enabled && !state.offline,
                    ) {
                        match header_action {
                            SummaryAction::Item(
                                confirm @ (ItemAction::Trash | ItemAction::DeleteForever),
                            ) => state.confirm = Some(confirm),
                            other => action = Some(other),
                        }
                    }
                    if state.action_in_flight {
                        ui.add(egui::Spinner::new().color(t.text_muted));
                    }
                    if let Some(folder) = &detail.folder {
                        ui.add_space(8.0);
                        ui.label(RichText::new(folder).color(t.text_faint));
                    }
                });
            }
        });
    });

    egui::CentralPanel::default()
        .frame(widgets::body_frame())
        .show(root, |ui| {
            if detail.is_none() {
                if state.in_flight {
                    widgets::empty_state(ui, "", "Loading item…", true);
                } else {
                    widgets::empty_state(ui, t.icon("\u{f05e}", "∅"), "No item loaded", false);
                }
                return;
            }
            if fields.is_empty() {
                widgets::empty_state(
                    ui,
                    t.icon("\u{f05e}", "∅"),
                    "This item has no copyable fields",
                    false,
                );
                return;
            }

            let scroll_to =
                (state.scrolled_to != Some(state.selected_field)).then_some(state.selected_field);
            state.scrolled_to = Some(state.selected_field);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    for (idx, field) in fields.iter().enumerate() {
                        let selected = idx == state.selected_field;
                        let (copied, rect) = draw_field(
                            ui,
                            state,
                            idx,
                            field,
                            selected,
                            selected && copy_selected,
                            copy,
                        );
                        if scroll_to == Some(idx) {
                            ui.scroll_to_rect(rect, None);
                        }
                        if copied {
                            action = Some(SummaryAction::Copied);
                        }
                    }
                });
        });

    if let Some(confirm) = state.confirm {
        let name = detail
            .as_ref()
            .map(|detail| detail.name.as_str())
            .unwrap_or("this item");
        let (title, body, label, key) = match confirm {
            ItemAction::DeleteForever => (
                "Delete permanently?",
                format!("\"{name}\" will be deleted for good. This cannot be undone."),
                "Delete forever",
                widgets::ConfirmKey::CtrlEnter,
            ),
            _ => (
                "Move to trash?",
                format!("\"{name}\" moves to Recently deleted, where you can restore it."),
                "Move to trash",
                widgets::ConfirmKey::Enter,
            ),
        };
        let dialog = widgets::ConfirmDialog {
            title,
            body: &body,
            confirm_label: label,
            danger: true,
            key,
            busy: state.action_in_flight,
            error: None,
        };
        match widgets::confirm_dialog(ctx, &dialog) {
            Some(true) if !state.offline => action = Some(SummaryAction::Item(confirm)),
            Some(true) => state.confirm = None,
            Some(false) => state.confirm = None,
            None => {}
        }
    }

    state.detail = detail;
    action
}

/// Icon buttons for the item's actions, laid out right to left.
fn draw_header_actions(
    ui: &mut Ui,
    item_state: ItemState,
    favorite: bool,
    enabled: bool,
) -> Option<SummaryAction> {
    let t = theme();
    let buttons: &[(&str, &str, &str, SummaryAction)] = match item_state {
        ItemState::Deleted => &[
            (
                "\u{f1f8}",
                "🗑",
                "Delete forever (Del)",
                SummaryAction::Item(ItemAction::DeleteForever),
            ),
            (
                "\u{f0e2}",
                "↩",
                "Restore (R)",
                SummaryAction::Item(ItemAction::Restore),
            ),
        ],
        ItemState::Archived => &[
            (
                "\u{f1f8}",
                "🗑",
                "Move to trash (Del)",
                SummaryAction::Item(ItemAction::Trash),
            ),
            (
                "\u{f0e2}",
                "↩",
                "Unarchive (A)",
                SummaryAction::Item(ItemAction::Unarchive),
            ),
            ("\u{f044}", "✎", "Edit (E)", SummaryAction::Edit),
        ],
        ItemState::Active => &[
            (
                "\u{f1f8}",
                "🗑",
                "Move to trash (Del)",
                SummaryAction::Item(ItemAction::Trash),
            ),
            (
                "\u{f187}",
                "🗄",
                "Archive (A)",
                SummaryAction::Item(ItemAction::Archive),
            ),
            ("\u{f044}", "✎", "Edit (E)", SummaryAction::Edit),
        ],
    };
    let mut clicked = None;
    let star = (item_state != ItemState::Deleted).then_some(if favorite {
        (
            "\u{f005}",
            "★",
            "Remove from favorites (F)",
            SummaryAction::Item(ItemAction::Unfavorite),
        )
    } else {
        (
            "\u{f006}",
            "☆",
            "Add to favorites (F)",
            SummaryAction::Item(ItemAction::Favorite),
        )
    });
    for (nerd, fallback, tooltip, action) in buttons.iter().chain(star.as_ref()) {
        let color = match action {
            SummaryAction::Item(ItemAction::DeleteForever) => t.danger,
            SummaryAction::Item(ItemAction::Unfavorite) => t.warning,
            _ => t.text_muted,
        };
        let response = ui
            .add_enabled(
                enabled,
                egui::Button::new(
                    RichText::new(t.icon(nerd, fallback))
                        .size(t.body())
                        .color(color),
                )
                .frame(false)
                .min_size(egui::vec2(28.0, 28.0)),
            )
            .on_hover_text(*tooltip);
        if response.clicked() {
            clicked = Some(*action);
        }
    }
    clicked
}

/// Draws one field row; returns whether its value was copied, and the row rect.
fn draw_field(
    ui: &mut Ui,
    state: &mut SummaryState,
    idx: usize,
    field: &Field<'_>,
    selected: bool,
    copy_requested: bool,
    copy: &mut dyn FnMut(usize) -> Result<(), String>,
) -> (bool, egui::Rect) {
    let t = theme();
    let revealed = state.reveal_fields.contains(&idx);
    let totp = (field.kind == FieldKind::Totp)
        .then(|| state.totp.clone())
        .flatten();
    let value: String = match field.kind {
        FieldKind::Secret if !revealed => MASK.to_string(),
        FieldKind::Totp => totp
            .as_ref()
            .map(|code| group_digits(&code.code))
            .unwrap_or_else(|| "······".into()),
        _ => field.value.to_string(),
    };
    let lines = if field.kind == FieldKind::Multiline {
        field.value.lines().count().clamp(1, 6)
    } else {
        1
    };
    let height = widgets::ROW_HEIGHT + (lines as f32 - 1.0) * (t.body() + 4.0);

    let (rect, response) = widgets::row(ui, selected, height);
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            ui.is_enabled(),
            selected,
            format!("{}: {}", field.label, value),
        )
    });
    let painter = ui.painter_at(rect);
    painter.text(
        egui::pos2(rect.left() + 14.0, rect.top() + 14.0),
        egui::Align2::LEFT_TOP,
        field.label,
        t.font(t.small()),
        if selected {
            t.selected_text
        } else {
            t.text_muted
        },
    );

    // Action glyphs on the right: reveal (secrets only) and copy.
    let copy_rect = egui::Rect::from_center_size(
        egui::pos2(rect.right() - 20.0, rect.top() + 22.0),
        egui::vec2(28.0, 28.0),
    );
    let copyable = field.kind != FieldKind::Passkey;
    let copy_clicked = copyable
        && glyph_button(
            ui,
            copy_rect,
            t.icon("\u{f0c5}", "📋"),
            ("copy", idx),
            &format!("Copy {}", field.label),
        );
    let mut value_right = copy_rect.left() - 8.0;
    if field.kind == FieldKind::Secret {
        let eye_rect = copy_rect.translate(egui::vec2(-32.0, 0.0));
        let eye = if revealed {
            t.icon("\u{f070}", "🙈")
        } else {
            t.icon("\u{f06e}", "👁")
        };
        if glyph_button(
            ui,
            eye_rect,
            eye,
            ("reveal", idx),
            &format!("{} {}", if revealed { "Hide" } else { "Show" }, field.label),
        ) {
            toggle_reveal(state, idx);
        }
        value_right = eye_rect.left() - 8.0;
    }

    let value_left = rect.left() + 14.0 + LABEL_WIDTH;
    let value_color = match field.kind {
        FieldKind::Totp => t.accent,
        _ if selected => t.text_strong,
        _ => t.text,
    };
    let value_font = match field.kind {
        FieldKind::Totp => t.mono(t.title()),
        FieldKind::Passkey => t.font(t.body()),
        _ => t.mono(t.body()),
    };
    let mut job = egui::text::LayoutJob::single_section(
        value,
        egui::TextFormat::simple(value_font, value_color),
    );
    job.wrap = egui::text::TextWrapping {
        max_width: (value_right - value_left).max(40.0),
        max_rows: lines,
        break_anywhere: field.kind != FieldKind::Multiline,
        overflow_character: Some('…'),
    };
    let galley = painter.layout_job(job);
    let value_top = if lines == 1 {
        rect.center().y - galley.size().y / 2.0
    } else {
        rect.top() + 12.0
    };
    let value_width = galley.size().x;
    painter.galley(egui::pos2(value_left, value_top), galley, value_color);

    if let Some(code) = &totp {
        let now = unix_now();
        // Show 0s while the refresh for the next step is still in flight.
        let remaining = if code.is_current(now) {
            code.seconds_remaining(now)
        } else {
            0
        };
        let label_x = value_left + value_width + 14.0;
        painter.text(
            egui::pos2(label_x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            format!("{remaining}s"),
            t.font(t.small()),
            if remaining <= 5 {
                t.warning
            } else {
                t.text_muted
            },
        );
        let track = egui::Rect::from_min_max(
            egui::pos2(value_left, rect.bottom() - 6.0),
            egui::pos2(value_right, rect.bottom() - 4.0),
        );
        painter.rect_filled(track, 0.0, t.separator);
        let fraction = remaining as f32 / code.period as f32;
        painter.rect_filled(
            egui::Rect::from_min_max(
                track.min,
                egui::pos2(track.left() + track.width() * fraction, track.bottom()),
            ),
            0.0,
            if remaining <= 5 { t.warning } else { t.accent },
        );
    }

    if response.clicked() {
        state.selected_field = idx;
    }
    if copy_clicked || (copy_requested && copyable) {
        match copy(idx) {
            Ok(()) => {
                state.copied_field = Some((field.label.to_string(), Instant::now()));
                return (true, rect);
            }
            Err(error) => state.error = Some(error),
        }
    }
    (false, rect)
}

fn glyph_button(
    ui: &mut Ui,
    rect: egui::Rect,
    glyph: &str,
    id: (&str, usize),
    label: &str,
) -> bool {
    let t = theme();
    let response = ui.interact(rect, ui.id().with(id), egui::Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, ui.is_enabled(), label)
    });
    let color = if response.hovered() {
        t.accent
    } else {
        t.text_muted
    };
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        glyph,
        t.font(t.body()),
        color,
    );
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

/// "menno on GitHub · saved 17 May 2026".
fn passkey_summary(passkey: &Passkey) -> String {
    match passkey
        .creation_date
        .as_deref()
        .and_then(widgets::format_date)
    {
        Some(date) => format!("{} · saved {date}", passkey.describe()),
        None => passkey.describe(),
    }
}

/// "123456" -> "123 456", the way authenticator apps show codes.
fn group_digits(code: &str) -> String {
    let split = code.len().div_ceil(2);
    if code.len() >= 6 && code.is_char_boundary(split) {
        format!("{} {}", &code[..split], &code[split..])
    } else {
        code.to_string()
    }
}

fn toggle_reveal(state: &mut SummaryState, idx: usize) {
    state.revealed_at = Some(Instant::now());
    if !state.reveal_fields.insert(idx) {
        state.reveal_fields.remove(&idx);
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Copy)]
pub enum SummaryAction {
    Back,
    Copied,
    Edit,
    /// Archive, restore and friends; trash and delete arrive here only once confirmed.
    Item(ItemAction),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_totp_digits() {
        assert_eq!(group_digits("123456"), "123 456");
        assert_eq!(group_digits("12345678"), "1234 5678");
        assert_eq!(group_digits("1234"), "1234");
    }
}
