//! Edit form for an item: name, login credentials, websites, custom fields and notes.

use crate::model::{DraftField, DraftFieldKind, DraftUri, ItemDraft, LoginDraft};
use crate::ui::theme::theme;
use crate::ui::widgets;
use egui::{Context, RichText, Ui};
use std::collections::HashSet;

const LABEL_WIDTH: f32 = 128.0;
const FIELD_NAME_WIDTH: f32 = 150.0;
const INPUT_HEIGHT: f32 = 34.0;

pub struct EditState {
    /// Item being edited; empty while creating a new one.
    pub id: String,
    pub creating: bool,
    /// Login data put aside while a new item is switched to a secure note.
    stashed_login: Option<LoginDraft>,
    /// `None` while the draft is loading.
    pub draft: Option<ItemDraft>,
    original: Option<ItemDraft>,
    pub error: Option<String>,
    pub saving: bool,
    confirm_discard: bool,
    reveal_password: bool,
    reveal_fields: HashSet<usize>,
    /// Input to focus on the next frame, such as the name of a field just added.
    focus: Option<egui::Id>,
}

pub enum EditAction {
    Cancel,
    Save(ItemDraft),
}

impl EditState {
    pub fn loading(id: String) -> Self {
        Self {
            id,
            creating: false,
            stashed_login: None,
            draft: None,
            original: None,
            error: None,
            saving: false,
            confirm_discard: false,
            reveal_password: false,
            reveal_fields: HashSet::new(),
            focus: Some(name_id()),
        }
    }

    /// Form for a new item. It starts as a login; the type can change until it is saved.
    pub fn create() -> Self {
        let mut state = Self::loading(String::new());
        state.creating = true;
        state.set_draft(ItemDraft {
            login: Some(LoginDraft::default()),
            ..ItemDraft::default()
        });
        state
    }

    pub fn set_draft(&mut self, draft: ItemDraft) {
        self.original = Some(draft.clone());
        self.draft = Some(draft);
    }

    pub fn is_dirty(&self) -> bool {
        self.draft != self.original
    }
}

fn name_id() -> egui::Id {
    egui::Id::new(("edit", "name"))
}

fn field_name_id(idx: usize) -> egui::Id {
    egui::Id::new(("edit-field-name", idx))
}

fn uri_id(idx: usize) -> egui::Id {
    egui::Id::new(("edit-uri", idx))
}

pub fn draw_edit(ctx: &Context, state: &mut EditState, show_shortcuts: bool) -> Option<EditAction> {
    let t = theme();
    let mut action = None;
    let dialog_open = state.confirm_discard;

    if !dialog_open && !state.saving {
        let popup_open = ctx.memory(|m| m.any_popup_open());
        ctx.input_mut(|input| {
            if input.consume_key(egui::Modifiers::COMMAND, egui::Key::S) {
                action = save_action(state);
            }
            if !popup_open && input.consume_key(egui::Modifiers::NONE, egui::Key::Escape) {
                action = cancel_action(state);
            }
        });
    }

    let status = state.error.as_deref().map(|error| (error, t.danger));
    if show_shortcuts || status.is_some() {
        let hints: &[(&str, &str)] = if show_shortcuts {
            &[("Tab", "Next field"), ("Ctrl+S", "Save"), ("Esc", "Cancel")]
        } else {
            &[]
        };
        egui::TopBottomPanel::bottom("footer")
            .frame(widgets::footer_frame())
            .show(ctx, |ui| widgets::footer(ui, hints, status));
    }

    egui::TopBottomPanel::top("header")
        .frame(widgets::header_frame())
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                let back = ui.add_enabled(
                    !state.saving,
                    egui::Button::new(
                        RichText::new(t.icon("\u{f060}", "←"))
                            .size(t.title())
                            .color(t.text_muted),
                    )
                    .frame(false),
                );
                if back.clicked() {
                    action = cancel_action(state);
                }
                ui.label(
                    RichText::new(t.icon("\u{f044}", "✎"))
                        .size(t.title())
                        .color(t.accent),
                );
                ui.add_space(6.0);
                let title = if state.creating { "New item" } else { "Edit item" };
                ui.label(RichText::new(title).size(t.title()).color(t.text_strong));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let can_save = state.draft.is_some() && !state.saving;
                    if widgets::button(ui, "Save", true, can_save).clicked() {
                        action = save_action(state);
                    }
                    if widgets::button(ui, "Cancel", false, !state.saving).clicked() {
                        action = cancel_action(state);
                    }
                    if state.saving {
                        ui.add(egui::Spinner::new().color(t.text_muted));
                    }
                });
            });
        });

    egui::CentralPanel::default()
        .frame(widgets::body_frame())
        .show(ctx, |ui| {
            if state.draft.is_none() {
                widgets::empty_state(ui, "", "Loading item…", true);
                return;
            }
            let enabled = !state.saving && !dialog_open;
            ui.add_enabled_ui(enabled, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| draw_form(ui, state));
            });
        });

    if dialog_open {
        let dialog = widgets::ConfirmDialog {
            title: "Discard changes?",
            body: "Your edits to this item will be lost.",
            confirm_label: "Discard",
            danger: true,
            key: widgets::ConfirmKey::Enter,
            busy: false,
            error: None,
        };
        match widgets::confirm_dialog(ctx, &dialog) {
            Some(true) => action = Some(EditAction::Cancel),
            Some(false) => state.confirm_discard = false,
            None => {}
        }
    }

    action
}

fn save_action(state: &mut EditState) -> Option<EditAction> {
    let draft = state.draft.as_ref()?;
    if let Err(message) = validate(draft) {
        state.error = Some(message.into());
        return None;
    }
    state.error = None;
    Some(EditAction::Save(draft.clone()))
}

fn cancel_action(state: &mut EditState) -> Option<EditAction> {
    if state.is_dirty() {
        state.confirm_discard = true;
        None
    } else {
        Some(EditAction::Cancel)
    }
}

pub fn validate(draft: &ItemDraft) -> Result<(), &'static str> {
    if draft.name.trim().is_empty() {
        return Err("Name is required");
    }
    if draft
        .fields
        .iter()
        .any(|field| field.name.trim().is_empty() && !field.value.is_empty())
    {
        return Err("Custom fields with a value need a name");
    }
    Ok(())
}

fn draw_form(ui: &mut Ui, state: &mut EditState) {
    let t = theme();
    let focus = state.focus.take();
    let Some(draft) = state.draft.as_mut() else {
        return;
    };
    let focus_if = |response: &egui::Response, id: egui::Id| {
        if focus == Some(id) {
            response.request_focus();
        }
    };
    ui.spacing_mut().item_spacing.y = 6.0;
    ui.add_space(4.0);

    if state.creating {
        labeled_row(ui, "Type", |ui| {
            let is_login = draft.login.is_some();
            if ui.selectable_label(is_login, "Login").clicked() && !is_login {
                draft.login = Some(state.stashed_login.take().unwrap_or_default());
            }
            if ui.selectable_label(!is_login, "Secure note").clicked() && is_login {
                state.stashed_login = draft.login.take();
            }
        });
    }

    labeled_row(ui, "Name", |ui| {
        let response = widgets::text_input(ui, name_id(), &mut draft.name, "Item name", false, t.body());
        focus_if(&response, name_id());
    });

    if let Some(login) = draft.login.as_mut() {
        labeled_row(ui, "Username", |ui| {
            widgets::text_input(
                ui,
                egui::Id::new(("edit", "username")),
                &mut login.username,
                "",
                false,
                t.body(),
            );
        });
        labeled_row(ui, "Password", |ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if reveal_button(ui, state.reveal_password).clicked() {
                    state.reveal_password = !state.reveal_password;
                }
                widgets::text_input(
                    ui,
                    egui::Id::new(("edit", "password")),
                    &mut login.password,
                    "",
                    !state.reveal_password,
                    t.body(),
                );
            });
        });
        labeled_row(ui, "TOTP secret", |ui| {
            widgets::text_input(
                ui,
                egui::Id::new(("edit", "totp")),
                &mut login.totp,
                "otpauth://… or base32 key",
                false,
                t.body(),
            );
        });

        let mut remove = None;
        for (idx, uri) in login.uris.iter_mut().enumerate() {
            let label = if idx == 0 { "Websites" } else { "" };
            labeled_row(ui, label, |ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if remove_button(ui).clicked() {
                        remove = Some(idx);
                    }
                    let response =
                        widgets::text_input(ui, uri_id(idx), &mut uri.uri, "https://", false, t.body());
                    focus_if(&response, uri_id(idx));
                });
            });
        }
        if let Some(idx) = remove {
            login.uris.remove(idx);
        }
        labeled_row(ui, if login.uris.is_empty() { "Websites" } else { "" }, |ui| {
            if add_button(ui, "Add website").clicked() {
                login.uris.push(DraftUri::default());
                state.focus = Some(uri_id(login.uris.len() - 1));
            }
        });
    }

    ui.add_space(8.0);
    ui.label(RichText::new("Custom fields").size(t.small()).color(t.text_muted));
    let mut remove = None;
    for (idx, field) in draft.fields.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            ui.allocate_ui(egui::vec2(FIELD_NAME_WIDTH, INPUT_HEIGHT), |ui| {
                let response =
                    widgets::text_input(ui, field_name_id(idx), &mut field.name, "Field name", false, t.body());
                focus_if(&response, field_name_id(idx));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if remove_button(ui).clicked() {
                    remove = Some(idx);
                }
                if field.kind != DraftFieldKind::Linked {
                    kind_selector(ui, idx, field);
                }
                draw_field_value(ui, idx, field, &mut state.reveal_fields);
            });
        });
    }
    if let Some(idx) = remove {
        draft.fields.remove(idx);
        state.reveal_fields.clear();
    }
    if add_button(ui, "Add field").clicked() {
        draft.fields.push(DraftField {
            name: String::new(),
            value: String::new(),
            kind: DraftFieldKind::Text,
            original_index: None,
        });
        state.focus = Some(field_name_id(draft.fields.len() - 1));
    }

    ui.add_space(8.0);
    ui.label(RichText::new("Notes").size(t.small()).color(t.text_muted));
    widgets::text_area(ui, egui::Id::new(("edit", "notes")), &mut draft.notes, "", 4);
    ui.add_space(8.0);
}

fn draw_field_value(ui: &mut Ui, idx: usize, field: &mut DraftField, revealed: &mut HashSet<usize>) {
    let t = theme();
    let id = egui::Id::new(("edit-field-value", idx));
    match field.kind {
        DraftFieldKind::Linked => {
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.label(RichText::new("Linked to another field").color(t.text_faint));
            });
        }
        DraftFieldKind::Boolean => {
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                let mut on = field.value == "true";
                if ui.checkbox(&mut on, "").changed() {
                    field.value = on.to_string();
                }
            });
        }
        DraftFieldKind::Hidden => {
            let shown = revealed.contains(&idx);
            if reveal_button(ui, shown).clicked() && !revealed.insert(idx) {
                revealed.remove(&idx);
            }
            widgets::text_input(ui, id, &mut field.value, "Value", !shown, t.body());
        }
        DraftFieldKind::Text => {
            widgets::text_input(ui, id, &mut field.value, "Value", false, t.body());
        }
    }
}

fn kind_selector(ui: &mut Ui, idx: usize, field: &mut DraftField) {
    let label = |kind| match kind {
        DraftFieldKind::Text => "Text",
        DraftFieldKind::Hidden => "Hidden",
        DraftFieldKind::Boolean => "Boolean",
        DraftFieldKind::Linked => "Linked",
    };
    let before = field.kind;
    egui::ComboBox::from_id_salt(("edit-field-kind", idx))
        .width(84.0)
        .selected_text(label(field.kind))
        .show_ui(ui, |ui| {
            for kind in [DraftFieldKind::Text, DraftFieldKind::Hidden, DraftFieldKind::Boolean] {
                ui.selectable_value(&mut field.kind, kind, label(kind));
            }
        });
    if field.kind == DraftFieldKind::Boolean && before != DraftFieldKind::Boolean {
        field.value = (field.value.trim().eq_ignore_ascii_case("true")).to_string();
    }
}

fn labeled_row(ui: &mut Ui, label: &str, add_contents: impl FnOnce(&mut Ui)) {
    let t = theme();
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            egui::vec2(LABEL_WIDTH, INPUT_HEIGHT),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_min_width(LABEL_WIDTH);
                ui.label(RichText::new(label).color(t.text_muted));
            },
        );
        add_contents(ui);
    });
}

fn glyph(ui: &mut Ui, nerd: &'static str, fallback: &'static str, tooltip: &str) -> egui::Response {
    let t = theme();
    ui.add(
        egui::Button::new(RichText::new(t.icon(nerd, fallback)).color(t.text_muted))
            .frame(false)
            .min_size(egui::vec2(28.0, 28.0)),
    )
    .on_hover_text(tooltip)
}

fn reveal_button(ui: &mut Ui, revealed: bool) -> egui::Response {
    if revealed {
        glyph(ui, "\u{f070}", "🙈", "Hide")
    } else {
        glyph(ui, "\u{f06e}", "👁", "Show")
    }
}

fn remove_button(ui: &mut Ui) -> egui::Response {
    glyph(ui, "\u{f00d}", "✕", "Remove")
}

fn add_button(ui: &mut Ui, text: &str) -> egui::Response {
    let t = theme();
    ui.add(
        egui::Button::new(
            RichText::new(format!("{} {text}", t.icon("\u{f067}", "+"))).color(t.accent),
        )
        .frame(false),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_name_and_field_names() {
        let mut draft = ItemDraft {
            name: "Item".into(),
            ..ItemDraft::default()
        };
        assert!(validate(&draft).is_ok());

        draft.fields.push(DraftField {
            name: " ".into(),
            value: "secret".into(),
            kind: DraftFieldKind::Hidden,
            original_index: None,
        });
        assert!(validate(&draft).is_err());

        draft.fields[0].value.clear();
        assert!(validate(&draft).is_ok(), "empty unnamed rows are dropped on save");

        draft.name = "  ".into();
        assert!(validate(&draft).is_err());
    }

    #[test]
    fn tracks_unsaved_changes() {
        let mut state = EditState::loading("id".into());
        state.set_draft(ItemDraft {
            name: "Item".into(),
            ..ItemDraft::default()
        });
        assert!(!state.is_dirty());

        state.draft.as_mut().unwrap().notes = "changed".into();
        assert!(state.is_dirty());
    }
}
