//! Edit form for an item: name, folder, login credentials, passkeys, websites, custom
//! fields and notes.

use crate::generator::{GeneratorMode, GeneratorOptions};
use crate::model::{
    DraftField, DraftFieldKind, DraftUri, Folder, ItemDraft, LoginDraft, TypedDraft, TypedKind,
    card_brand,
};
use crate::ui::shortcuts as sc;
use crate::ui::theme::theme;
use crate::ui::widgets;
use egui::{RichText, Ui};
use std::collections::HashSet;

const LABEL_WIDTH: f32 = 128.0;
const FIELD_NAME_WIDTH: f32 = 150.0;
const INPUT_HEIGHT: f32 = 34.0;

pub struct EditState {
    /// Item being edited; empty while creating a new one.
    pub id: String,
    pub creating: bool,
    /// Login data put aside while a new item is switched to another type.
    stashed_login: Option<LoginDraft>,
    /// Card and identity data put aside the same way.
    stashed_typed: Vec<TypedDraft>,
    /// `None` while the draft is loading.
    pub draft: Option<ItemDraft>,
    original: Option<ItemDraft>,
    pub error: Option<String>,
    pub saving: bool,
    /// Folders to choose from; empty until the caller provides them.
    pub folders: Vec<Folder>,
    confirm_discard: bool,
    /// Passkey (index into the draft's passkeys) waiting for removal confirmation.
    confirm_remove_passkey: Option<usize>,
    reveal_password: bool,
    reveal_totp: bool,
    reveal_fields: HashSet<usize>,
    /// Revealed secret card or identity fields, by index into the kind's fields.
    reveal_typed: HashSet<usize>,
    /// Input to focus on the next frame, such as the name of a field just added.
    focus: Option<egui::Id>,
    generator_open: bool,
    /// The generator options changed since the caller last saved them.
    pub generator_changed: bool,
}

pub enum EditAction {
    Cancel,
    Save(ItemDraft),
}

impl Drop for EditState {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(draft) = &mut self.draft {
            draft.zeroize();
        }
        if let Some(original) = &mut self.original {
            original.zeroize();
        }
        if let Some(login) = &mut self.stashed_login {
            login.zeroize();
        }
        for typed in &mut self.stashed_typed {
            typed.zeroize();
        }
    }
}

impl EditState {
    pub fn loading(id: String) -> Self {
        Self {
            id,
            creating: false,
            stashed_login: None,
            stashed_typed: Vec::new(),
            draft: None,
            original: None,
            error: None,
            saving: false,
            folders: Vec::new(),
            confirm_discard: false,
            confirm_remove_passkey: None,
            reveal_password: false,
            reveal_totp: false,
            reveal_fields: HashSet::new(),
            reveal_typed: HashSet::new(),
            focus: Some(name_id()),
            generator_open: false,
            generator_changed: false,
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

/// The Generate button and its options under the password field. Changing an option
/// replaces the password with a new one, like pressing Generate again.
struct GeneratorState<'a> {
    open: &'a mut bool,
    /// Whether the password field shows its value.
    reveal: &'a mut bool,
    changed: &'a mut bool,
    error: &'a mut Option<String>,
}

fn draw_generator(
    ui: &mut Ui,
    state: GeneratorState,
    login: &mut LoginDraft,
    options: &mut GeneratorOptions,
) {
    let t = theme();
    let before = options.clone();
    let mut regenerate = false;
    labeled_row(ui, "", |ui| {
        ui.horizontal(|ui| {
            let label = match options.mode {
                GeneratorMode::Password => "Generate password",
                GeneratorMode::Passphrase => "Generate passphrase",
            };
            regenerate |= ui.button(label).clicked();
            let toggle = if *state.open {
                "Hide options"
            } else {
                "Options"
            };
            if ui.button(toggle).clicked() {
                *state.open = !*state.open;
                // Show what the options produce while they are open.
                if *state.open {
                    *state.reveal = true;
                }
            }
            let bits = options.entropy_bits();
            ui.label(
                RichText::new(format!(
                    "{} · {:.0} bits",
                    crate::generator::strength_label(bits),
                    bits
                ))
                .size(t.small())
                .color(t.text_muted),
            );
        });
    });
    if *state.open {
        labeled_row(ui, "", |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.radio_value(&mut options.mode, GeneratorMode::Password, "Password");
                    ui.radio_value(&mut options.mode, GeneratorMode::Passphrase, "Passphrase");
                });
                match options.mode {
                    GeneratorMode::Password => {
                        ui.add(
                            egui::Slider::new(&mut options.length, crate::generator::LENGTH_RANGE)
                                .text("characters"),
                        );
                        ui.horizontal_wrapped(|ui| {
                            ui.checkbox(&mut options.uppercase, "A–Z");
                            ui.checkbox(&mut options.lowercase, "a–z");
                            ui.checkbox(&mut options.digits, "0–9");
                            ui.checkbox(&mut options.symbols, "!@#$%");
                            ui.checkbox(
                                &mut options.avoid_ambiguous,
                                "Avoid ambiguous (I l 1 O 0)",
                            );
                        });
                    }
                    GeneratorMode::Passphrase => {
                        ui.add(
                            egui::Slider::new(&mut options.words, crate::generator::WORDS_RANGE)
                                .text("words"),
                        );
                        ui.horizontal_wrapped(|ui| {
                            ui.label("Separator");
                            ui.add(
                                egui::TextEdit::singleline(&mut options.separator)
                                    .char_limit(3)
                                    .desired_width(36.0),
                            );
                            ui.checkbox(&mut options.capitalize, "Capitalize");
                            ui.checkbox(&mut options.include_number, "Add a number");
                        });
                    }
                }
            });
        });
    }
    if *options != before {
        *state.changed = true;
        regenerate = true;
    }
    if regenerate {
        match crate::generator::generate(options) {
            Ok(password) => {
                use zeroize::Zeroize;
                login.password.zeroize();
                login.password = password;
                *state.reveal = true;
            }
            Err(error) => *state.error = Some(format!("Could not generate password: {error}")),
        }
    }
}

/// What a new item is, as the type picker offers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemKind {
    Login,
    SecureNote,
    Typed(TypedKind),
}

impl ItemKind {
    const ALL: [Self; 4] = [
        Self::Login,
        Self::SecureNote,
        Self::Typed(TypedKind::Card),
        Self::Typed(TypedKind::Identity),
    ];

    fn of(draft: &ItemDraft) -> Self {
        match (&draft.login, &draft.typed) {
            (Some(_), _) => Self::Login,
            (None, Some(typed)) => Self::Typed(typed.kind),
            (None, None) => Self::SecureNote,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Login => "Login",
            Self::SecureNote => "Secure note",
            Self::Typed(kind) => kind.label(),
        }
    }
}

/// Changes a new item's type, keeping what was typed for the old type in case the user
/// switches back.
struct Stash<'a> {
    login: &'a mut Option<LoginDraft>,
    typed: &'a mut Vec<TypedDraft>,
}

fn switch_kind(stash: Stash, draft: &mut ItemDraft, kind: ItemKind) {
    if let Some(login) = draft.login.take() {
        *stash.login = Some(login);
    }
    if let Some(typed) = draft.typed.take() {
        stash.typed.push(typed);
    }
    match kind {
        ItemKind::Login => draft.login = Some(stash.login.take().unwrap_or_default()),
        ItemKind::SecureNote => {}
        ItemKind::Typed(kind) => {
            let stashed = stash.typed.iter().position(|typed| typed.kind == kind);
            draft.typed = Some(match stashed {
                Some(idx) => stash.typed.remove(idx),
                None => TypedDraft::new(kind),
            });
        }
    }
}

/// Card or identity fields. Secret ones are masked until revealed, and a card number
/// fills in the brand unless the user chose a different one.
fn draw_typed(ui: &mut Ui, typed: &mut TypedDraft, revealed: &mut HashSet<usize>) {
    let t = theme();
    let kind = typed.kind;
    let detected_before = card_brand(typed.get("number"));
    for (idx, field) in kind.fields().iter().enumerate() {
        let Some(value) = typed.values.get_mut(idx) else {
            continue;
        };
        labeled_row(ui, field.label, |ui| {
            let id = egui::Id::new(("edit-typed", kind.label(), idx));
            if field.secret {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let shown = revealed.contains(&idx);
                    if reveal_button(ui, shown).clicked() && !revealed.remove(&idx) {
                        revealed.insert(idx);
                    }
                    widgets::text_input(ui, id, value, "", !shown, t.body());
                });
            } else {
                let hint = match field.key {
                    "expMonth" => "MM",
                    "expYear" => "YYYY",
                    _ => "",
                };
                widgets::text_input(ui, id, value, hint, false, t.body());
            }
        });
    }
    if kind == TypedKind::Card {
        let brand = typed.get("brand");
        let detected = card_brand(typed.get("number"));
        if detected != detected_before
            && (brand.is_empty() || Some(brand) == detected_before)
            && let Some(detected) = detected
        {
            typed.set("brand", detected.to_string());
        }
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

pub fn draw_edit(
    root: &mut egui::Ui,
    state: &mut EditState,
    show_shortcuts: bool,
    generator: &mut GeneratorOptions,
) -> Option<EditAction> {
    let ctx = &root.ctx().clone();
    let t = theme();
    let mut action = None;
    let dialog_open = state.confirm_discard || state.confirm_remove_passkey.is_some();

    if !dialog_open && !state.saving {
        let popup_open = egui::Popup::is_any_open(ctx);
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
        let hints: &[(sc::Combo, &str)] = if show_shortcuts {
            &[
                (sc::TAB, "Next field"),
                (sc::command("S"), "Save"),
                (sc::ESCAPE, "Cancel"),
                (sc::HELP, "Keyboard shortcuts"),
            ]
        } else {
            &[]
        };
        egui::Panel::bottom("footer")
            .frame(widgets::footer_frame())
            .show(root, |ui| widgets::footer(ui, hints, status));
    }

    widgets::header(root, "header", |ui| {
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
            let title = if state.creating {
                "New item"
            } else {
                "Edit item"
            };
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
        .show(root, |ui| {
            if state.draft.is_none() {
                widgets::empty_state(ui, "", "Loading item…", true);
                return;
            }
            let enabled = !state.saving && !dialog_open;
            ui.add_enabled_ui(enabled, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| draw_form(ui, state, generator));
            });
        });

    if let Some(idx) = state.confirm_remove_passkey {
        let passkeys = state
            .draft
            .as_mut()
            .and_then(|draft| draft.login.as_mut())
            .map(|login| &mut login.passkeys);
        match passkeys {
            Some(passkeys) if idx < passkeys.len() => {
                let body = format!(
                    "You will no longer be able to sign in with the passkey for {}. \
                     It is deleted from the vault when you save this item.",
                    passkeys[idx].passkey.describe()
                );
                let dialog = widgets::ConfirmDialog {
                    title: "Remove passkey?",
                    body: &body,
                    confirm_label: "Remove passkey",
                    danger: true,
                    key: widgets::ConfirmKey::CtrlEnter,
                    busy: false,
                    error: None,
                };
                match widgets::confirm_dialog(ctx, &dialog) {
                    Some(true) => {
                        passkeys.remove(idx);
                        state.confirm_remove_passkey = None;
                    }
                    Some(false) => state.confirm_remove_passkey = None,
                    None => {}
                }
            }
            _ => state.confirm_remove_passkey = None,
        }
    } else if state.confirm_discard {
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
    if let Some(problem) = draft.typed.as_ref().and_then(TypedDraft::problem) {
        return Err(problem);
    }
    Ok(())
}

fn draw_form(ui: &mut Ui, state: &mut EditState, generator: &mut GeneratorOptions) {
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
            let current = ItemKind::of(draft);
            for kind in ItemKind::ALL {
                if ui.selectable_label(current == kind, kind.label()).clicked() && current != kind {
                    switch_kind(
                        Stash {
                            login: &mut state.stashed_login,
                            typed: &mut state.stashed_typed,
                        },
                        draft,
                        kind,
                    );
                    state.reveal_typed.clear();
                }
            }
        });
    }

    labeled_row(ui, "Name", |ui| {
        let response =
            widgets::text_input(ui, name_id(), &mut draft.name, "Item name", false, t.body());
        focus_if(&response, name_id());
    });

    labeled_row(ui, "Folder", |ui| {
        folder_selector(ui, &mut draft.folder_id, &state.folders);
        ui.add_space(12.0);
        let star = if draft.favorite {
            t.icon("\u{f005}", "★")
        } else {
            t.icon("\u{f006}", "☆")
        };
        let color = if draft.favorite {
            t.warning
        } else {
            t.text_muted
        };
        if ui
            .add(
                egui::Button::new(RichText::new(format!("{star} Favorite")).color(color))
                    .frame(false),
            )
            .clicked()
        {
            draft.favorite = !draft.favorite;
        }
    });

    if let Some(typed) = draft.typed.as_mut() {
        draw_typed(ui, typed, &mut state.reveal_typed);
    }

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
        draw_generator(
            ui,
            GeneratorState {
                open: &mut state.generator_open,
                reveal: &mut state.reveal_password,
                changed: &mut state.generator_changed,
                error: &mut state.error,
            },
            login,
            generator,
        );
        labeled_row(ui, "TOTP secret", |ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if reveal_button(ui, state.reveal_totp).clicked() {
                    state.reveal_totp = !state.reveal_totp;
                }
                widgets::text_input(
                    ui,
                    egui::Id::new(("edit", "totp")),
                    &mut login.totp,
                    "otpauth://… or base32 key",
                    !state.reveal_totp,
                    t.body(),
                );
            });
        });

        for (idx, passkey) in login.passkeys.iter().enumerate() {
            let label = if idx == 0 { "Passkeys" } else { "" };
            labeled_row(ui, label, |ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if glyph(ui, "\u{f1f8}", "🗑", "Remove passkey").clicked() {
                        state.confirm_remove_passkey = Some(idx);
                    }
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!(
                                "{}  {}",
                                t.icon("\u{f084}", "🔑"),
                                passkey.passkey.describe()
                            ))
                            .color(t.text),
                        );
                        if let Some(date) = passkey
                            .passkey
                            .creation_date
                            .as_deref()
                            .and_then(widgets::format_date)
                        {
                            ui.label(RichText::new(format!("saved {date}")).color(t.text_faint));
                        }
                    });
                });
            });
        }

        let mut remove = None;
        for (idx, uri) in login.uris.iter_mut().enumerate() {
            let label = if idx == 0 { "Websites" } else { "" };
            labeled_row(ui, label, |ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if remove_button(ui).clicked() {
                        remove = Some(idx);
                    }
                    let response = widgets::text_input(
                        ui,
                        uri_id(idx),
                        &mut uri.uri,
                        "https://",
                        false,
                        t.body(),
                    );
                    focus_if(&response, uri_id(idx));
                });
            });
        }
        if let Some(idx) = remove {
            login.uris.remove(idx);
        }
        labeled_row(
            ui,
            if login.uris.is_empty() {
                "Websites"
            } else {
                ""
            },
            |ui| {
                if add_button(ui, "Add website").clicked() {
                    login.uris.push(DraftUri::default());
                    state.focus = Some(uri_id(login.uris.len() - 1));
                }
            },
        );
    }

    ui.add_space(8.0);
    ui.label(
        RichText::new("Custom fields")
            .size(t.small())
            .color(t.text_muted),
    );
    let mut remove = None;
    for (idx, field) in draft.fields.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            ui.allocate_ui(egui::vec2(FIELD_NAME_WIDTH, INPUT_HEIGHT), |ui| {
                let response = widgets::text_input(
                    ui,
                    field_name_id(idx),
                    &mut field.name,
                    "Field name",
                    false,
                    t.body(),
                );
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
    widgets::text_area(
        ui,
        egui::Id::new(("edit", "notes")),
        &mut draft.notes,
        "",
        4,
    );
    ui.add_space(8.0);
}

fn draw_field_value(
    ui: &mut Ui,
    idx: usize,
    field: &mut DraftField,
    revealed: &mut HashSet<usize>,
) {
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

fn folder_selector(ui: &mut Ui, folder_id: &mut Option<String>, folders: &[Folder]) {
    let current = match folder_id.as_deref() {
        None => "No folder".to_string(),
        Some(id) => folders
            .iter()
            .find(|folder| folder.id == id)
            .map(|folder| folder.name.clone())
            .unwrap_or_else(|| "Unknown folder".into()),
    };
    egui::ComboBox::from_id_salt(("edit", "folder"))
        .width(220.0)
        .selected_text(current)
        .show_ui(ui, |ui| {
            ui.selectable_value(folder_id, None, "No folder");
            for folder in folders {
                ui.selectable_value(folder_id, Some(folder.id.clone()), &folder.name);
            }
        });
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
            for kind in [
                DraftFieldKind::Text,
                DraftFieldKind::Hidden,
                DraftFieldKind::Boolean,
            ] {
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
    fn switching_type_keeps_what_was_typed() {
        let mut login = None;
        let mut typed = Vec::new();
        let mut draft = ItemDraft {
            login: Some(LoginDraft {
                username: "alex".into(),
                ..LoginDraft::default()
            }),
            ..ItemDraft::default()
        };
        let mut switch = |draft: &mut ItemDraft, kind| {
            switch_kind(
                Stash {
                    login: &mut login,
                    typed: &mut typed,
                },
                draft,
                kind,
            )
        };

        switch(&mut draft, ItemKind::Typed(TypedKind::Card));
        assert!(draft.login.is_none());
        draft.typed.as_mut().unwrap().set("number", "4111".into());
        switch(&mut draft, ItemKind::Typed(TypedKind::Identity));
        assert_eq!(draft.typed.as_ref().unwrap().kind, TypedKind::Identity);
        switch(&mut draft, ItemKind::SecureNote);
        assert!(draft.login.is_none() && draft.typed.is_none());
        switch(&mut draft, ItemKind::Typed(TypedKind::Card));
        assert_eq!(draft.typed.as_ref().unwrap().get("number"), "4111");
        switch(&mut draft, ItemKind::Login);
        assert_eq!(draft.login.as_ref().unwrap().username, "alex");
        assert_eq!(ItemKind::of(&draft), ItemKind::Login);
    }

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
        assert!(
            validate(&draft).is_ok(),
            "empty unnamed rows are dropped on save"
        );

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
    fn with_passkey() -> EditState {
        let mut state = EditState::loading("id".into());
        state.set_draft(ItemDraft {
            name: "GitHub".into(),
            login: Some(LoginDraft {
                passkeys: vec![crate::model::DraftPasskey {
                    passkey: crate::model::Passkey {
                        rp_id: "github.com".into(),
                        user_name: Some("alice".into()),
                        ..Default::default()
                    },
                    original_index: 0,
                }],
                ..LoginDraft::default()
            }),
            ..ItemDraft::default()
        });
        state
    }

    fn frame(state: &mut EditState, events: Vec<egui::Event>) -> Vec<String> {
        let ctx = egui::Context::default();
        let input = |events| egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(680., 460.),
            )),
            events,
            ..Default::default()
        };
        // egui lays windows out invisibly on their first frame.
        let mut out = ctx.run_ui(input(Vec::new()), |ui| {
            draw_edit(ui, state, true, &mut GeneratorOptions::default());
        });
        out.textures_delta.clear();
        let mut out = ctx.run_ui(input(events), |ui| {
            draw_edit(ui, state, true, &mut GeneratorOptions::default());
        });
        out.textures_delta.clear();
        out.shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some(text.galley.job.text.clone()),
                _ => None,
            })
            .collect()
    }

    fn key(key: egui::Key, modifiers: egui::Modifiers) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers,
        }
    }

    fn passkey_count(state: &EditState) -> usize {
        state
            .draft
            .as_ref()
            .unwrap()
            .login
            .as_ref()
            .unwrap()
            .passkeys
            .len()
    }

    #[test]
    fn editor_lists_passkeys() {
        let mut state = with_passkey();
        let texts = frame(&mut state, Vec::new());
        assert!(
            texts
                .iter()
                .any(|text| text.contains("alice on github.com"))
        );
    }

    #[test]
    fn removing_a_passkey_needs_confirmation() {
        let mut state = with_passkey();
        state.confirm_remove_passkey = Some(0);
        let texts = frame(&mut state, Vec::new());
        assert!(texts.iter().any(|text| text == "Remove passkey?"));
        assert_eq!(passkey_count(&state), 1);

        // A plain Enter must not remove it; Escape cancels.
        frame(
            &mut state,
            vec![key(egui::Key::Enter, egui::Modifiers::NONE)],
        );
        assert_eq!(passkey_count(&state), 1);
        frame(
            &mut state,
            vec![key(egui::Key::Escape, egui::Modifiers::NONE)],
        );
        assert_eq!(state.confirm_remove_passkey, None);
        assert_eq!(passkey_count(&state), 1);
        assert!(!state.is_dirty());

        state.confirm_remove_passkey = Some(0);
        frame(
            &mut state,
            vec![key(egui::Key::Enter, egui::Modifiers::COMMAND)],
        );
        assert_eq!(passkey_count(&state), 0);
        assert!(state.is_dirty(), "removal waits for Save");
    }

    #[test]
    fn totp_seed_is_masked_in_editor() {
        let ctx = egui::Context::default();
        let mut state = EditState::create();
        state.draft.as_mut().unwrap().login.as_mut().unwrap().totp = "AUDITSECRETSEED".into();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(680., 460.),
            )),
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ctx| {
            draw_edit(ctx, &mut state, true, &mut GeneratorOptions::default());
        });
        out.textures_delta.clear();
        assert!(!out.shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(text) if text.galley.job.text.contains("AUDITSECRETSEED"))));
    }
}
