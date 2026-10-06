//! Keyboard shortcuts as data, drawn as keycaps. macOS shows ⌘ ⇧ ⌥ and Return; other
//! platforms Ctrl, Shift, Alt and Enter. Footer hints and the shortcuts dialog share them.
use crate::ui::theme::theme;
use egui::{Color32, Painter, Pos2, RichText, Ui};

const MAC: bool = cfg!(target_os = "macos");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Enter,
    Escape,
    Space,
    Tab,
    Backspace,
    Delete,
    Up,
    Down,
    UpDown,
    Text(&'static str),
}

/// A key with the modifiers held for it. `command` is egui's COMMAND: ⌘ on macOS and
/// Ctrl elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Combo {
    pub command: bool,
    pub shift: bool,
    pub alt: bool,
    pub key: Key,
}

impl Combo {
    pub const fn key(key: Key) -> Self {
        Self {
            command: false,
            shift: false,
            alt: false,
            key,
        }
    }

    pub const fn command(key: Key) -> Self {
        Self {
            command: true,
            ..Self::key(key)
        }
    }

    pub const fn shift(key: Key) -> Self {
        Self {
            shift: true,
            ..Self::key(key)
        }
    }

    /// One label per keycap, modifiers first in the platform's usual order.
    pub fn caps(self) -> Vec<String> {
        let modifiers: &[(bool, &str, &str)] = &[
            (self.alt, "⌥", "Alt"),
            (self.shift, "⇧", "Shift"),
            (self.command, "⌘", "Ctrl"),
        ];
        let mut caps: Vec<String> = if MAC {
            modifiers
                .iter()
                .filter(|(held, ..)| *held)
                .map(|(_, mac, _)| (*mac).to_owned())
                .collect()
        } else {
            // Ctrl, Alt, Shift, as Linux and Windows spell combinations.
            [
                (self.command, "Ctrl"),
                (self.alt, "Alt"),
                (self.shift, "Shift"),
            ]
            .into_iter()
            .filter(|(held, _)| *held)
            .map(|(_, name)| name.to_owned())
            .collect()
        };
        caps.push(key_label(self.key).to_owned());
        caps
    }
}

fn key_label(key: Key) -> &'static str {
    match key {
        Key::Enter if MAC => "Return",
        Key::Enter => "Enter",
        Key::Escape => "Esc",
        Key::Space => "Space",
        Key::Tab => "Tab",
        Key::Backspace if MAC => "⌫",
        Key::Backspace => "Backspace",
        Key::Delete => "Del",
        Key::Up => "↑",
        Key::Down => "↓",
        Key::UpDown => "↑↓",
        Key::Text(text) => text,
    }
}

impl Combo {
    /// The combination as inline text for tooltips: "⇧⌘R" on macOS, "Ctrl+Shift+R" elsewhere.
    pub fn text(self) -> String {
        self.caps().join(if MAC { "" } else { "+" })
    }
}

/// Keycaps for the global quick access shortcut, as the shortcut settings record it.
pub fn global_caps(shortcut: &crate::shortcut::Shortcut) -> Vec<String> {
    let names = if MAC {
        ["⌃", "⌥", "⇧", "⌘"]
    } else {
        ["Ctrl", "Alt", "Shift", "Super"]
    };
    let mut caps: Vec<String> = [
        shortcut.ctrl,
        shortcut.alt,
        shortcut.shift,
        shortcut.super_key,
    ]
    .into_iter()
    .zip(names)
    .filter(|(held, _)| *held)
    .map(|(_, name)| name.to_owned())
    .collect();
    caps.push(shortcut.key.clone());
    caps
}

/// Keycap height and label size.
#[derive(Clone, Copy)]
pub struct CapStyle {
    pub height: f32,
    pub font: f32,
}

impl CapStyle {
    pub fn footer() -> Self {
        Self {
            height: 20.0,
            font: theme().small() - 1.0,
        }
    }

    pub fn dialog() -> Self {
        Self {
            height: 24.0,
            font: theme().small(),
        }
    }
}

const CAP_GAP: f32 = 3.0;

fn cap_width(painter: &Painter, cap: &str, style: CapStyle) -> f32 {
    let arrows = match cap {
        "↑" | "↓" | "←" | "→" => Some(1.0),
        "↑↓" => Some(2.0),
        "←↑↓→" => Some(4.0),
        _ => None,
    };
    if let Some(count) = arrows {
        return style.height + (count - 1.0) * 10.0;
    }
    let galley = painter.layout_no_wrap(cap.to_owned(), theme().font(style.font), Color32::WHITE);
    (galley.size().x + 12.0).max(style.height)
}

/// Width of `caps` laid out side by side.
pub fn caps_width(painter: &Painter, caps: &[String], style: CapStyle) -> f32 {
    caps.iter()
        .map(|cap| cap_width(painter, cap, style))
        .sum::<f32>()
        + CAP_GAP * caps.len().saturating_sub(1) as f32
}

/// Paints `caps` from `left_center` rightwards and returns the right edge.
pub fn paint_caps(painter: &Painter, left_center: Pos2, caps: &[String], style: CapStyle) -> f32 {
    let t = theme();
    let mut left = left_center.x;
    for cap in caps {
        let width = cap_width(painter, cap, style);
        let rect = egui::Rect::from_min_size(
            egui::pos2(left, left_center.y - style.height / 2.0),
            egui::vec2(width, style.height),
        );
        let radius = t.rounding.min(5) as f32;
        painter.rect_filled(rect, radius, t.surface);
        painter.rect_stroke(
            rect,
            radius,
            egui::Stroke::new(1.0_f32, t.border),
            egui::StrokeKind::Inside,
        );
        paint_label(painter, rect, cap, style, t.text);
        left = rect.right() + CAP_GAP;
    }
    left - CAP_GAP
}

fn paint_label(painter: &Painter, rect: egui::Rect, cap: &str, style: CapStyle, color: Color32) {
    // The bundled fonts have no arrows, so arrow keys are drawn.
    let directions: &[egui::Vec2] = match cap {
        "↑" => &[egui::vec2(0.0, -4.5)],
        "↓" => &[egui::vec2(0.0, 4.5)],
        "←" => &[egui::vec2(-5.0, 0.0)],
        "→" => &[egui::vec2(5.0, 0.0)],
        "↑↓" => &[egui::vec2(0.0, -4.5), egui::vec2(0.0, 4.5)],
        "←↑↓→" => &[
            egui::vec2(-4.5, 0.0),
            egui::vec2(0.0, -4.5),
            egui::vec2(0.0, 4.5),
            egui::vec2(4.5, 0.0),
        ],
        _ => {
            // Apple Symbols draws these smaller than the text font draws ⌘.
            let size = if matches!(cap, "⇧" | "⌥" | "⌃" | "⌫") {
                style.font * 1.35
            } else {
                style.font
            };
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                cap,
                theme().font(size),
                color,
            );
            return;
        }
    };
    let spacing = 10.0;
    let first = rect.center().x - spacing * (directions.len() as f32 - 1.0) / 2.0;
    for (index, direction) in directions.iter().enumerate() {
        arrow(
            painter,
            egui::pos2(first + spacing * index as f32, rect.center().y),
            *direction,
            color,
        );
    }
}

fn arrow(painter: &Painter, center: Pos2, delta: egui::Vec2, color: Color32) {
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

/// Opens the shortcuts dialog from any screen of quick access or the vault window.
pub const HELP: Combo = Combo::command(Key::Text("/"));
pub const ENTER: Combo = Combo::key(Key::Enter);
pub const ESCAPE: Combo = Combo::key(Key::Escape);
pub const SPACE: Combo = Combo::key(Key::Space);
pub const TAB: Combo = Combo::key(Key::Tab);
pub const BACKSPACE: Combo = Combo::key(Key::Backspace);
pub const UP_DOWN: Combo = Combo::key(Key::UpDown);

/// The command modifier (⌘ or Ctrl) with a letter.
pub const fn command(letter: &'static str) -> Combo {
    Combo::command(Key::Text(letter))
}

/// A single letter key.
pub const fn letter(letter: &'static str) -> Combo {
    Combo::key(Key::Text(letter))
}

/// Moves an item to the trash: ⌫ on Mac keyboards, where forward delete needs fn.
pub const TRASH: Combo = Combo::key(if MAC { Key::Backspace } else { Key::Delete });

const ITEM_ROWS: &[(&str, Combo)] = &[
    ("Copy or open the selected field", ENTER),
    ("Copy the selected field", command("C")),
    ("Show or hide a hidden field", SPACE),
    ("Edit", letter("E")),
    ("Favorite or unfavorite", letter("F")),
    ("Archive or unarchive", letter("A")),
    ("Move to trash, or delete from trash", TRASH),
    ("Restore from trash", letter("R")),
];

const EDIT_ROWS: &[(&str, Combo)] = &[
    ("Next field", TAB),
    ("Save", command("S")),
    ("Cancel", ESCAPE),
];

/// Every shortcut in quick access, from the key handlers in `ui::search`, `ui::summary`
/// and `ui::edit`.
pub const QUICK_ACCESS: &[Section] = &[
    Section {
        title: "Basics",
        rows: &[
            ("Keyboard shortcuts", HELP),
            ("Hide quick access", ESCAPE),
            ("Sync vault", command("R")),
        ],
    },
    Section {
        title: "Search",
        rows: &[
            ("Next or previous result", UP_DOWN),
            ("Open", ENTER),
            ("Copy password", Combo::shift(Key::Enter)),
        ],
    },
    Section {
        title: "Selected item",
        rows: ITEM_ROWS,
    },
    Section {
        title: "Item details",
        rows: &[("Next or previous field", UP_DOWN), ("Back", ESCAPE)],
    },
    Section {
        title: "Editing",
        rows: EDIT_ROWS,
    },
    Section {
        title: "Archive and trash",
        rows: &[
            ("Change sort order", TAB),
            ("Sort ascending", Combo::command(Key::Up)),
            ("Sort descending", Combo::command(Key::Down)),
            ("Back to search", ESCAPE),
        ],
    },
    Section {
        title: "Settings",
        rows: &[
            ("Next or previous setting", UP_DOWN),
            ("Change the selected setting", SPACE),
            ("Record the quick access shortcut", ENTER),
            ("Clear the quick access shortcut", BACKSPACE),
            ("Back to search", ESCAPE),
        ],
    },
];

/// Every shortcut in the vault window, from the key handlers in `window` and the shared
/// item and edit screens.
pub const VAULT_WINDOW: &[Section] = &[
    Section {
        title: "Basics",
        rows: &[
            ("Keyboard shortcuts", HELP),
            ("Search vault", command("F")),
            ("New item", command("N")),
            ("Sync vault", command("R")),
            ("Lock vault", command("L")),
        ],
    },
    Section {
        title: "Item list",
        rows: &[
            ("Next or previous item", UP_DOWN),
            ("Select all", command("A")),
            ("Add an item to the selection", command("Click")),
            ("Select a range", Combo::shift(Key::Text("Click"))),
            ("Clear search", ESCAPE),
        ],
    },
    Section {
        title: "Selected item",
        rows: ITEM_ROWS,
    },
    Section {
        title: "Editing",
        rows: EDIT_ROWS,
    },
    Section {
        title: "Settings",
        rows: &[
            ("Next or previous setting", UP_DOWN),
            ("Change the selected setting", SPACE),
            ("Record the quick access shortcut", ENTER),
            ("Clear the quick access shortcut", BACKSPACE),
            ("Back", ESCAPE),
        ],
    },
];

pub struct Section {
    pub title: &'static str,
    pub rows: &'static [(&'static str, Combo)],
}

#[derive(Default)]
pub struct ShortcutsDialog {
    pub open: bool,
}

impl ShortcutsDialog {
    /// Call before other key handling: ⌘/ toggles the dialog, Escape closes it, and while
    /// it is open no other key reaches the screen behind it.
    pub fn handle_keys(&mut self, ctx: &egui::Context) {
        ctx.input_mut(|input| {
            if input.consume_key(egui::Modifiers::COMMAND, egui::Key::Slash) {
                self.open = !self.open;
            } else if self.open && input.consume_key(egui::Modifiers::NONE, egui::Key::Escape) {
                self.open = false;
            }
            if self.open {
                input.events.retain(|event| {
                    !matches!(event, egui::Event::Key { .. } | egui::Event::Text(_))
                });
            }
        });
    }

    /// `global` is the quick access shortcut, listed first when one is set.
    pub fn show(
        &mut self,
        ctx: &egui::Context,
        sections: &[Section],
        global: Option<&crate::shortcut::Shortcut>,
    ) {
        if !self.open {
            return;
        }
        let t = theme();
        let style = CapStyle::dialog();
        let max_height = (ctx.content_rect().height() - 80.0).max(160.0);
        egui::Window::new("Keyboard shortcuts")
            .collapsible(false)
            .resizable(false)
            .title_bar(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(
                egui::Frame::window(&ctx.global_style())
                    .fill(t.bg)
                    .stroke(egui::Stroke::new(1.0_f32, t.border))
                    .inner_margin(egui::Margin::same(16)),
            )
            .show(ctx, |ui| {
                ui.set_width(420.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Keyboard shortcuts")
                            .size(t.title())
                            .color(t.text_strong),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Button::new(RichText::new("✕").color(t.text_muted))
                                    .frame(false),
                            )
                            .on_hover_text("Close (Esc)")
                            .clicked()
                        {
                            self.open = false;
                        }
                    });
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .max_height(max_height)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        let global_row =
                            global.map(|shortcut| ("Show quick access", global_caps(shortcut)));
                        for (index, section) in sections.iter().enumerate() {
                            if index > 0 {
                                ui.add_space(4.0);
                                ui.separator();
                            }
                            ui.add_space(6.0);
                            ui.label(RichText::new(section.title).strong().color(t.text_strong));
                            ui.add_space(2.0);
                            let rows = section
                                .rows
                                .iter()
                                .map(|(label, combo)| (*label, combo.caps()));
                            let rows: Vec<_> = if index == 0 {
                                global_row.clone().into_iter().chain(rows).collect()
                            } else {
                                rows.collect()
                            };
                            for (label, caps) in rows {
                                shortcut_row(ui, label, &caps, style);
                            }
                        }
                    });
            });
    }
}

fn shortcut_row(ui: &mut Ui, label: &str, caps: &[String], style: CapStyle) {
    let t = theme();
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), style.height + 10.0),
        egui::Sense::hover(),
    );
    let painter = ui.painter_at(rect);
    painter.text(
        egui::pos2(rect.left(), rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        t.font(t.body()),
        t.text,
    );
    let width = caps_width(&painter, caps, style);
    paint_caps(
        &painter,
        egui::pos2(rect.right() - width - 2.0, rect.center().y),
        caps,
        style,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combos_use_platform_names_and_order() {
        let copy = Combo {
            command: true,
            shift: true,
            alt: false,
            key: Key::Text("C"),
        };
        let open = Combo::key(Key::Enter);
        if MAC {
            assert_eq!(copy.caps(), ["⇧", "⌘", "C"]);
            assert_eq!(open.caps(), ["Return"]);
            assert_eq!(HELP.caps(), ["⌘", "/"]);
        } else {
            assert_eq!(copy.caps(), ["Ctrl", "Shift", "C"]);
            assert_eq!(open.caps(), ["Enter"]);
            assert_eq!(HELP.caps(), ["Ctrl", "/"]);
        }
    }

    #[test]
    fn dialog_toggles_and_blocks_other_keys_while_open() {
        let ctx = egui::Context::default();
        let mut dialog = ShortcutsDialog::default();
        let press = |key, modifiers| egui::RawInput {
            events: vec![egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers,
            }],
            ..Default::default()
        };
        ctx.run_ui(press(egui::Key::Slash, egui::Modifiers::COMMAND), |ui| {
            dialog.handle_keys(ui.ctx());
        })
        .textures_delta
        .clear();
        assert!(dialog.open);
        ctx.run_ui(press(egui::Key::ArrowDown, egui::Modifiers::NONE), |ui| {
            dialog.handle_keys(ui.ctx());
            assert!(
                ui.input(|i| i.events.is_empty()),
                "keys must not reach the screen"
            );
        })
        .textures_delta
        .clear();
        ctx.run_ui(press(egui::Key::Escape, egui::Modifiers::NONE), |ui| {
            dialog.handle_keys(ui.ctx());
        })
        .textures_delta
        .clear();
        assert!(!dialog.open);
    }
}
