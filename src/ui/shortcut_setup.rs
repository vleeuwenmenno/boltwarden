//! The quick access shortcut as an inline settings row: Enter starts recording, the
//! next key combination is applied at once, and Backspace clears it.
use crate::{
    backend::AppBackend,
    shortcut::{MODIFIER_NAMES, Shortcut, Status},
    ui::{theme::theme, widgets},
};
use egui::{Response, Ui};
use std::{sync::mpsc, time::Duration};

#[derive(Default)]
pub struct ShortcutSetup {
    recording: bool,
    /// Linux desktops intercept Super, so it is added with a toggle while recording.
    include_super: bool,
    status: Option<Status>,
    error: Option<String>,
    notice: Option<&'static str>,
    pending: Option<mpsc::Receiver<Reply>>,
    queued: Option<Request>,
}

enum Request {
    Set(Option<Shortcut>),
    CopyBinding(Shortcut),
}

enum Reply {
    Status(Result<Status, String>),
    Binding(Result<String, String>),
}

impl ShortcutSetup {
    /// Starts recording, or copies the toggle command where the desktop cannot register
    /// shortcuts for us.
    pub fn activate(&mut self) {
        if self.pending.is_some() || self.queued.is_some() {
            return;
        }
        self.error = None;
        self.notice = None;
        if self.recording {
            self.recording = false;
            return;
        }
        match &self.status {
            Some(status) if !status.supported => {
                let shortcut = status.selected.clone().unwrap_or_else(default_shortcut);
                self.queued = Some(Request::CopyBinding(shortcut));
            }
            _ => self.recording = true,
        }
    }

    pub fn clear(&mut self) {
        let configured = self
            .status
            .as_ref()
            .is_some_and(|status| status.supported && status.selected.is_some());
        if configured && self.pending.is_none() && !self.recording {
            self.error = None;
            self.queued = Some(Request::Set(None));
        }
    }

    /// Runs first each frame: captures a shortcut being recorded before other key
    /// handling sees the keys, and exchanges requests with the daemon.
    pub fn poll(&mut self, ctx: &egui::Context, backend: &AppBackend) {
        self.capture(ctx);
        if let Some(reply) = self.pending.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.pending = None;
            match reply {
                Reply::Status(Ok(status)) => self.status = Some(status),
                Reply::Status(Err(error)) | Reply::Binding(Err(error)) => self.error = Some(error),
                Reply::Binding(Ok(text)) => {
                    ctx.copy_text(text);
                    self.notice = Some("Command copied; bind it in your desktop settings");
                }
            }
        }
        if self.pending.is_some() {
            ctx.request_repaint_after(Duration::from_millis(50));
            return;
        }
        let backend = backend.clone();
        let job: Box<dyn FnOnce() -> Reply + Send> = match self.queued.take() {
            Some(Request::Set(shortcut)) => {
                Box::new(move || Reply::Status(backend.set_shortcut(shortcut)))
            }
            Some(Request::CopyBinding(shortcut)) => {
                Box::new(move || Reply::Binding(backend.shortcut_binding(shortcut)))
            }
            None if self.status.is_none() && self.error.is_none() => {
                Box::new(move || Reply::Status(backend.shortcut_status()))
            }
            None => return,
        };
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(job());
        });
        ctx.request_repaint_after(Duration::from_millis(50));
    }

    fn capture(&mut self, ctx: &egui::Context) {
        if !self.recording {
            return;
        }
        let keys = ctx.input_mut(|input| {
            let keys: Vec<_> = input
                .events
                .iter()
                .filter_map(|event| match event {
                    egui::Event::Key {
                        key,
                        pressed: true,
                        repeat: false,
                        modifiers,
                        ..
                    } => Some((*key, *modifiers)),
                    _ => None,
                })
                .collect();
            input
                .events
                .retain(|event| !matches!(event, egui::Event::Key { .. } | egui::Event::Text(_)));
            keys
        });
        for (key, modifiers) in keys {
            if key == egui::Key::Escape {
                self.recording = false;
                return;
            }
            let shortcut = Shortcut {
                ctrl: modifiers.ctrl,
                alt: modifiers.alt,
                shift: modifiers.shift,
                super_key: if cfg!(target_os = "macos") {
                    modifiers.mac_cmd
                } else {
                    self.include_super
                },
                key: key.name().to_owned(),
            };
            // Modifiers arrive as keys of their own; keep recording until the main key.
            if shortcut.virtual_key().is_none() {
                continue;
            }
            self.recording = false;
            match shortcut.validate() {
                Ok(()) => self.queued = Some(Request::Set(Some(shortcut))),
                Err(error) => self.error = Some(error),
            }
            return;
        }
    }

    /// Footer hints for the shortcut row.
    pub fn hints(&self) -> &'static [(&'static str, &'static str)] {
        if self.recording {
            &[("Esc", "Cancel recording")]
        } else if self.status.as_ref().is_some_and(|status| !status.supported) {
            &[("↑↓", "Select"), ("⏎", "Copy command"), ("Esc", "Back")]
        } else {
            &[
                ("↑↓", "Select"),
                ("⏎", "Record"),
                ("⌫", "Clear"),
                ("Esc", "Back"),
            ]
        }
    }

    pub fn draw_row(&mut self, ui: &mut Ui, selected: bool) -> Response {
        let t = theme();
        let (rect, response) = widgets::row(ui, selected, widgets::ROW_HEIGHT + 4.0);
        let selected_shortcut = self.status.as_ref().and_then(|s| s.selected.as_ref());
        let value = selected_shortcut.map(Shortcut::label);
        response.widget_info(|| {
            let value = if self.recording {
                "Recording, press a shortcut".to_owned()
            } else {
                value.clone().unwrap_or_else(|| "Not set".into())
            };
            egui::WidgetInfo::labeled(
                egui::WidgetType::Button,
                ui.is_enabled(),
                format!("Quick access shortcut: {value}"),
            )
        });
        let painter = ui.painter_at(rect);
        // Recording pulses in the accent color until a combination is pressed.
        let pulse = if self.recording {
            ui.ctx().request_repaint();
            let time = ui.input(|input| input.time) as f32;
            0.55 + 0.45 * (time * 4.0).sin().abs()
        } else {
            1.0
        };
        if self.recording {
            painter.rect_stroke(
                rect.shrink(1.0),
                t.rounding,
                egui::Stroke::new(1.5_f32, t.accent.gamma_multiply(pulse)),
                egui::StrokeKind::Inside,
            );
        }
        painter.text(
            egui::pos2(rect.left() + 28.0, rect.center().y),
            egui::Align2::CENTER_CENTER,
            t.icon("\u{f11c}", "⌨"),
            t.font(t.body()),
            t.accent,
        );
        let left = rect.left() + 54.0;
        painter.text(
            egui::pos2(left, rect.top() + 7.0),
            egui::Align2::LEFT_TOP,
            "Quick access shortcut",
            t.font(t.body()),
            if selected {
                t.selected_text
            } else {
                t.text_strong
            },
        );
        let (description, color) = self.description();
        painter.text(
            egui::pos2(left, rect.bottom() - 7.0),
            egui::Align2::LEFT_BOTTOM,
            description,
            t.font(t.small()),
            color,
        );
        let right = rect.right() - 14.0;
        if self.recording {
            painter.text(
                egui::pos2(right, rect.center().y),
                egui::Align2::RIGHT_CENTER,
                "Press a shortcut…",
                t.font(t.body()),
                t.accent.gamma_multiply(pulse),
            );
        } else if let Some(shortcut) = selected_shortcut {
            let mut keys: Vec<&str> = [
                shortcut.ctrl,
                shortcut.alt,
                shortcut.shift,
                shortcut.super_key,
            ]
            .into_iter()
            .zip(MODIFIER_NAMES)
            .filter_map(|(pressed, name)| pressed.then_some(name))
            .collect();
            keys.push(&shortcut.key);
            widgets::keycaps(&painter, egui::pos2(right, rect.center().y), &keys);
        } else {
            painter.text(
                egui::pos2(right, rect.center().y),
                egui::Align2::RIGHT_CENTER,
                if self.status.is_some() {
                    "Not set"
                } else {
                    "…"
                },
                t.font(t.body()),
                t.text_faint,
            );
        }
        if self.recording && cfg!(target_os = "linux") {
            ui.horizontal(|ui| {
                ui.add_space(54.0);
                ui.checkbox(&mut self.include_super, "Add Super")
                    .on_hover_text("Desktops intercept Super while recording");
            });
        }
        response
    }

    fn description(&self) -> (&str, egui::Color32) {
        let t = theme();
        if let Some(error) = &self.error {
            (error, t.danger)
        } else if self.recording {
            ("Hold modifiers and press a key · Esc cancels", t.accent)
        } else if self.pending.is_some() || self.queued.is_some() {
            ("Saving…", t.text_muted)
        } else if let Some(notice) = self.notice {
            (notice, t.success)
        } else {
            match &self.status {
                Some(status) if !status.supported => (&status.message, t.text_muted),
                Some(status) if status.selected.is_some() && !status.active => {
                    (&status.message, t.warning)
                }
                _ => ("Show or hide quick access from any app", t.text_muted),
            }
        }
    }
}

fn default_shortcut() -> Shortcut {
    Shortcut {
        ctrl: true,
        alt: true,
        key: "B".into(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(
        ctx: &egui::Context,
        state: &mut ShortcutSetup,
        keys: &[egui::Key],
        modifiers: egui::Modifiers,
    ) {
        let input = egui::RawInput {
            events: keys
                .iter()
                .map(|key| egui::Event::Key {
                    key: *key,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers,
                })
                .collect(),
            ..Default::default()
        };
        ctx.run_ui(input, |root| {
            state.capture(root.ctx());
            assert!(
                root.input(|i| i.events.is_empty()),
                "recording must consume keys"
            );
        })
        .textures_delta
        .clear();
    }

    #[test]
    fn recording_waits_past_modifier_keys_and_queues_the_shortcut() {
        let ctx = egui::Context::default();
        let mut state = ShortcutSetup::default();
        state.activate();
        assert!(state.recording);
        let modifiers = egui::Modifiers {
            ctrl: true,
            shift: true,
            ..Default::default()
        };
        press(
            &ctx,
            &mut state,
            &[egui::Key::ControlLeft, egui::Key::ShiftLeft],
            modifiers,
        );
        assert!(state.recording, "a modifier alone must not end recording");
        press(&ctx, &mut state, &[egui::Key::B], modifiers);
        assert!(!state.recording);
        let Some(Request::Set(Some(shortcut))) = &state.queued else {
            panic!("the recorded shortcut should be applied");
        };
        let [ctrl, _, shift, _] = MODIFIER_NAMES;
        assert_eq!(shortcut.label(), format!("{ctrl}+{shift}+B"));
    }

    #[test]
    fn escape_cancels_recording_without_applying() {
        let ctx = egui::Context::default();
        let mut state = ShortcutSetup::default();
        state.activate();
        press(
            &ctx,
            &mut state,
            &[egui::Key::Escape],
            egui::Modifiers::NONE,
        );
        assert!(!state.recording);
        assert!(state.queued.is_none());
    }

    #[test]
    fn invalid_combination_reports_an_error() {
        let ctx = egui::Context::default();
        let mut state = ShortcutSetup::default();
        state.activate();
        press(&ctx, &mut state, &[egui::Key::B], egui::Modifiers::SHIFT);
        assert!(!state.recording);
        assert!(state.queued.is_none());
        assert!(state.error.is_some());
    }

    #[test]
    fn unsupported_desktop_copies_the_command_instead_of_recording() {
        let mut state = ShortcutSetup {
            status: Some(Status::unavailable("No shortcut service")),
            ..Default::default()
        };
        state.activate();
        assert!(!state.recording);
        assert!(matches!(state.queued, Some(Request::CopyBinding(_))));
    }
}
