use crate::{
    backend::AppBackend,
    shortcut::{Shortcut, Status},
    ui::{theme::theme, widgets},
};
use std::{sync::mpsc, time::Duration};
#[derive(Default)]
pub struct ShortcutSetup {
    pub open: bool,
    pub recording: bool,
    draft: Option<Shortcut>,
    status: Option<Status>,
    error: Option<String>,
    pending: Option<mpsc::Receiver<Reply>>,
    copied: bool,
}
enum Reply {
    Status(Result<Status, String>),
    Binding(Result<String, String>),
}
impl ShortcutSetup {
    pub fn open(&mut self) {
        self.open = true;
        self.status = None;
        self.error = None;
        self.recording = false;
    }
    fn request(&mut self, job: impl FnOnce() -> Reply + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        self.error = None;
        self.copied = false;
        std::thread::spawn(move || {
            let _ = tx.send(job());
        });
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
                break;
            }
            let shortcut = Shortcut {
                ctrl: modifiers.ctrl,
                alt: modifiers.alt,
                shift: modifiers.shift,
                super_key: self.draft.as_ref().is_some_and(|draft| draft.super_key),
                key: key.name().to_owned(),
            };
            self.error = shortcut.validate().err();
            self.draft = Some(shortcut);
            self.recording = false;
            break;
        }
    }
    pub fn show(&mut self, root: &mut egui::Ui, backend: &AppBackend) {
        let ctx = root.ctx().clone();
        self.capture(&ctx);
        if let Some(reply) = self.pending.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.pending = None;
            match reply {
                Reply::Status(Ok(status)) => {
                    self.draft = Some(status.selected.clone().unwrap_or(Shortcut {
                        ctrl: true,
                        alt: true,
                        key: "B".into(),
                        ..Default::default()
                    }));
                    self.status = Some(status);
                }
                Reply::Status(Err(error)) | Reply::Binding(Err(error)) => self.error = Some(error),
                Reply::Binding(Ok(text)) => {
                    ctx.copy_text(text);
                    self.copied = true;
                }
            }
        }
        if self.status.is_none() && self.pending.is_none() && self.error.is_none() {
            let backend = backend.clone();
            self.request(move || Reply::Status(backend.shortcut_status()));
        }
        if self.pending.is_none()
            && !self.recording
            && ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            self.open = false;
        }
        widgets::header(root, "shortcut-header", |ui| {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(self.pending.is_none(), egui::Button::new("Back"))
                    .clicked()
                {
                    self.open = false;
                    self.recording = false;
                }
                ui.heading("Quick access shortcut");
            });
        });
        egui::CentralPanel::default().frame(widgets::body_frame()).show(root, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.label("Show or hide quick access from any application.");
                ui.add_space(8.0);
                if let Some(status) = &self.status {
                    let current = status.selected.as_ref().map(Shortcut::label).unwrap_or_else(|| "None".into());
                    ui.label(format!("Current: {current}"));
                    ui.colored_label(if status.active { theme().success } else { theme().text_muted }, &status.message);
                }
                if let Some(error) = &self.error { ui.colored_label(theme().danger, error); }
                ui.add_space(8.0);
                let busy = self.pending.is_some();
                ui.add_enabled_ui(!busy, |ui| {
                    if let Some(draft) = &mut self.draft {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(draft.label()).strong());
                            if ui.button(if self.recording { "Cancel recording" } else { "Record shortcut" }).clicked() {
                                self.recording = !self.recording; self.error = None;
                            }
                        });
                        if self.recording { ui.label("Press your shortcut. Escape cancels recording."); }
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut draft.ctrl, "Ctrl"); ui.checkbox(&mut draft.alt, "Alt"); ui.checkbox(&mut draft.shift, "Shift");
                            #[cfg(not(windows))]
                            ui.checkbox(&mut draft.super_key, "Super");
                            egui::ComboBox::from_id_salt("shortcut-key").selected_text(&draft.key).show_ui(ui, |ui| {
                                for key in (b'A'..=b'Z').chain(b'0'..=b'9').map(|key| (key as char).to_string())
                                    .chain(std::iter::once("Space".into())).chain((1..=24).map(|n| format!("F{n}"))) {
                                    ui.selectable_value(&mut draft.key, key.clone(), key);
                                }
                            });
                        });
                        ui.small("If your desktop intercepts recording, use the modifier controls and key list.");
                        #[cfg(not(windows))]
                        ui.small("For Super combinations, select Super here before recording.");
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let valid = self.draft.as_ref().is_some_and(|draft| draft.validate().is_ok());
                        let supported = self.status.as_ref().is_some_and(|status| status.supported);
                        if ui.add_enabled(valid && supported && !self.recording, egui::Button::new("Apply shortcut")).clicked() {
                            let backend = backend.clone(); let value = self.draft.clone();
                            self.request(move || Reply::Status(backend.set_shortcut(value)));
                        }
                        if ui.add_enabled(supported && self.status.as_ref().is_some_and(|s| s.selected.is_some()), egui::Button::new("Clear shortcut")).clicked() {
                            self.recording = false; let backend = backend.clone();
                            self.request(move || Reply::Status(backend.set_shortcut(None)));
                        }
                        if ui.add_enabled(valid, egui::Button::new(if cfg!(windows) { "Copy command" } else { "Copy binding" })).clicked() {
                            let backend = backend.clone(); let value = self.draft.clone().unwrap();
                            self.request(move || Reply::Binding(backend.shortcut_binding(value)));
                        }
                    });
                });
                if busy { ui.spinner(); ctx.request_repaint_after(Duration::from_millis(50)); }
                if self.copied { ui.label("Copied to clipboard"); }
                ui.add_space(8.0);
                #[cfg(windows)]
                ui.label("Works while Boltwarden is running, including while the vault is locked. The installer can enable start at sign-in.");
                #[cfg(not(windows))]
                ui.label("Apply adds a Boltwarden binding file and an include to your Hyprland config, with a backup. Existing bindings are preserved. Clear removes only the managed shortcut. Other desktops can bind the command: boltwarden toggle");
            });
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recording_consumes_keys_without_applying_or_triggering_navigation() {
        let ctx = egui::Context::default();
        let mut state = ShortcutSetup {
            open: true,
            recording: true,
            ..Default::default()
        };
        let input = egui::RawInput {
            events: vec![egui::Event::Key {
                key: egui::Key::B,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers {
                    ctrl: true,
                    alt: true,
                    ..Default::default()
                },
            }],
            ..Default::default()
        };
        ctx.run_ui(input, |root| {
            state.capture(root.ctx());
            assert!(root.input(|i| i.events.is_empty()));
        })
        .textures_delta
        .clear();
        assert_eq!(state.draft.as_ref().unwrap().label(), "Ctrl+Alt+B");
        assert!(!state.recording);
        assert!(state.pending.is_none());
    }
}
