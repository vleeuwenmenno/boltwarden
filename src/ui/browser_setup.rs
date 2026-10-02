//! Local native-host registration, shared by quick access and the full window.
use crate::browser::install::{self, BrowserFamily, BrowserRegistration};
use crate::config::{self, BrowserSetupPreferences};
use crate::ui::{theme::theme, widgets};
use egui::{RichText, Ui};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};

type SetupResult = Result<
    (
        Vec<BrowserRegistration>,
        BrowserSetupPreferences,
        Option<String>,
    ),
    String,
>;

pub struct BrowserSetupState {
    rows: Vec<BrowserRegistration>,
    selected: Vec<bool>,
    preferences: BrowserSetupPreferences,
    pending: Option<Receiver<SetupResult>>,
    initialized: bool,
    applying: bool,
    error: Option<String>,
    notice: Option<String>,
    cursor: usize,
    custom_open: bool,
    executable: String,
    directory: String,
    family: BrowserFamily,
}

impl Default for BrowserSetupState {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            selected: Vec::new(),
            preferences: Default::default(),
            pending: None,
            initialized: false,
            applying: false,
            error: None,
            notice: None,
            cursor: 0,
            custom_open: false,
            executable: String::new(),
            directory: String::new(),
            family: BrowserFamily::Chromium,
        }
    }
}

fn discover() -> SetupResult {
    let preferences = config::load_browser_setup().map_err(|e| e.to_string())?;
    let mut rows = install::discover().map_err(|e| e.to_string())?;
    for custom in &preferences.custom {
        let normalized = install::normalize_native_host_dir(&custom.native_host_dir)
            .map_err(|e| e.to_string())?;
        if rows.iter().any(|r| {
            install::normalize_native_host_dir(&r.native_host_dir)
                .ok()
                .as_ref()
                == Some(&normalized)
        }) {
            continue;
        }
        let mut row = custom.clone();
        row.native_host_dir = normalized;
        row.registered = install::is_registered(&row.native_host_dir).map_err(|e| e.to_string())?;
        rows.push(row);
    }
    Ok((rows, preferences, None))
}

impl BrowserSetupState {
    pub fn refresh(&mut self) {
        if self.pending.is_some() {
            return;
        }
        self.initialized = true;
        self.applying = false;
        self.error = None;
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(discover());
        });
    }

    fn apply(&mut self) {
        if self.pending.is_some() {
            return;
        }
        let choices: Vec<_> = self
            .rows
            .iter()
            .cloned()
            .zip(self.selected.iter().copied())
            .collect();
        let mut preferences = self.preferences.clone();
        preferences.configured = true;
        self.applying = true;
        self.error = None;
        self.notice = None;
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        std::thread::spawn(move || {
            let result = (|| {
                // Remember custom entries even when one registration needs correction.
                config::save_browser_setup(&preferences).map_err(|e| e.to_string())?;
                let mut errors = Vec::new();
                for (row, selected) in choices {
                    let result = if selected {
                        install::register(row.executable, row.family, row.native_host_dir)
                    } else {
                        install::unregister(row.native_host_dir)
                    };
                    if let Err(error) = result {
                        errors.push(format!("{}: {error}", row.label));
                    }
                }
                let warning = (!errors.is_empty())
                    .then(|| format!("Some changes could not be applied. {}", errors.join("; ")));
                let (rows, preferences, _) = discover()?;
                Ok((rows, preferences, warning))
            })();
            let _ = tx.send(result);
        });
    }

    fn poll(&mut self, ui: &Ui) {
        if !self.initialized {
            self.refresh();
        }
        let result = self.pending.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(value) => Some(value),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => Some(Err(
                "Browser setup stopped unexpectedly. Try refreshing.".into(),
            )),
        });
        if let Some(result) = result {
            self.pending = None;
            match result {
                Ok((rows, preferences, warning)) => {
                    self.selected = rows
                        .iter()
                        .map(|row| {
                            if warning.is_some() {
                                if let Some(index) = self
                                    .rows
                                    .iter()
                                    .position(|old| old.native_host_dir == row.native_host_dir)
                                {
                                    return self.selected[index];
                                }
                            }
                            row.registered || !preferences.configured
                        })
                        .collect();
                    self.error = warning;
                    self.rows = rows;
                    self.preferences = preferences;
                    self.cursor = self.cursor.min(self.rows.len().saturating_sub(1));
                    if self.applying && self.error.is_none() {
                        self.notice = Some(
                            "Browser setup saved. Open the extension to pair or reconnect.".into(),
                        );
                    }
                }
                Err(error) => self.error = Some(error),
            }
            self.applying = false;
        }
        if self.pending.is_some() {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(50));
        }
    }

    fn add_custom(&mut self) -> Result<(), String> {
        let executable = expand_path(&self.executable)?;
        let directory = install::normalize_native_host_dir(&expand_path(&self.directory)?)
            .map_err(|e| e.to_string())?;
        if !executable.is_file() {
            return Err("Choose an existing browser executable.".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(&executable)
                .map_err(|e| e.to_string())?
                .permissions()
                .mode()
                & 0o111
                == 0
            {
                return Err("The selected file is not executable.".into());
            }
        }
        if directory.exists() && !directory.is_dir() {
            return Err("Native-host location must be a directory.".into());
        }
        if self.rows.iter().any(|r| {
            install::normalize_native_host_dir(&r.native_host_dir)
                .ok()
                .as_ref()
                == Some(&directory)
        }) {
            return Err("This native-host folder is already listed. Select that browser above and click Apply.".into());
        }
        let label = executable
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let row = BrowserRegistration {
            id: format!("custom:{}", directory.display()),
            label,
            executable,
            family: self.family,
            registered: install::is_registered(&directory).map_err(|e| e.to_string())?,
            native_host_dir: directory,
        };
        self.preferences.custom.push(row.clone());
        self.rows.push(row);
        self.selected.push(true);
        self.cursor = self.rows.len() - 1;
        self.custom_open = false;
        self.executable.clear();
        self.error = None;
        self.notice =
            Some("Browser added to selection. Apply to enable its extension connection.".into());
        Ok(())
    }
}

fn expand_path(value: &str) -> Result<PathBuf, String> {
    let value = value.trim();
    let path = if let Some(rest) = value.strip_prefix("~/") {
        PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set")?).join(rest)
    } else {
        PathBuf::from(value)
    };
    if !path.is_absolute() {
        return Err("Use an absolute path or ~/path.".into());
    }
    if value.contains(['\n', '\r', '\0']) {
        return Err("Paths cannot contain control characters.".into());
    }
    Ok(path)
}

/// Only explicit Apply writes registrations. Disabling a registration does not revoke a paired session.
pub fn draw_browser_setup(ui: &mut Ui, state: &mut BrowserSetupState) {
    state.poll(ui);
    let t = theme();
    let busy = state.pending.is_some();
    if !busy && !state.custom_open {
        ui.input_mut(|input| {
            let count = state.rows.len();
            if count > 0 {
                if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                    state.cursor = (state.cursor + 1) % count;
                }
                if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                    state.cursor = (state.cursor + count - 1) % count;
                }
                if input.consume_key(egui::Modifiers::NONE, egui::Key::Space) {
                    state.selected[state.cursor] = !state.selected[state.cursor];
                }
            }
        });
    }
    ui.label(
        RichText::new("Choose browsers that can connect to Boltwarden.")
            .color(t.text_muted)
            .size(t.small()),
    );
    ui.label(
        RichText::new("To end existing access, revoke it in Paired browsers.")
            .color(t.text_muted)
            .size(t.small()),
    );
    ui.add_space(6.0);
    if let Some(error) = &state.error {
        widgets::error_line(ui, error);
    }
    if let Some(notice) = &state.notice {
        ui.label(RichText::new(notice).color(t.success).size(t.small()));
    }
    egui::ScrollArea::vertical()
        .id_salt("browser-setup-list")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_enabled_ui(!busy, |ui| {
                for (index, row) in state.rows.iter().enumerate() {
                    let description = if row.registered {
                        "Extension connection installed"
                    } else {
                        "Extension connection not installed"
                    };
                    let response = widgets::toggle_row(
                        ui,
                        state.cursor == index,
                        state.selected[index],
                        &row.label,
                        description,
                    )
                    .on_hover_text(format!(
                        "{}\n{}",
                        row.executable.display(),
                        row.native_host_dir.display()
                    ));
                    if response.clicked() {
                        state.selected[index] = !state.selected[index];
                        state.cursor = index;
                    }
                }
                if state.rows.is_empty() && !busy {
                    ui.label("No supported browsers detected. Add a browser below.");
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if widgets::button(ui, "Apply", true, !state.rows.is_empty()).clicked() {
                        state.apply();
                    }
                    if widgets::button(ui, "Refresh", false, true).clicked() {
                        state.refresh();
                    }
                    if widgets::button(ui, "Add browser", false, true).clicked() {
                        state.custom_open = !state.custom_open;
                        if state.directory.is_empty() {
                            state.directory = install::default_native_host_dir(state.family)
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_default();
                        }
                    }
                });
                if state.custom_open {
                    ui.add_space(12.0);
                    widgets::field_label(ui, "Browser executable");
                    let previous_executable = state.executable.clone();
                    widgets::text_input(
                        ui,
                        egui::Id::new("browser-setup-executable"),
                        &mut state.executable,
                        "/usr/bin/browser",
                        false,
                        t.body(),
                    );
                    if state.executable != previous_executable {
                        if let Ok(path) = expand_path(&state.executable) {
                            if let Some((family, directory)) = install::suggested_registration(&path) {
                                state.family = family;
                                state.directory = directory.to_string_lossy().into_owned();
                            }
                        }
                    }
                    let family_label = if state.family == BrowserFamily::Firefox {
                        "Firefox"
                    } else {
                        "Chromium"
                    };
                    if widgets::choice_row(
                        ui,
                        false,
                        "Browser family",
                        "Determines the native messaging manifest format",
                        family_label,
                    )
                    .clicked()
                    {
                        state.family = if state.family == BrowserFamily::Firefox {
                            BrowserFamily::Chromium
                        } else {
                            BrowserFamily::Firefox
                        };
                        state.directory = install::default_native_host_dir(state.family)
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default();
                    }
                    widgets::field_label(ui, "Native-host folder");
                    widgets::text_input(
                        ui,
                        egui::Id::new("browser-setup-directory"),
                        &mut state.directory,
                        "~/.config/browser/NativeMessagingHosts",
                        false,
                        t.body(),
                    );
                    ui.label(
                        RichText::new(
                            "Chromium: <user-data-dir>/NativeMessagingHosts, not Default or Profile 1.",
                        )
                        .size(t.small())
                        .color(t.text_muted),
                    );
                    if widgets::button(ui, "Add to selection", true, true).clicked()
                        && let Err(error) = state.add_custom()
                    {
                        state.error = Some(error);
                    }
                }
            });
            if busy {
                ui.add(egui::Spinner::new().color(t.text_muted));
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> BrowserSetupState {
        BrowserSetupState {
            initialized: true,
            rows: vec![BrowserRegistration {
                id: "test-browser".into(),
                label: "Test browser".into(),
                executable: "/usr/bin/browser".into(),
                family: BrowserFamily::Chromium,
                native_host_dir: "/tmp/boltwarden-test-browser/NativeMessagingHosts".into(),
                registered: false,
            }],
            selected: vec![true],
            ..Default::default()
        }
    }

    #[test]
    fn keyboard_selection_is_staged_until_apply() {
        let ctx = egui::Context::default();
        let mut state = state();
        let input = egui::RawInput {
            events: vec![egui::Event::Key {
                key: egui::Key::Space,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
            ..Default::default()
        };
        ctx.run_ui(input, |ui| draw_browser_setup(ui, &mut state))
            .textures_delta
            .clear();
        assert_eq!(state.selected, vec![false]);
        assert!(
            state.pending.is_none(),
            "Toggling must not write registrations before Apply"
        );
        assert!(!state.rows[0].registered);
    }

    #[test]
    fn custom_path_inputs_do_not_toggle_browser_rows() {
        let ctx = egui::Context::default();
        let mut state = state();
        state.custom_open = true;
        let input = egui::RawInput {
            events: vec![egui::Event::Key {
                key: egui::Key::Space,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
            ..Default::default()
        };
        ctx.run_ui(input, |ui| draw_browser_setup(ui, &mut state))
            .textures_delta
            .clear();
        assert_eq!(state.selected, vec![true]);
        assert!(state.pending.is_none());
    }

    #[test]
    fn invalid_custom_paths_are_not_added() {
        let mut state = state();
        state.executable = "relative/browser".into();
        state.directory = "/tmp/native-hosts".into();
        assert!(state.add_custom().is_err());
        assert!(state.preferences.custom.is_empty());
        assert_eq!(state.rows.len(), 1);
        assert!(expand_path("/tmp/path\nwith-newline").is_err());
    }
}
