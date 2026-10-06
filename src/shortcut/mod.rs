//! Global quick-access shortcuts are independent of vault data and preferences.
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, OnceLock, mpsc};
#[cfg(target_os = "linux")]
mod hyprland;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;
#[cfg(target_os = "linux")]
use hyprland::Runtime;
#[cfg(target_os = "macos")]
use macos::Runtime;
#[cfg(windows)]
use windows::Runtime;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Shortcut {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub super_key: bool,
    pub key: String,
}
impl Shortcut {
    pub fn validate(&self) -> Result<(), String> {
        if !self.ctrl && !self.alt && !self.super_key {
            return Err("Use Ctrl, Alt, or Super with the key".into());
        }
        if self.virtual_key().is_none() {
            return Err("Choose a letter, digit, Space, or F1–F24".into());
        }
        #[cfg(windows)]
        if self.super_key || self.key == "F12" {
            return Err(
                "Windows reserves Win combinations and F12; choose another shortcut".into(),
            );
        }
        Ok(())
    }
    pub fn virtual_key(&self) -> Option<u32> {
        let key = self.key.as_bytes();
        if key.len() == 1 && (key[0].is_ascii_uppercase() || key[0].is_ascii_digit()) {
            return Some(key[0] as u32);
        }
        if self.key == "Space" {
            return Some(0x20);
        }
        let number = self.key.strip_prefix('F')?.parse::<u32>().ok()?;
        ((1..=24).contains(&number) && self.key == format!("F{number}")).then(|| 0x70 + number - 1)
    }
    pub fn label(&self) -> String {
        let mut parts = Vec::new();
        if self.ctrl {
            parts.push("Ctrl");
        }
        if self.alt {
            parts.push("Alt");
        }
        if self.shift {
            parts.push("Shift");
        }
        if self.super_key {
            parts.push("Super");
        }
        parts.push(&self.key);
        parts.join("+")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub selected: Option<Shortcut>,
    pub active: bool,
    pub supported: bool,
    pub message: String,
}
impl Status {
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            selected: None,
            active: false,
            supported: false,
            message: message.into(),
        }
    }
}
struct Manager {
    runtime: Runtime,
    status: Status,
}
static MANAGER: OnceLock<Mutex<Manager>> = OnceLock::new();
const SETTINGS_FILE: &str = "quick-access-shortcut.json";

pub fn start(activate: mpsc::Sender<()>) {
    let selected = crate::config::config_path(SETTINGS_FILE)
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice::<Option<Shortcut>>(&bytes).ok())
        .flatten();
    let mut runtime = Runtime::new(activate);
    let mut status = Status {
        selected: selected.clone(),
        active: false,
        supported: runtime.supported(),
        message: "Not configured".into(),
    };
    if let Some(shortcut) = &selected {
        match shortcut
            .validate()
            .and_then(|_| runtime.apply(None, Some(shortcut)))
        {
            Ok(()) => {
                status.active = true;
                status.message = "Active".into();
            }
            Err(error) => status.message = error,
        }
    } else if !status.supported {
        status.message = runtime.unavailable_message();
    }
    let _ = MANAGER.set(Mutex::new(Manager { runtime, status }));
}
pub fn status() -> Status {
    #[allow(unused_mut)] // Hyprland status is refreshed from the compositor below.
    let mut status = MANAGER
        .get()
        .and_then(|manager| manager.lock().ok())
        .map(|manager| manager.status.clone())
        .unwrap_or_else(|| Status::unavailable("Shortcut service unavailable"));
    #[cfg(target_os = "linux")]
    if let Some(selected) = &status.selected {
        match Runtime.active(selected) {
            Ok(true) => {
                status.active = true;
                status.message = "Active".into();
            }
            Ok(false) => {
                status.active = false;
                status.message = "Not active in Hyprland; Apply to retry".into();
            }
            Err(error) => {
                status.active = false;
                status.message = error;
            }
        }
    }
    status
}
pub fn set(selected: Option<Shortcut>) -> Result<Status, String> {
    if let Some(shortcut) = &selected {
        shortcut.validate()?;
    }
    let mut manager = MANAGER
        .get()
        .ok_or("Shortcut service unavailable")?
        .lock()
        .map_err(|_| "Shortcut service unavailable")?;
    let previous = manager.status.selected.clone();
    manager
        .runtime
        .apply(previous.as_ref(), selected.as_ref())?;
    let saved = serde_json::to_vec(&selected)
        .map_err(|e| e.to_string())
        .and_then(|bytes| {
            crate::config::write_private(SETTINGS_FILE, &bytes).map_err(|e| e.to_string())
        });
    if let Err(error) = saved {
        let rollback = manager.runtime.apply(selected.as_ref(), previous.as_ref());
        if rollback.is_err() {
            manager.status.active = false;
            manager.status.message = "Shortcut rollback failed; restart Boltwarden".into();
        }
        return Err(format!("Could not save shortcut: {error}"));
    }
    manager.status.selected = selected;
    manager.status.active = manager.status.selected.is_some();
    manager.status.message = if manager.status.active {
        "Active"
    } else {
        "Not configured"
    }
    .into();
    Ok(manager.status.clone())
}

pub fn binding(shortcut: &Shortcut) -> Result<String, String> {
    shortcut.validate()?;
    #[cfg(target_os = "linux")]
    {
        hyprland::copy_binding(shortcut)
    }
    #[cfg(target_os = "macos")]
    {
        Err("Global shortcuts are not supported on macOS yet".into())
    }
    #[cfg(windows)]
    {
        Ok(format!(
            "\"{}\" toggle",
            std::env::current_exe()
                .map_err(|e| e.to_string())?
                .display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn restores_private_saved_shortcut_and_persists_clear() {
        crate::config::with_test_config(|_| {
            let shortcut = Shortcut {
                ctrl: true,
                alt: true,
                shift: true,
                key: "F22".into(),
                ..Default::default()
            };
            crate::config::write_private(SETTINGS_FILE, &serde_json::to_vec(&shortcut).unwrap())
                .unwrap();
            let (tx, _rx) = mpsc::channel();
            start(tx);
            let loaded = status();
            assert_eq!(loaded.selected.as_ref(), Some(&shortcut));
            assert!(loaded.active, "{}", loaded.message);
            let cleared = set(None).unwrap();
            assert!(!cleared.active);
            assert!(cleared.selected.is_none());
            let saved = std::fs::read(crate::config::config_path(SETTINGS_FILE).unwrap()).unwrap();
            assert_eq!(
                serde_json::from_slice::<Option<Shortcut>>(&saved).unwrap(),
                None
            );
        });
    }
    #[test]
    fn validates_modifiers_and_limits_keys_to_safe_names() {
        for key in ["A", "0", "Space", "F1", "F24"] {
            assert!(
                Shortcut {
                    ctrl: true,
                    key: key.into(),
                    ..Default::default()
                }
                .validate()
                .is_ok()
            );
        }
        for key in ["a", "F0", "F01", "F25", "B; exec bad", "A\nexec=bad"] {
            assert!(
                Shortcut {
                    ctrl: true,
                    key: key.into(),
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            Shortcut {
                shift: true,
                key: "A".into(),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
}
