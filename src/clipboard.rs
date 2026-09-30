use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const CLEAR_AFTER: Duration = Duration::from_secs(45);

/// Owns the foreground clipboard provider. Killing only this process relinquishes
/// our selection without overwriting text copied later from another application.
#[derive(Clone, Default)]
pub struct Clipboard(Arc<Mutex<ClipboardState>>);

#[derive(Default)]
struct ClipboardState {
    generation: u64,
    child: Option<Child>,
}

impl Clipboard {
    pub fn copy(&self, text: &str) -> Result<(), String> {
        let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
        let candidates: &[&[&str]] = if wayland {
            &[&["wl-copy", "--foreground", "--sensitive"]]
        } else {
            &[
                &["xclip", "-selection", "clipboard", "-quiet"],
                &["xsel", "--clipboard", "--input", "--nodetach"],
            ]
        };
        let mut slot = self.0.lock().map_err(|_| "Clipboard unavailable")?;
        let mut next = None;
        for command in candidates {
            if let Ok(child) = spawn_provider(command, text) {
                next = Some(child);
                break;
            }
        }
        let child = next.ok_or_else(|| {
            if wayland {
                "Could not copy. Install wl-clipboard and check the Wayland session.".to_string()
            } else {
                "Could not copy. Install xclip or xsel and check the X11 session.".to_string()
            }
        })?;
        stop_provider(&mut slot.child);
        slot.generation = slot.generation.wrapping_add(1);
        let generation = slot.generation;
        slot.child = Some(child);
        drop(slot);
        let clipboard = self.clone();
        std::thread::spawn(move || {
            std::thread::sleep(CLEAR_AFTER);
            clipboard.expire(generation);
        });
        Ok(())
    }

    fn expire(&self, generation: u64) {
        if let Ok(mut slot) = self.0.lock() {
            if slot.generation == generation {
                stop_provider(&mut slot.child);
            }
        }
    }

    pub fn clear(&self) {
        if let Ok(mut slot) = self.0.lock() {
            stop_provider(&mut slot.child);
        }
    }
}

fn stop_provider(slot: &mut Option<Child>) {
    if let Some(mut child) = slot.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn spawn_provider(command: &[&str], text: &str) -> Result<Child, ()> {
    let mut child = Command::new(command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let written = child
        .stdin
        .take()
        .is_some_and(|mut stdin| stdin.write_all(text.as_bytes()).is_ok());
    if !written {
        let _ = child.kill();
        let _ = child.wait();
        return Err(());
    }
    // Foreground providers stay alive while they own the selection.
    std::thread::sleep(Duration::from_millis(40));
    match child.try_wait() {
        Ok(None) => Ok(child),
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_expiry_preserves_new_provider_and_current_expiry_stops_it() {
        let child = Command::new("sleep").arg("10").spawn().unwrap();
        let clipboard = Clipboard(Arc::new(Mutex::new(ClipboardState {
            generation: 2,
            child: Some(child),
        })));
        clipboard.expire(1);
        assert!(
            clipboard
                .0
                .lock()
                .unwrap()
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none()
        );
        clipboard.expire(2);
        assert!(clipboard.0.lock().unwrap().child.is_none());
    }
}
