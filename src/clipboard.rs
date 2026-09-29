use std::io::Write;
use std::process::{Command, Stdio};

/// Copies `text` to the clipboard, marked as sensitive so clipboard managers (including
/// Omarchy's clipboard history) skip it. The value goes through stdin, never argv.
pub fn copy(text: &str) -> bool {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let candidates: &[&[&str]] = if wayland {
        &[&["wl-copy", "--sensitive"]]
    } else {
        // x-kde-passwordManagerHint is the convention KDE Klipper and most X11 clipboard
        // managers honor, but xclip can only offer one target, so it cannot carry the hint.
        &[
            &["xclip", "-selection", "clipboard"],
            &["xsel", "--clipboard", "--input"],
        ]
    };
    candidates
        .iter()
        .any(|command| run_with_stdin(command, text))
}

fn run_with_stdin(command: &[&str], text: &str) -> bool {
    let Ok(mut child) = Command::new(command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    // Scope the pipe so it closes before wait(); the tool reads until EOF.
    let written = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(text.as_bytes()).is_ok(),
        None => false,
    };
    matches!(child.wait(), Ok(status) if status.success()) && written
}
