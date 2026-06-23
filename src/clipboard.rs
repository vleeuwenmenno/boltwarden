use std::io::Write;
use std::process::Stdio;

pub fn copy(text: &str) -> bool {
    // Try wl-copy first (Wayland)
    if let Ok(mut child) = std::process::Command::new("wl-copy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
            let _ = stdin.flush();
        }
        if child.wait().is_ok() {
            return true;
        }
    }

    // Fallback: xclip
    if let Ok(mut child) = std::process::Command::new("xclip")
        .arg("-selection")
        .arg("clipboard")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
            let _ = stdin.flush();
        }
        if child.wait().is_ok() {
            return true;
        }
    }

    // Fallback: xsel
    if let Ok(mut child) = std::process::Command::new("xsel")
        .arg("--clipboard")
        .arg("--input")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
            let _ = stdin.flush();
        }
        if child.wait().is_ok() {
            return true;
        }
    }

    false
}
