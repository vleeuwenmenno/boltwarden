//! Per-window Hyprland capture protection. Never change rules for other windows.
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn available() -> bool {
    std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some()
}

fn hyprctl(args: &[&str]) -> Result<String, String> {
    let mut child = Command::new("hyprctl")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not run hyprctl: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(match result {
                    Err(e) => format!("could not wait for hyprctl: {e}"),
                    _ => "hyprctl timed out".into(),
                });
            }
        }
    }
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("hyprctl could not change screen capture protection".into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub fn apply(obscure: bool) -> Result<(), String> {
    if !available() {
        return Err("screen capture protection requires Hyprland".into());
    }
    let window = format!("pid:{}", std::process::id());
    apply_to_window(obscure, &window, hyprctl)
}

fn apply_to_window(
    obscure: bool,
    window: &str,
    mut run: impl FnMut(&[&str]) -> Result<String, String>,
) -> Result<(), String> {
    // The startup worker may run before Wayland has mapped the native window.
    for attempt in 0..20 {
        let current = run(&["getprop", window, "no_screen_share"])?;
        if current == "true" || current == "false" {
            let desired = if obscure { "true" } else { "false" };
            // Set even if already equal, so later dynamic rules cannot override it.
            // Hyprland's Lua configuration uses structured dispatchers; older
            // Hyprlang configurations use the legacy dispatcher syntax.
            let lua = format!(
                "hl.dispatch(hl.dsp.window.set_prop({{window=\"{window}\", prop=\"no_screen_share\", value=\"{desired}\"}}))"
            );
            let applied = run(&["eval", &lua]);
            if !matches!(applied.as_deref(), Ok("ok")) {
                let result = run(&[
                    "dispatch",
                    "setprop",
                    &format!("{window} no_screen_share {desired}"),
                ])?;
                if result != "ok" {
                    return Err(result);
                }
            }
            if run(&["getprop", window, "no_screen_share"])? == desired {
                return Ok(());
            }
            return Err("Hyprland did not apply screen capture protection".into());
        }
        if current != "window not found" || attempt == 19 {
            return Err(format!(
                "cannot read this window's capture protection: {current}"
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise(
        obscure: bool,
        replies: Vec<Result<&str, &str>>,
    ) -> (Result<(), String>, Vec<Vec<String>>) {
        let mut replies = replies.into_iter();
        let mut calls = Vec::new();
        let result = apply_to_window(obscure, "pid:1234", |args| {
            calls.push(args.iter().map(|arg| arg.to_string()).collect());
            replies
                .next()
                .expect("unexpected compositor request")
                .map(str::to_owned)
                .map_err(str::to_owned)
        });
        assert!(replies.next().is_none());
        (result, calls)
    }

    #[test]
    fn lua_toggle_targets_only_the_popup_and_checks_readback() {
        for obscure in [false, true] {
            let desired = if obscure { "true" } else { "false" };
            let (result, calls) = exercise(obscure, vec![Ok("true"), Ok("ok"), Ok(desired)]);
            assert!(result.is_ok());
            assert_eq!(calls[0], ["getprop", "pid:1234", "no_screen_share"]);
            assert_eq!(calls[2], calls[0]);
            assert_eq!(calls[1][0], "eval");
            assert!(calls[1][1].contains("window=\"pid:1234\""));
            assert!(calls[1][1].contains(&format!("value=\"{desired}\"")));
        }
    }

    #[test]
    fn legacy_compositor_uses_legacy_dispatcher() {
        let (result, calls) = exercise(
            false,
            vec![Ok("true"), Err("no Lua config"), Ok("ok"), Ok("false")],
        );
        assert!(result.is_ok());
        assert_eq!(
            calls[2],
            ["dispatch", "setprop", "pid:1234 no_screen_share false"]
        );
    }

    #[test]
    fn successful_command_with_wrong_readback_is_an_error() {
        let (result, _) = exercise(true, vec![Ok("false"), Ok("ok"), Ok("false")]);
        assert!(result.is_err());
    }
}
