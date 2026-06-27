use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    pub locked: bool,
    pub idle: bool,
    pub idle_for: Option<Duration>,
}

pub fn current_session_state() -> Result<SessionState, String> {
    let session_id =
        current_session_id().ok_or_else(|| "could not determine session id".to_string())?;
    let output = Command::new("loginctl")
        .arg("show-session")
        .arg(session_id)
        .arg("--property=LockedHint")
        .arg("--property=IdleHint")
        .arg("--property=IdleSinceHintMonotonic")
        .output()
        .map_err(|e| format!("could not run loginctl: {e}"))?;

    if !output.status.success() {
        return Err("loginctl show-session failed".into());
    }

    let text = String::from_utf8(output.stdout)
        .map_err(|e| format!("loginctl returned invalid UTF-8: {e}"))?;
    Ok(parse_session_state(&text, monotonic_uptime()))
}

fn current_session_id() -> Option<String> {
    std::env::var("XDG_SESSION_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(loginctl_display_session)
        .or_else(loginctl_first_user_session)
}

fn loginctl_display_session() -> Option<String> {
    loginctl_show_user_value("Display")
}

fn loginctl_first_user_session() -> Option<String> {
    loginctl_show_user_value("Sessions").and_then(|value| {
        value
            .split_whitespace()
            .next()
            .map(|session| session.to_string())
    })
}

fn loginctl_show_user_value(property: &str) -> Option<String> {
    let user = std::env::var("USER").ok()?;
    let output = Command::new("loginctl")
        .arg("show-user")
        .arg(user)
        .arg(format!("--property={property}"))
        .arg("--value")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

pub fn parse_session_state(input: &str, uptime: Option<Duration>) -> SessionState {
    let mut locked = false;
    let mut idle = false;
    let mut idle_since_monotonic_micros = None;

    for line in input.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "LockedHint" => locked = parse_bool(value),
            "IdleHint" => idle = parse_bool(value),
            "IdleSinceHintMonotonic" => {
                idle_since_monotonic_micros = value.trim().parse::<u64>().ok();
            }
            _ => {}
        }
    }

    let idle_for = if idle {
        idle_duration(idle_since_monotonic_micros, uptime)
    } else {
        None
    };

    SessionState {
        locked,
        idle,
        idle_for,
    }
}

fn parse_bool(value: &str) -> bool {
    matches!(value.trim(), "yes" | "true" | "1")
}

fn idle_duration(idle_since_micros: Option<u64>, uptime: Option<Duration>) -> Option<Duration> {
    let idle_since = idle_since_micros?;
    if idle_since == 0 {
        return None;
    }
    let uptime = uptime?;
    let uptime_micros = uptime.as_micros().min(u128::from(u64::MAX)) as u64;
    uptime_micros
        .checked_sub(idle_since)
        .map(Duration::from_micros)
}

fn monotonic_uptime() -> Option<Duration> {
    let text = std::fs::read_to_string("/proc/uptime").ok()?;
    let seconds = text.split_whitespace().next()?.parse::<f64>().ok()?;
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    Some(Duration::from_secs_f64(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_locked_and_idle_session_state() {
        let state = parse_session_state(
            "LockedHint=yes\nIdleHint=yes\nIdleSinceHintMonotonic=1000000\n",
            Some(Duration::from_secs(61)),
        );

        assert!(state.locked);
        assert!(state.idle);
        assert_eq!(state.idle_for, Some(Duration::from_secs(60)));
    }

    #[test]
    fn inactive_session_has_no_idle_duration() {
        let state = parse_session_state(
            "LockedHint=no\nIdleHint=no\nIdleSinceHintMonotonic=1000000\n",
            Some(Duration::from_secs(61)),
        );

        assert!(!state.locked);
        assert!(!state.idle);
        assert_eq!(state.idle_for, None);
    }

    #[test]
    fn idle_duration_is_unknown_without_monotonic_timestamp() {
        let state = parse_session_state(
            "LockedHint=no\nIdleHint=yes\nIdleSinceHintMonotonic=0\n",
            Some(Duration::from_secs(61)),
        );

        assert!(state.idle);
        assert_eq!(state.idle_for, None);
    }
}
