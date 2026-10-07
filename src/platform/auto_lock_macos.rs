//! Session monitoring by polling: CoreGraphics reports screen lock and input idle time
//! without any privacy permission. A sleep shows up as wall-clock time that passed while
//! the monotonic clock, which stops during sleep on macOS, did not.
use objc2_core_foundation::{CFBoolean, CFDictionary, CFString};
use objc2_core_graphics::{
    CGEventSource, CGEventSourceStateID, CGEventType, CGSessionCopyCurrentDictionary,
};
use std::{
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant, SystemTime},
};

const POLL: Duration = Duration::from_secs(2);
/// Wall-clock time beyond the monotonic clock that counts as a system sleep.
const SLEEP_GAP: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    pub locked: bool,
    pub idle: bool,
    pub idle_for: Option<Duration>,
}

#[derive(Debug)]
pub enum Event {
    State(SessionState),
    LockRequested(&'static str),
    Unavailable(String),
}

fn screen_locked() -> Result<bool, String> {
    let session = CGSessionCopyCurrentDictionary()
        .ok_or_else(|| "no macOS login session for this process".to_string())?;
    let key = CFString::from_static_str("CGSSessionScreenIsLocked");
    // The key is present only while the screen is locked.
    let value = unsafe { CFDictionary::value(&session, (&*key as *const CFString).cast()) };
    if value.is_null() {
        return Ok(false);
    }
    Ok(unsafe { &*value.cast::<CFBoolean>() }.as_bool())
}

fn idle_for() -> Duration {
    // kCGAnyInputEventType: the most recent keyboard, mouse or tablet event.
    let any_input = CGEventType(u32::MAX);
    let seconds = CGEventSource::seconds_since_last_event_type(
        CGEventSourceStateID::HIDSystemState,
        any_input,
    );
    Duration::try_from_secs_f64(seconds).unwrap_or_default()
}

fn state() -> Result<SessionState, String> {
    let idle_for = idle_for();
    Ok(SessionState {
        locked: screen_locked()?,
        idle: idle_for >= POLL,
        idle_for: Some(idle_for),
    })
}

/// True when more wall-clock than monotonic time passed between two polls.
fn slept(since: (Instant, SystemTime)) -> bool {
    let monotonic = since.0.elapsed();
    let wall = since.1.elapsed().unwrap_or_default();
    wall.saturating_sub(monotonic) >= SLEEP_GAP
}

pub fn subscribe() -> Receiver<Event> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut last = (Instant::now(), SystemTime::now());
        loop {
            if slept(last) && tx.send(Event::LockRequested("system sleep")).is_err() {
                break;
            }
            last = (Instant::now(), SystemTime::now());
            let event = match state() {
                Ok(state) => Event::State(state),
                Err(error) => Event::Unavailable(error),
            };
            if tx.send(event).is_err() {
                break;
            }
            std::thread::sleep(POLL);
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_clock_jump_beyond_monotonic_time_counts_as_sleep() {
        let now = (Instant::now(), SystemTime::now());
        assert!(!slept(now));
        let before_sleep = (Instant::now(), SystemTime::now() - Duration::from_secs(60));
        assert!(slept(before_sleep));
    }

    #[test]
    fn reports_idle_time_for_this_session() {
        // A test runner without a login session (for example over SSH) has no lock state.
        if let Ok(state) = state() {
            assert!(state.idle_for.is_some());
        }
    }
}
