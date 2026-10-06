//! macOS session monitoring is not implemented yet. Report it as unavailable so the
//! daemon keeps the vault locked whenever automatic locking is enabled.
use std::{
    sync::mpsc::{self, Receiver},
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    pub locked: bool,
    pub idle: bool,
    pub idle_for: Option<Duration>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum Event {
    State(SessionState),
    LockRequested(&'static str),
    Unavailable(String),
}

pub fn subscribe() -> Receiver<Event> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        while tx
            .send(Event::Unavailable("not supported on macOS yet".into()))
            .is_ok()
        {
            std::thread::sleep(Duration::from_secs(5));
        }
    });
    rx
}
