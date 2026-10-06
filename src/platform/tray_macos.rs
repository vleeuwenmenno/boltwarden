//! The macOS menu bar item is not implemented yet; the daemon runs without one.
use std::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TrayCommand {
    Show,
    Hide,
    Toggle,
    Window,
    Quit,
}

pub struct Handle;

pub fn spawn(_tx: mpsc::Sender<TrayCommand>) -> Result<Handle, String> {
    Err("not supported on macOS yet".into())
}
