//! Global shortcuts are not implemented on macOS yet.
use super::Shortcut;
use std::sync::mpsc;

pub struct Runtime;
impl Runtime {
    pub fn new(_activate: mpsc::Sender<()>) -> Self {
        Self
    }
    pub fn supported(&self) -> bool {
        false
    }
    pub fn unavailable_message(&self) -> String {
        "Global shortcuts are not supported on macOS yet".into()
    }
    pub fn apply(&mut self, _: Option<&Shortcut>, _: Option<&Shortcut>) -> Result<(), String> {
        Err(self.unavailable_message())
    }
}
