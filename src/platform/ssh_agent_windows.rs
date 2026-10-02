//! Windows preview deliberately exposes no SSH agent endpoint.
use crate::{config::AppSettings, model::*};
use std::{path::Path, sync::mpsc};
#[derive(Clone)]
pub struct SshApprovalService;
impl SshApprovalService {
    pub fn new(_: mpsc::Sender<()>) -> Self {
        Self
    }
    pub fn active_request(&self) -> Option<SshApprovalRequest> {
        None
    }
    pub fn recent_status(&self) -> Option<SshApprovalStatus> {
        None
    }
    pub fn decide(&self, _: SshApprovalDecision) -> Result<SshApprovalStatus, String> {
        Err(unsupported())
    }
    pub fn clear_all(&self, _: &str) {}
}
#[derive(Clone)]
pub struct SshKeyStore;
impl SshKeyStore {
    pub fn new(_: mpsc::Sender<()>) -> Self {
        Self
    }
    pub fn set_unlocked(&self, _: Vec<SshKey>) {}
    pub fn set_locked(&self) {}
    pub fn cancel_unlock(&self) {}
}
pub struct SshAgentHandle;
impl SshAgentHandle {
    pub fn path(&self) -> &Path {
        Path::new("")
    }
    pub fn status(&self) -> SshAgentStatus {
        disabled_status()
    }
    pub fn stop(self) {}
}
fn unsupported() -> String {
    "SSH agent is unavailable in the Windows preview".into()
}
pub fn disabled_status() -> SshAgentStatus {
    SshAgentStatus {
        enabled: false,
        active: false,
        socket_path: String::new(),
        identity_count: 0,
        skipped_count: 0,
        message: unsupported(),
    }
}
pub fn waiting_for_unlock_status(_: &AppSettings) -> SshAgentStatus {
    disabled_status()
}
pub fn error_status(_: &AppSettings, _: impl Into<String>) -> SshAgentStatus {
    disabled_status()
}
pub fn prepared_key_counts(_: &[SshKey]) -> (usize, usize) {
    (0, 0)
}
pub fn start(
    _: &AppSettings,
    _: SshKeyStore,
    _: SshApprovalService,
) -> Result<SshAgentHandle, String> {
    Err(unsupported())
}
