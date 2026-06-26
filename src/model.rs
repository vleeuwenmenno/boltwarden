#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BwItem {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub folder: Option<String>,
    pub item_type: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    pub hidden: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BwItemDetail {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uris: Vec<String>,
    pub totp: Option<String>,
    pub notes: Option<String>,
    pub custom_fields: Vec<CustomField>,
    pub folder: Option<String>,
    pub item_type: String,
    pub ssh_key: Option<SshKey>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SshKey {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub private_key: String,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshAgentClientInfo {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub ppid: Option<u32>,
    pub start_time_ticks: Option<u64>,
    pub process_name: Option<String>,
    pub command_line: Option<String>,
    pub executable: Option<String>,
    pub cwd: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub parent_start_time_ticks: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SshApprovalKind {
    Sign,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshApprovalRequest {
    pub id: String,
    pub kind: SshApprovalKind,
    pub key_id: String,
    pub key_name: String,
    pub public_key: String,
    pub fingerprint: Option<String>,
    pub algorithm: String,
    pub client: SshAgentClientInfo,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SshApprovalRemember {
    Once,
    Process,
    Parent,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshApprovalDecision {
    pub request_id: String,
    pub approved: bool,
    pub remember: SshApprovalRemember,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SshApprovalStatusKind {
    Pending,
    Approved,
    Denied,
    TimedOut,
    AutoApproved,
    Cleared,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshApprovalStatus {
    pub request_id: String,
    pub key_name: String,
    pub process_name: Option<String>,
    pub kind: SshApprovalStatusKind,
    pub message: String,
    pub at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshAgentStatus {
    pub enabled: bool,
    pub active: bool,
    pub socket_path: String,
    pub identity_count: usize,
    pub skipped_count: usize,
    pub message: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncStatus {
    pub server_ciphers: usize,
    pub decrypted_items: usize,
    pub skipped_items: usize,
    pub first_error: Option<String>,
}
