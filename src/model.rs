#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BwItem {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub folder: Option<String>,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    pub item_type: String,
    /// Public hostname of the item's first website, used to look up its icon.
    #[serde(default)]
    pub icon_host: Option<String>,
    #[serde(default)]
    pub state: ItemState,
    #[serde(default)]
    pub dates: ItemDates,
}

/// Server timestamps (ISO 8601 UTC, so they sort as strings) used to order the archived
/// and trash lists.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ItemDates {
    /// When the item was archived or trashed, for items in those states.
    #[serde(default)]
    pub state_changed_at: Option<String>,
    #[serde(default)]
    pub revision_date: Option<String>,
    #[serde(default)]
    pub creation_date: Option<String>,
}

/// Where an item lives in the vault. A trashed item that was also archived counts as
/// deleted: it only shows up under "Recently deleted".
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum ItemState {
    #[default]
    Active,
    Archived,
    Deleted,
}

/// A change to an item's place in the vault. Editing its contents goes through `ItemDraft`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ItemAction {
    Archive,
    Unarchive,
    Trash,
    Restore,
    DeleteForever,
    Favorite,
    Unfavorite,
}

impl ItemAction {
    /// Short past-tense status line shown after the action succeeds.
    pub fn done_message(self) -> &'static str {
        match self {
            Self::Archive => "Archived",
            Self::Unarchive => "Moved back to the vault",
            Self::Trash => "Moved to trash",
            Self::Restore => "Restored",
            Self::DeleteForever => "Deleted permanently",
            Self::Favorite => "Added to favorites",
            Self::Unfavorite => "Removed from favorites",
        }
    }
}

/// Editable plaintext copy of an item. `original_index` ties a row back to the entry it
/// came from, so renames keep the entry and its extra settings (URI match, linked id).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ItemDraft {
    pub name: String,
    pub notes: String,
    pub login: Option<LoginDraft>,
    pub fields: Vec<DraftField>,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favorite: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoginDraft {
    pub username: String,
    pub password: String,
    pub totp: String,
    pub uris: Vec<DraftUri>,
    /// Passkeys can't be created or changed here, only removed.
    #[serde(default)]
    pub passkeys: Vec<DraftPasskey>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DraftPasskey {
    pub passkey: Passkey,
    pub original_index: usize,
}

/// What the UI shows of a stored passkey. The private key never leaves the daemon.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Passkey {
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub creation_date: Option<String>,
}

impl Passkey {
    /// "alice on example.com", for field rows and confirmations.
    pub fn describe(&self) -> String {
        let site = self
            .rp_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(&self.rp_id);
        match self
            .user_name
            .as_deref()
            .or(self.user_display_name.as_deref())
            .filter(|user| !user.is_empty())
        {
            Some(user) => format!("{user} on {site}"),
            None => site.to_string(),
        }
    }
}

/// A vault folder. Bitwarden nests folders by name: "Work/Servers" sits inside "Work".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Folder {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DraftUri {
    pub uri: String,
    pub original_index: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DraftField {
    pub name: String,
    pub value: String,
    pub kind: DraftFieldKind,
    pub original_index: Option<usize>,
}

/// Bitwarden custom field types 0..=3. Linked fields point at another field of the item
/// and have no value of their own, so the editor only lets you rename them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DraftFieldKind {
    Text,
    Hidden,
    Boolean,
    Linked,
}

impl DraftFieldKind {
    pub fn from_type(field_type: i64) -> Self {
        match field_type {
            1 => Self::Hidden,
            2 => Self::Boolean,
            3 => Self::Linked,
            _ => Self::Text,
        }
    }

    pub fn type_id(self) -> i64 {
        match self {
            Self::Text => 0,
            Self::Hidden => 1,
            Self::Boolean => 2,
            Self::Linked => 3,
        }
    }
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
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub passkeys: Vec<Passkey>,
    pub item_type: String,
    pub ssh_key: Option<SshKey>,
    #[serde(default)]
    pub state: ItemState,
    #[serde(default)]
    pub dates: ItemDates,
}

/// A generated TOTP code plus the time step it belongs to, so the UI can show the real
/// remaining validity and refresh exactly when the step rolls over.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TotpCode {
    pub code: String,
    pub period: u64,
    pub step: u64,
}

impl TotpCode {
    pub fn seconds_remaining(&self, now_unix: u64) -> u64 {
        self.period - now_unix % self.period
    }

    pub fn is_current(&self, now_unix: u64) -> bool {
        now_unix / self.period == self.step
    }
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
    CommandInCwd { duration_seconds: u64 },
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
    #[serde(default)]
    pub offline: bool,
    #[serde(default)]
    pub cache_synced_unix: Option<u64>,
    #[serde(default)]
    pub last_synced_unix: Option<u64>,
    pub server_ciphers: usize,
    pub decrypted_items: usize,
    pub skipped_items: usize,
    pub first_error: Option<String>,
}

impl SyncStatus {
    pub fn offline_tooltip(&self) -> String {
        let age = self
            .cache_synced_unix
            .map(|at| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let minutes = now.saturating_sub(at) / 60;
                if minutes >= 1440 {
                    format!("{} d ago", minutes / 1440)
                } else if minutes >= 60 {
                    format!("{} h ago", minutes / 60)
                } else {
                    format!("{minutes} min ago")
                }
            })
            .unwrap_or_else(|| "unknown time".into());
        format!("Offline · copy from {age} · Ctrl+R to retry")
    }
}

/// One kind of problem the action center looks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HealthCheck {
    ReusedPasswords,
    WeakPasswords,
    UnsecuredWebsites,
    Duplicates,
    Expiring,
    TwoFactorAvailable,
    PasskeysAvailable,
}

impl HealthCheck {
    pub const ALL: [Self; 7] = [
        Self::ReusedPasswords,
        Self::WeakPasswords,
        Self::UnsecuredWebsites,
        Self::Duplicates,
        Self::TwoFactorAvailable,
        Self::PasskeysAvailable,
        Self::Expiring,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::ReusedPasswords => "Reused passwords",
            Self::WeakPasswords => "Weak passwords",
            Self::UnsecuredWebsites => "Unsecured websites",
            Self::Duplicates => "Duplicate items",
            Self::Expiring => "Expiring items",
            Self::TwoFactorAvailable => "Two-factor authentication",
            Self::PasskeysAvailable => "Passkeys available",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::ReusedPasswords => {
                "The same password is used by more than one login. Give each site its own."
            }
            Self::WeakPasswords => "These passwords are easy to guess. Generate strong ones.",
            Self::UnsecuredWebsites => {
                "Websites saved with http:// send your login unencrypted. Switch them to https://."
            }
            Self::Duplicates => {
                "Logins with the same website, username and password. Delete the extra copies."
            }
            Self::Expiring => "Cards that have expired or expire within 30 days.",
            Self::TwoFactorAvailable => {
                "These sites offer two-factor authentication, but no one-time code is saved."
            }
            Self::PasskeysAvailable => {
                "These sites support passkeys, a phishing-resistant alternative to passwords."
            }
        }
    }

    /// Security problems, as opposed to suggestions such as adding a passkey.
    pub fn is_risk(self) -> bool {
        matches!(
            self,
            Self::ReusedPasswords | Self::WeakPasswords | Self::UnsecuredWebsites
        )
    }
}

/// Vault health for the action center. Holds item ids only, never secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HealthReport {
    /// Active logins that have a password.
    pub passwords: usize,
    /// How many passwords got each strength score, from 0 (very weak) to 4 (strong).
    pub strength: [usize; 5],
    /// Share of those logins with no risk (reused, weak or unsecured), 0..=100.
    pub score: u8,
    pub findings: Vec<(HealthCheck, Vec<String>)>,
    /// Why the two-factor and passkey checks are missing, if they are.
    pub directory_error: Option<String>,
}

impl HealthReport {
    pub fn items(&self, check: HealthCheck) -> &[String] {
        self.findings
            .iter()
            .find(|(kind, _)| *kind == check)
            .map(|(_, ids)| ids.as_slice())
            .unwrap_or(&[])
    }
}

impl BwItemDetail {
    /// Bind a copy request to the exact item shown, including field ordering.
    pub fn copy_version(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let encoded = zeroize::Zeroizing::new(serde_json::to_vec(self).expect("serializable item"));
        Sha256::digest(encoded.as_slice()).into()
    }

    pub fn copy_value_checked(&self, index: usize, version: &[u8; 32]) -> Result<String, String> {
        if &self.copy_version() != version {
            return Err("Item changed. Reopen it before copying.".into());
        }
        self.copy_value(index)
    }

    /// The same field ordering used by the detail view. TOTP is generated at copy time.
    pub fn copy_value(&self, index: usize) -> Result<String, String> {
        enum Source<'a> {
            Value(&'a str),
            Totp,
            Passkey,
        }
        let mut values = Vec::new();
        if let Some(value) = &self.username {
            values.push(Source::Value(value));
        }
        if let Some(value) = &self.password {
            values.push(Source::Value(value));
        }
        if self.totp.is_some() {
            values.push(Source::Totp);
        }
        values.extend(self.passkeys.iter().map(|_| Source::Passkey));
        values.extend(self.uris.iter().map(|s| Source::Value(s)));
        if let Some(key) = &self.ssh_key {
            values.push(Source::Value(&key.public_key));
            if let Some(value) = &key.fingerprint {
                values.push(Source::Value(value));
            }
            values.push(Source::Value(&key.private_key));
        }
        values.extend(self.custom_fields.iter().map(|f| Source::Value(&f.value)));
        if let Some(value) = &self.notes {
            values.push(Source::Value(value));
        }
        match values.get(index) {
            Some(Source::Value(value)) => Ok((*value).to_owned()),
            Some(Source::Totp) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_secs();
                crate::bw::generate_totp(self.totp.as_deref().ok_or("No TOTP secret")?, now)
                    .map(|code| code.code)
                    .map_err(|e| e.to_string())
            }
            Some(Source::Passkey) => Err("Passkeys can't be copied".into()),
            None => Err("Field is no longer available".into()),
        }
    }
}

impl zeroize::Zeroize for BwItemDetail {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.uris.zeroize();
        self.totp.zeroize();
        self.notes.zeroize();
        self.folder.zeroize();
        for field in &mut self.custom_fields {
            field.name.zeroize();
            field.value.zeroize();
        }
        if let Some(key) = &mut self.ssh_key {
            key.private_key.zeroize();
        }
    }
}
impl zeroize::Zeroize for ItemDraft {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.notes.zeroize();
        if let Some(login) = &mut self.login {
            login.zeroize();
        }
        for field in &mut self.fields {
            field.name.zeroize();
            field.value.zeroize();
        }
    }
}
impl zeroize::Zeroize for LoginDraft {
    fn zeroize(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.totp.zeroize();
        for uri in &mut self.uris {
            uri.uri.zeroize();
        }
    }
}

impl Drop for SshKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key.zeroize();
    }
}
