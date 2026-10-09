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
    /// When a login's password last changed; unset if it never changed since creation.
    #[serde(default)]
    pub password_changed_at: Option<String>,
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
    /// Card or identity data; `None` for logins and secure notes.
    #[serde(default)]
    pub typed: Option<TypedDraft>,
}

/// Item types whose data is a fixed list of text fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TypedKind {
    Card,
    Identity,
}

/// One field of a card or identity, as the server stores it.
pub struct TypedField {
    /// Key inside the item's `card` or `identity` object.
    pub key: &'static str,
    pub label: &'static str,
    /// Masked until revealed.
    pub secret: bool,
}

const fn field(key: &'static str, label: &'static str, secret: bool) -> TypedField {
    TypedField { key, label, secret }
}

const CARD_FIELDS: [TypedField; 6] = [
    field("cardholderName", "Cardholder name", false),
    field("number", "Number", true),
    field("brand", "Brand", false),
    field("expMonth", "Expiry month", false),
    field("expYear", "Expiry year", false),
    field("code", "Security code", true),
];

const IDENTITY_FIELDS: [TypedField; 18] = [
    field("title", "Title", false),
    field("firstName", "First name", false),
    field("middleName", "Middle name", false),
    field("lastName", "Last name", false),
    field("username", "Username", false),
    field("company", "Company", false),
    field("email", "Email", false),
    field("phone", "Phone", false),
    field("address1", "Address 1", false),
    field("address2", "Address 2", false),
    field("address3", "Address 3", false),
    field("city", "City", false),
    field("state", "State / province", false),
    field("postalCode", "Postal code", false),
    field("country", "Country", false),
    field("ssn", "Social security number", true),
    field("passportNumber", "Passport number", true),
    field("licenseNumber", "License number", true),
];

impl TypedKind {
    pub const ALL: [Self; 2] = [Self::Card, Self::Identity];

    pub fn fields(self) -> &'static [TypedField] {
        match self {
            Self::Card => &CARD_FIELDS,
            Self::Identity => &IDENTITY_FIELDS,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Card => "Card",
            Self::Identity => "Identity",
        }
    }

    /// The server's cipher type.
    pub fn type_id(self) -> i64 {
        match self {
            Self::Card => 3,
            Self::Identity => 4,
        }
    }

    /// The top-level object that holds the fields.
    pub fn object_key(self) -> &'static str {
        match self {
            Self::Card => "card",
            Self::Identity => "identity",
        }
    }

    pub fn from_type_id(type_id: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.type_id() == type_id)
    }

    fn index(self, key: &str) -> Option<usize> {
        self.fields().iter().position(|field| field.key == key)
    }
}

/// Card or identity values, in the order of `kind.fields()`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TypedDraft {
    pub kind: TypedKind,
    pub values: Vec<String>,
}

impl TypedDraft {
    pub fn new(kind: TypedKind) -> Self {
        Self {
            kind,
            values: vec![String::new(); kind.fields().len()],
        }
    }

    pub fn get(&self, key: &str) -> &str {
        self.kind
            .index(key)
            .and_then(|idx| self.values.get(idx))
            .map_or("", String::as_str)
    }

    pub fn set(&mut self, key: &str, value: String) {
        if let Some(slot) = self
            .kind
            .index(key)
            .and_then(|idx| self.values.get_mut(idx))
        {
            use zeroize::Zeroize;
            slot.zeroize();
            *slot = value;
        }
    }

    /// Why the values can't be saved, if they can't.
    pub fn problem(&self) -> Option<&'static str> {
        if self.kind != TypedKind::Card {
            return None;
        }
        let month = self.get("expMonth").trim();
        if !month.is_empty() && !month.parse::<u8>().is_ok_and(|m| (1..=12).contains(&m)) {
            return Some("Expiry month must be a number from 1 to 12");
        }
        let year = self.get("expYear").trim();
        if !year.is_empty() && !(matches!(year.len(), 2 | 4) && year.parse::<u16>().is_ok()) {
            return Some("Expiry year must have 2 or 4 digits");
        }
        None
    }
}

/// The card brand for a number, by its issuer prefix, using the official clients' names.
pub fn card_brand(number: &str) -> Option<&'static str> {
    let digits = number
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>();
    if digits.len() < 2 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let prefix = |len: usize| digits.get(..len).and_then(|p| p.parse::<u32>().ok());
    let in_range =
        |len: usize, low: u32, high: u32| prefix(len).is_some_and(|p| (low..=high).contains(&p));
    Some(if digits.starts_with('4') {
        "Visa"
    } else if in_range(2, 34, 34) || in_range(2, 37, 37) {
        "Amex"
    } else if in_range(2, 51, 55) || in_range(4, 2221, 2720) {
        "Mastercard"
    } else if digits.starts_with("6011") || digits.starts_with("65") || in_range(3, 644, 649) {
        "Discover"
    } else if in_range(4, 3528, 3589) {
        "JCB"
    } else if in_range(3, 300, 305) || in_range(2, 36, 36) || in_range(2, 38, 39) {
        "Diners Club"
    } else if digits.starts_with("62") {
        "UnionPay"
    } else if in_range(2, 50, 50) || in_range(2, 56, 58) || digits.starts_with('6') {
        "Maestro"
    } else {
        return None;
    })
}

#[cfg(test)]
mod typed_tests {
    use super::*;

    #[test]
    fn detects_card_brands_by_prefix() {
        let cases = [
            ("4111 1111 1111 1111", Some("Visa")),
            ("5500-0000-0000-0004", Some("Mastercard")),
            ("2221000000000009", Some("Mastercard")),
            ("378282246310005", Some("Amex")),
            ("6011111111111117", Some("Discover")),
            ("3530111333300000", Some("JCB")),
            ("30569309025904", Some("Diners Club")),
            ("6200000000000005", Some("UnionPay")),
            ("6759649826438453", Some("Maestro")),
            ("9", None),
            ("abcd", None),
            ("", None),
        ];
        for (number, brand) in cases {
            assert_eq!(card_brand(number), brand, "{number}");
        }
    }

    #[test]
    fn validates_card_expiry_and_ignores_identities() {
        let card = |month: &str, year: &str| {
            let mut card = TypedDraft::new(TypedKind::Card);
            card.set("expMonth", month.into());
            card.set("expYear", year.into());
            card.problem()
        };
        assert_eq!(card("", ""), None);
        assert_eq!(card("04", "2030"), None);
        assert_eq!(card("12", "30"), None);
        assert!(card("0", "").is_some());
        assert!(card("13", "").is_some());
        assert!(card("", "203").is_some());
        assert!(card("", "20x0").is_some());
        assert_eq!(TypedDraft::new(TypedKind::Identity).problem(), None);
    }

    #[test]
    fn typed_values_follow_the_field_list() {
        let mut identity = TypedDraft::new(TypedKind::Identity);
        assert_eq!(identity.values.len(), TypedKind::Identity.fields().len());
        identity.set("city", "Utrecht".into());
        identity.set("unknown", "ignored".into());
        assert_eq!(identity.get("city"), "Utrecht");
        assert_eq!(identity.get("unknown"), "");
        assert_eq!(TypedKind::from_type_id(3), Some(TypedKind::Card));
        assert_eq!(TypedKind::from_type_id(1), None);
    }
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
    /// The terminal session that "remember" covers: the nearest shell above the client.
    #[serde(default)]
    pub session_pid: Option<u32>,
    #[serde(default)]
    pub session_name: Option<String>,
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
    /// The client's terminal session; see `SshAgentClientInfo::session_pid`.
    Session,
    Parent,
    CommandInCwd {
        duration_seconds: u64,
    },
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
    BreachedWebsites,
    ExposedPasswords,
    DataBreaches,
}

impl HealthCheck {
    pub const ALL: [Self; 10] = [
        Self::ExposedPasswords,
        Self::BreachedWebsites,
        Self::ReusedPasswords,
        Self::WeakPasswords,
        Self::UnsecuredWebsites,
        Self::Duplicates,
        Self::TwoFactorAvailable,
        Self::PasskeysAvailable,
        Self::DataBreaches,
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
            Self::BreachedWebsites => "Breached websites",
            Self::ExposedPasswords => "Exposed passwords",
            Self::DataBreaches => "Data breaches",
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
            Self::BreachedWebsites => {
                "These sites leaked passwords in a breach after you last changed yours. Change them."
            }
            Self::ExposedPasswords => {
                "These passwords appear in known data breaches. Change them everywhere you use them."
            }
            Self::DataBreaches => {
                "These sites leaked personal data, but no passwords. Watch for phishing and fraud."
            }
        }
    }

    /// Security problems, as opposed to suggestions such as adding a passkey.
    pub fn is_risk(self) -> bool {
        matches!(
            self,
            Self::ReusedPasswords
                | Self::WeakPasswords
                | Self::UnsecuredWebsites
                | Self::BreachedWebsites
                | Self::ExposedPasswords
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
    /// Share of those logins with no risk (reused, weak, unsecured, breached or
    /// exposed), 0..=100.
    pub score: u8,
    pub findings: Vec<(HealthCheck, Vec<String>)>,
    /// Why the two-factor and passkey checks are missing, if they are.
    pub directory_error: Option<String>,
    /// Why the breached websites check is missing, if it is.
    #[serde(default)]
    pub breach_error: Option<String>,
    /// The breaches behind the two breach checks, one entry per item and breach.
    #[serde(default)]
    pub breach_notes: Vec<BreachNote>,
    /// Whether the opt-in exposed passwords check is on.
    #[serde(default)]
    pub exposure_enabled: bool,
    /// Why some or all passwords could not be checked against known breaches.
    #[serde(default)]
    pub exposure_error: Option<String>,
}

/// A public website breach that affects one vault item.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BreachNote {
    pub item_id: String,
    pub title: String,
    /// `YYYY-MM-DD`
    pub date: String,
    /// What leaked, as Have I Been Pwned names it.
    pub data_classes: Vec<String>,
    pub exposed_passwords: bool,
}

impl HealthReport {
    pub fn breaches_for<'a>(&'a self, item_id: &'a str) -> impl Iterator<Item = &'a BreachNote> {
        self.breach_notes
            .iter()
            .filter(move |note| note.item_id == item_id)
    }

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
        if let Some(typed) = &mut self.typed {
            typed.zeroize();
        }
    }
}
impl zeroize::Zeroize for TypedDraft {
    fn zeroize(&mut self) {
        for value in &mut self.values {
            value.zeroize();
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
