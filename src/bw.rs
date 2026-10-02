use crate::config;
use crate::config::{SavedKdf, SavedSession};
use crate::model::{
    BwItem, BwItemDetail, CustomField, DraftField, DraftFieldKind, DraftPasskey, DraftUri, Folder,
    HealthReport, ItemAction, ItemDates, ItemDraft, ItemState, LoginDraft, Passkey, SshKey,
    SyncStatus, TotpCode,
};
use crate::uri_match::{self, LoginUri, UriMatchType};
use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use reqwest::Method;
use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

const HTTP_TIMEOUT: Duration = Duration::from_secs(12);
const CLIENT_NAME: &str = "boltwarden";
// Vaultwarden gates newer cipher types, including SSH keys, on this Bitwarden client header.
const SYNC_COMPAT_CLIENT_VERSION: &str = "2024.12.0";
// Official clients keep this many old passwords per login.
const PASSWORD_HISTORY_LIMIT: usize = 5;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

#[derive(Clone)]
pub struct BwClient {
    email: Option<String>,
    raw_profile: Option<Value>,
    raw_folders: Vec<Value>,
    undecodable_ciphers: Vec<Value>,
    retry_seconds: u64,
    client: Client,
    reauth: Option<(String, SavedKdf, String)>,
    /// Established only by a completed password unlock of this in-memory session.
    verified_unlock: bool,
    item_grants: HashMap<String, Instant>,
    base_url: String,
    device_identifier: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    user_key: Option<Vec<u8>>,
    items: Vec<BwItemDetail>,
    /// Encrypted source of every item in `items`, needed to write changes back without
    /// dropping the fields this app does not understand.
    ciphers: HashMap<String, StoredCipher>,
    folders: HashMap<String, String>,
    organization_keys: HashMap<String, Vec<u8>>,
    sync_warning: Option<String>,
    sync_status: SyncStatus,
    last_sync_attempt: Option<Instant>,
    /// The last action center report and the vault state it was computed for. Strength
    /// checks are slow enough to matter on every sync of a big vault.
    health_cache: Option<(u64, HealthReport)>,
}

#[derive(Clone)]
struct StoredCipher {
    raw: Value,
    item_key: Vec<u8>,
    revision_date: Option<String>,
    /// Matching rules stay in the daemon, rather than the desktop item RPC model.
    browser_uris: Vec<LoginUri>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BrowserMatchSummary {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub revision: String,
    pub reprompt: bool,
    pub insecure_downgrade: bool,
}

/// Selection metadata only; private key material never enters an RPC item model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeySummary {
    pub requires_password: bool,
    pub id: String,
    pub credential_id: String,
    pub revision: String,
    pub name: String,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
}

/// Daemon-owned evidence after explicit consent for this passkey operation.
/// Reusing a verified vault unlock never satisfies an item's fresh-password rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyVerificationEvidence {
    None,
    FreshPassword,
    VaultUnlock,
}

impl PasskeyVerificationEvidence {
    fn verified(self) -> bool {
        self != Self::None
    }
}

struct PasskeyMaterial {
    credential_id: Vec<u8>,
    user_handle: Option<Vec<u8>>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    discoverable: bool,
    pkcs8_der: Zeroizing<Vec<u8>>,
}

/// The only plaintext fields the fill protocol may return. Never include an item
/// detail, TOTP seed, custom fields, notes, or passkey key material.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct BrowserCredentials {
    pub username: Option<String>,
    pub password: Option<String>,
    pub insecure_downgrade: bool,
}

impl std::fmt::Debug for BrowserCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserCredentials")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("insecure_downgrade", &self.insecure_downgrade)
            .finish()
    }
}

impl Drop for BrowserCredentials {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Debug)]
pub enum BwError {
    NotUnlocked,
    RepromptRequired,
    TwoFactorRequired(TwoFactorChallenge),
    Network(String),
    Cli(String),
    Parse(String),
    NotFound,
}

impl std::fmt::Display for BwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BwError::RepromptRequired => write!(f, "Master password required for this item"),
            BwError::NotUnlocked => write!(f, "vault is not unlocked"),
            BwError::TwoFactorRequired(_) => write!(f, "two factor required"),
            BwError::Network(s) | BwError::Cli(s) => write!(f, "{s}"),
            BwError::Parse(s) => write!(f, "parse error: {s}"),
            BwError::NotFound => write!(f, "not found"),
        }
    }
}

impl std::error::Error for BwError {}

#[derive(Clone)]
pub struct TwoFactorChallenge {
    base_url: String,
    device_identifier: String,
    email: String,
    password: String,
    password_hash: String,
    master_key: Vec<u8>,
    kdf: SavedKdf,
    remember: bool,
    providers: Vec<TwoFactorProvider>,
}

impl std::fmt::Debug for TwoFactorChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorChallenge")
            .field("base_url", &self.base_url)
            .field("device_identifier", &self.device_identifier)
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("password_hash", &"<redacted>")
            .field("master_key", &"<redacted>")
            .field("kdf", &self.kdf)
            .field("remember", &self.remember)
            .field("providers", &self.providers)
            .finish()
    }
}

impl TwoFactorChallenge {
    pub fn providers(&self) -> &[TwoFactorProvider] {
        &self.providers
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoFactorProvider {
    Authenticator,
    Email,
    Duo,
    Yubikey,
    Remember,
    OrganizationDuo,
    WebAuthn,
    RecoveryCode,
    Unknown(i64),
}

impl TwoFactorProvider {
    pub fn supports_code_entry(self) -> bool {
        matches!(self, Self::Authenticator | Self::Yubikey)
    }

    pub fn id(self) -> i64 {
        match self {
            TwoFactorProvider::Authenticator => 0,
            TwoFactorProvider::Email => 1,
            TwoFactorProvider::Duo => 2,
            TwoFactorProvider::Yubikey => 3,
            TwoFactorProvider::Remember => 5,
            TwoFactorProvider::OrganizationDuo => 6,
            TwoFactorProvider::WebAuthn => 7,
            TwoFactorProvider::RecoveryCode => 8,
            TwoFactorProvider::Unknown(id) => id,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TwoFactorProvider::Authenticator => "Authenticator app",
            TwoFactorProvider::Email => "Email",
            TwoFactorProvider::Duo => "Duo",
            TwoFactorProvider::Yubikey => "YubiKey",
            TwoFactorProvider::Remember => "Remembered device",
            TwoFactorProvider::OrganizationDuo => "Organization Duo",
            TwoFactorProvider::WebAuthn => "WebAuthn",
            TwoFactorProvider::RecoveryCode => "Recovery code",
            TwoFactorProvider::Unknown(_) => "Unknown provider",
        }
    }
}

impl Drop for BwClient {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.user_key.zeroize();
        for item in &mut self.items {
            item.zeroize();
        }
        for key in self.organization_keys.values_mut() {
            key.zeroize();
        }
    }
}
impl Drop for StoredCipher {
    fn drop(&mut self) {
        self.item_key.zeroize();
        for uri in &mut self.browser_uris {
            uri.uri.zeroize();
        }
    }
}
impl Drop for TwoFactorChallenge {
    fn drop(&mut self) {
        self.password.zeroize();
        self.password_hash.zeroize();
        self.master_key.zeroize();
    }
}

impl Default for BwClient {
    fn default() -> Self {
        Self::new()
    }
}

impl BwClient {
    #[cfg(test)]
    pub(crate) fn browser_test_fixture() -> Self {
        let mut client = tests::protected_fixture();
        // Browser integration tests must never contact the fixture's example server.
        client.last_sync_attempt = Some(Instant::now());
        client
    }

    #[cfg(test)]
    pub(crate) fn browser_card_test_fixture(protected: bool) -> Self {
        let mut client = Self::browser_test_fixture();
        let stored = &client.ciphers["cipher-edit"];
        let mut raw = stored.raw.clone();
        raw["type"] = json!(3);
        raw["reprompt"] = json!(u8::from(protected));
        raw["login"] = Value::Null;
        raw["card"] = json!({});
        for (key, value) in [
            ("cardholderName", "Alice Example"),
            ("number", "4111111111111111"),
            ("code", "123"),
            ("expMonth", "3"),
            ("expYear", "2030"),
            ("brand", "Visa"),
        ] {
            raw["card"][key] = encrypt_value(value, &stored.item_key).unwrap();
        }
        client.replace_cipher(raw).unwrap();
        client
    }

    #[cfg(test)]
    pub(crate) fn browser_totp_test_fixture() -> Self {
        let mut client = Self::browser_test_fixture();
        client.items[0].totp = Some("JBSWY3DPEHPK3PXP".into());
        client
    }

    #[cfg(test)]
    pub(crate) fn browser_passkey_test_fixture() -> Self {
        passkey_vault_tests::fixture()
    }

    #[cfg(test)]
    pub(crate) fn browser_passkey_test_add_second(&mut self) {
        let stored = &self.ciphers["cipher-edit"];
        let mut raw = stored.raw.clone();
        raw["id"] = json!("cipher-second");
        raw["name"] = encrypt_value("Second account", &stored.item_key).unwrap();
        let credential = &mut raw["login"]["fido2Credentials"][0];
        credential["credentialId"] =
            encrypt_value("18d70b74-e9f5-4522-a425-e5dcd40107e7", &stored.item_key).unwrap();
        credential["userName"] = encrypt_value("bob@example.com", &stored.item_key).unwrap();
        credential["userDisplayName"] = encrypt_value("Bob", &stored.item_key).unwrap();
        let (detail, stored) = decode_cipher(
            raw,
            self.user_key.as_ref().unwrap(),
            &self.organization_keys,
            &self.folders,
        )
        .unwrap();
        self.items.push(detail);
        self.ciphers.insert("cipher-second".into(), stored);
    }

    #[cfg(test)]
    pub(crate) fn browser_passkey_test_set_reprompt(&mut self, id: &str, enabled: bool) {
        let mut raw = self.ciphers[id].raw.clone();
        raw_set(&mut raw, "reprompt", json!(u8::from(enabled)));
        self.replace_cipher(raw).unwrap();
    }

    #[cfg(test)]
    pub(crate) fn browser_test_clear_unlock_verification(&mut self) {
        self.verified_unlock = false;
    }

    #[cfg(test)]
    pub(crate) fn browser_test_change_password(&mut self) {
        let stored = self.ciphers.get("cipher-edit").unwrap();
        let mut raw = stored.raw.clone();
        raw["login"]["password"] = encrypt_value("changed-password", &stored.item_key).unwrap();
        self.replace_cipher(raw).unwrap();
    }

    #[cfg(test)]
    pub(crate) fn browser_test_use_offline_session(&mut self) {
        self.access_token = None;
        self.sync_status.offline = true;
        self.last_sync_attempt = Some(Instant::now());
        self.sync_warning = Some("Offline: showing encrypted local copy".into());
    }

    #[cfg(test)]
    pub(crate) fn browser_test_revoke_on_next_sync(&mut self) -> std::thread::JoinHandle<()> {
        let (url, server) =
            tests::serve_responses(vec![(400, json!({"error": "invalid_grant"}).to_string())]);
        self.browser_test_use_offline_session();
        self.base_url = url;
        self.refresh_token = Some("revoked-refresh-token".into());
        self.last_sync_attempt = None;
        self.client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        server
    }

    pub fn new() -> Self {
        Self {
            email: None,
            raw_profile: None,
            raw_folders: Vec::new(),
            undecodable_ciphers: Vec::new(),
            retry_seconds: 60,
            reauth: None,
            verified_unlock: false,
            item_grants: HashMap::new(),
            client: Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(4))
                .timeout(HTTP_TIMEOUT)
                .user_agent("boltwarden/0.1")
                .build()
                .expect("reqwest client"),
            base_url: std::env::var("BW_SERVER")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "https://vault.bitwarden.com".to_string()),
            device_identifier: config::load_or_create_device_identifier(),
            access_token: None,
            refresh_token: None,
            user_key: None,
            items: Vec::new(),
            ciphers: HashMap::new(),
            folders: HashMap::new(),
            organization_keys: HashMap::new(),
            sync_warning: None,
            sync_status: SyncStatus::default(),
            last_sync_attempt: None,
            health_cache: None,
        }
    }

    pub fn has_session(&self) -> bool {
        self.user_key.is_some() && (self.access_token.is_some() || self.sync_status.offline)
    }

    pub fn has_verified_unlock(&self) -> bool {
        self.verified_unlock && self.has_session() && self.reauth.is_some()
    }

    pub fn unlock_saved_session(
        &mut self,
        saved: &SavedSession,
        password: &str,
    ) -> Result<(), BwError> {
        self.verified_unlock = false;
        self.base_url = normalize_server_url(&saved.server_url)?;
        self.email = Some(saved.email.clone());
        let master_key = Zeroizing::new(master_key_from_saved(password, saved)?);
        let user_key = unwrap_user_key(&saved.master_key_encrypted_user_key, &master_key)?;
        self.reauth = Some((
            saved.salt.clone(),
            saved.kdf.clone(),
            saved.master_key_encrypted_user_key.clone(),
        ));
        self.refresh_token = Some(saved_session_token(saved, &user_key)?);
        self.user_key = Some(user_key);
        let result = match self.refresh_session().and_then(|_| self.sync()) {
            Err(error @ BwError::Network(_)) => {
                self.last_sync_attempt = Some(Instant::now());
                if self.load_offline_cache().is_ok() {
                    Ok(())
                } else {
                    Err(error)
                }
            }
            result => result,
        };
        self.verified_unlock = result.is_ok();
        result
    }

    pub fn login(
        &mut self,
        server_url: &str,
        email: &str,
        password: &str,
        remember: bool,
    ) -> Result<(), BwError> {
        self.verified_unlock = false;
        self.base_url = normalize_server_url(server_url)?;
        self.email = Some(email.trim().to_string());
        let prelogin = self.prelogin(email)?;
        let master_key = Zeroizing::new(master_key(email, password, &prelogin)?);
        let password_hash = password_hash(password, &master_key);
        let token = match self.token(email, &password_hash, None)? {
            TokenResult::Success(token) => token,
            TokenResult::TwoFactor(challenge) => {
                return Err(BwError::TwoFactorRequired(TwoFactorChallenge {
                    base_url: self.base_url.clone(),
                    device_identifier: self.device_identifier.clone(),
                    email: email.to_string(),
                    password: password.to_string(),
                    password_hash,
                    master_key: master_key.to_vec(),
                    kdf: SavedKdf {
                        kdf_type: prelogin.kdf,
                        iterations: prelogin.kdf_iterations,
                        memory: prelogin.kdf_memory,
                        parallelism: prelogin.kdf_parallelism,
                    },
                    remember,
                    providers: challenge.providers,
                }));
            }
        };
        let (wrapped_user_key, unlock_data) = token.master_key_encrypted_user_key()?;
        let master_key = match unlock_data {
            Some(unlock) => master_key_from_unlock(password, unlock)?,
            None => master_key.to_vec(),
        };
        let master_key = Zeroizing::new(master_key);
        let user_key = unwrap_user_key(wrapped_user_key, &master_key)?;
        let (salt, kdf) = saved_kdf_from_login(email, &prelogin, unlock_data);
        self.reauth = Some((salt, kdf, wrapped_user_key.to_owned()));
        save_successful_session(
            &self.base_url,
            email,
            token.refresh_token.as_deref(),
            wrapped_user_key,
            saved_kdf_from_login(email, &prelogin, unlock_data),
            &user_key,
        )?;

        self.refresh_token = token.refresh_token;
        self.access_token = Some(token.access_token);
        self.user_key = Some(user_key);
        self.sync()?;
        self.verified_unlock = true;
        Ok(())
    }

    pub fn complete_two_factor(
        &mut self,
        challenge: &TwoFactorChallenge,
        provider: TwoFactorProvider,
        token_code: &str,
        remember: bool,
    ) -> Result<(), BwError> {
        self.verified_unlock = false;
        if !provider.supports_code_entry() {
            return Err(BwError::Cli(
                "This two-step method is not supported; use the official Bitwarden app".into(),
            ));
        }
        self.base_url = challenge.base_url.clone();
        self.email = Some(challenge.email.trim().to_string());
        self.device_identifier = challenge.device_identifier.clone();
        let submission = TwoFactorSubmission {
            provider,
            token: token_code.trim().to_string(),
            remember: remember || challenge.remember,
        };
        let token = match self.token(
            &challenge.email,
            &challenge.password_hash,
            Some(&submission),
        )? {
            TokenResult::Success(token) => token,
            TokenResult::TwoFactor(_) => {
                return Err(BwError::Cli("two factor token was rejected".into()));
            }
        };
        let (wrapped_user_key, unlock_data) = token.master_key_encrypted_user_key()?;
        let master_key = match unlock_data {
            Some(unlock) => master_key_from_unlock(&challenge.password, unlock)?,
            None => challenge.master_key.clone(),
        };
        let master_key = Zeroizing::new(master_key);
        let user_key = unwrap_user_key(wrapped_user_key, &master_key)?;
        let (salt, kdf) = saved_kdf_from_challenge(&challenge.email, &challenge.kdf, unlock_data);
        self.reauth = Some((salt, kdf, wrapped_user_key.to_owned()));
        save_successful_session(
            &self.base_url,
            &challenge.email,
            token.refresh_token.as_deref(),
            wrapped_user_key,
            saved_kdf_from_challenge(&challenge.email, &challenge.kdf, unlock_data),
            &user_key,
        )?;

        self.refresh_token = token.refresh_token;
        self.access_token = Some(token.access_token);
        self.user_key = Some(user_key);
        self.sync()?;
        self.verified_unlock = true;
        Ok(())
    }

    pub fn list_items_in(&self, state: ItemState, search: &str) -> Result<Vec<BwItem>, BwError> {
        self.require_unlocked()?;
        let needle = search.trim().to_lowercase();
        Ok(ranked_search_results(
            self.items
                .iter()
                .filter(|item| item.state == state)
                .filter(|item| {
                    !self.item_requires_reprompt(&item.id)
                        || title_match_rank(&item.name, &needle).is_some()
                }),
            &needle,
        ))
    }

    /// Base URL of the icon service that belongs to this server.
    pub fn icons_url(&self) -> String {
        crate::icons::icons_url_for_server(&self.base_url)
    }

    pub fn sync_warning(&self) -> Option<String> {
        self.sync_warning.clone()
    }

    pub fn sync_now(&mut self) -> Result<SyncStatus, BwError> {
        self.require_unlocked()?;
        match self.sync() {
            Ok(()) => Ok(self.sync_status()),
            Err(error) => {
                if matches!(error, BwError::Network(_)) {
                    self.retry_seconds = if self.sync_status.offline {
                        (self.retry_seconds * 2).min(300)
                    } else {
                        60
                    };
                    self.sync_status.offline = true;
                    self.sync_warning = Some(format!("Offline: showing local copy: {error}"));
                } else {
                    self.sync_warning = Some(format!("Sync failed; showing cached items: {error}"));
                }
                Err(error)
            }
        }
    }

    pub fn sync_if_stale(&mut self) {
        if self
            .last_sync_attempt
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(self.retry_seconds))
        {
            let _ = self.sync_now();
        }
    }

    pub fn sync_status(&self) -> SyncStatus {
        self.sync_status.clone()
    }

    pub fn refresh_session(&mut self) -> Result<(), BwError> {
        let refresh_token = self
            .refresh_token
            .as_deref()
            .ok_or_else(|| BwError::Cli("no refresh token available".into()))?;
        let url = format!("{}/identity/connect/token", self.base_url);
        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", "web"),
        ];
        let response = self
            .client
            .post(url)
            .form(&params)
            .send()
            .map_err(|e| transport_error(e, "refresh request"))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            if status.as_u16() == 401
                || serde_json::from_str::<Value>(&body)
                    .ok()
                    .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned))
                    .as_deref()
                    == Some("invalid_grant")
            {
                self.invalidate_session();
            }
            return Err(BwError::Cli(format!(
                "refresh failed with HTTP {status}: {body}"
            )));
        }
        let body = Zeroizing::new(
            response
                .text()
                .map_err(|e| transport_error(e, "refresh response body"))?,
        );
        let token: RefreshTokenResponse = serde_json::from_str(&body)
            .map_err(|e| BwError::Parse(format!("refresh response: {e}")))?;
        let old_refresh = zeroize::Zeroizing::new(self.refresh_token.clone().unwrap_or_default());
        self.access_token.zeroize();
        self.access_token = Some(token.access_token);
        if let Some(refresh_token) = token.refresh_token {
            self.refresh_token.zeroize();
            self.refresh_token = Some(refresh_token);
        }
        let user_key = self.user_key.as_deref().ok_or(BwError::NotUnlocked)?;
        if let Some(mut saved) =
            config::load_saved_session().filter(|saved| saved.server_url == self.base_url)
        {
            let previous = Zeroizing::new(saved_session_token(&saved, user_key)?);
            if *previous == *old_refresh {
                encrypt_session_token(
                    &mut saved,
                    self.refresh_token.as_deref().unwrap_or_default(),
                    user_key,
                )?;
                config::save_session(&saved)
                    .map_err(|e| BwError::Cli(format!("Could not save encrypted session: {e}")))?;
            }
        }
        Ok(())
    }

    fn item_requires_reprompt(&self, id: &str) -> bool {
        self.ciphers.get(id).is_some_and(|cipher| {
            raw_get(&cipher.raw, "reprompt")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                != 0
        })
    }

    fn require_item_access(&self, id: &str) -> Result<(), BwError> {
        if self.item_requires_reprompt(id)
            && !self
                .item_grants
                .get(id)
                .is_some_and(|at| at.elapsed() < Duration::from_secs(60))
        {
            return Err(BwError::RepromptRequired);
        }
        Ok(())
    }

    pub fn authorize_item(&mut self, id: &str, password: &str) -> Result<BwItemDetail, BwError> {
        self.require_unlocked()?;
        if !self.ciphers.contains_key(id) {
            return Err(BwError::NotFound);
        }
        self.verify_master_password(password)?;
        self.item_grants.insert(id.to_owned(), Instant::now());
        self.get_item(id)
    }

    /// Verify identity without granting access to any desktop or browser item.
    /// Browser approval ownership and one-use authorization are enforced by its hub.
    pub fn verify_master_password(&self, password: &str) -> Result<(), BwError> {
        self.require_unlocked()?;
        let (salt, kdf, encrypted_key) = self
            .reauth
            .as_ref()
            .ok_or_else(|| BwError::Cli("Lock and unlock the vault to verify this item".into()))?;
        let master = Zeroizing::new(derive_master_key(
            password,
            salt,
            kdf.kdf_type,
            kdf.iterations,
            kdf.memory,
            kdf.parallelism,
        )?);
        let verified = Zeroizing::new(
            unwrap_user_key(encrypted_key, &master)
                .map_err(|_| BwError::Cli("Incorrect master password".into()))?,
        );
        use subtle::ConstantTimeEq;
        if !bool::from(
            verified
                .as_slice()
                .ct_eq(self.user_key.as_deref().ok_or(BwError::NotUnlocked)?),
        ) {
            return Err(BwError::Cli("Incorrect master password".into()));
        }
        Ok(())
    }

    fn card_details(&self, id: &str) -> Result<crate::browser::protocol::CardDetails, BwError> {
        let stored = self.ciphers.get(id).ok_or(BwError::NotFound)?;
        // Read canonical card fields, never similarly named user-defined fields.
        let raw = raw_get(&stored.raw, "card")
            .filter(|value| value.is_object())
            .or_else(|| raw_get(&stored.raw, "data").filter(|value| value.is_object()))
            .ok_or(BwError::NotFound)?;
        let card: CardResponse =
            serde_json::from_value(raw.clone()).map_err(|_| BwError::NotFound)?;
        let decrypt = |value: Option<String>| -> Result<String, BwError> {
            Ok(decrypt_opt_string(value.as_deref(), &stored.item_key)?.unwrap_or_default())
        };
        Ok(crate::browser::protocol::CardDetails {
            cardholder: decrypt(card.cardholder_name)?,
            number: decrypt(card.number)?,
            code: decrypt(card.code)?,
            exp_month: decrypt(card.exp_month)?,
            exp_year: decrypt(card.exp_year)?,
            brand: decrypt(card.brand)?,
        })
    }

    pub fn browser_cards(&self) -> Result<Vec<BrowserMatchSummary>, BwError> {
        self.require_unlocked()?;
        let mut cards = Vec::new();
        for item in &self.items {
            if item.state != ItemState::Active || item.item_type != "card" {
                continue;
            }
            let card = self.card_details(&item.id)?;
            let digits = Zeroizing::new(
                card.number
                    .chars()
                    .filter(char::is_ascii_digit)
                    .collect::<String>(),
            );
            if !(12..=19).contains(&digits.len()) {
                continue;
            }
            cards.push(BrowserMatchSummary {
                id: item.id.clone(),
                name: item.name.clone(),
                username: Some(
                    format!("{} •••• {}", card.brand, &digits[digits.len() - 4..])
                        .trim()
                        .to_string(),
                ),
                revision: browser_revision(self.ciphers.get(&item.id).ok_or(BwError::NotFound)?)?,
                reprompt: self.item_requires_reprompt(&item.id),
                insecure_downgrade: false,
            });
        }
        cards.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        Ok(cards)
    }

    pub fn browser_card(
        &self,
        id: &str,
        revision: &str,
        protected_authorized: bool,
    ) -> Result<crate::browser::protocol::CardDetails, BwError> {
        self.require_unlocked()?;
        let item = self
            .items
            .iter()
            .find(|item| {
                item.id == id && item.state == ItemState::Active && item.item_type == "card"
            })
            .ok_or(BwError::NotFound)?;
        if browser_revision(self.ciphers.get(id).ok_or(BwError::NotFound)?)? != revision {
            return Err(BwError::NotFound);
        }
        if self.item_requires_reprompt(&item.id) && !protected_authorized {
            return Err(BwError::RepromptRequired);
        }
        self.card_details(id)
    }

    pub fn browser_matches(
        &self,
        frame_url: &str,
        default_match: UriMatchType,
    ) -> Result<Vec<BrowserMatchSummary>, BwError> {
        self.require_unlocked()?;
        let mut matches = Vec::new();
        for item in &self.items {
            if item.state != ItemState::Active || item.item_type != "login" {
                continue;
            }
            let Some(stored) = self.ciphers.get(&item.id) else {
                continue;
            };
            let Some(insecure_downgrade) = browser_uri_match(stored, frame_url, default_match)
            else {
                continue;
            };
            matches.push(BrowserMatchSummary {
                id: item.id.clone(),
                name: item.name.clone(),
                username: item.username.clone(),
                revision: browser_revision(stored)?,
                reprompt: self.item_requires_reprompt(&item.id),
                insecure_downgrade,
            });
        }
        matches.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        Ok(matches)
    }

    /// Only editable personal logins are offered for browser writes.
    pub fn browser_write_targets(
        &self,
        url: &str,
        matching: UriMatchType,
    ) -> Result<Vec<BrowserMatchSummary>, BwError> {
        self.require_unlocked()?;
        self.require_online()?;
        Ok(self
            .browser_matches(url, matching)?
            .into_iter()
            .filter(|item| {
                self.ciphers.get(&item.id).is_some_and(|stored| {
                    !item.insecure_downgrade
                        && raw_get(&stored.raw, "organizationId").is_none()
                        && ensure_editable(&stored.raw).is_ok()
                })
            })
            .take(64)
            .collect())
    }

    fn browser_write_target(
        &self,
        target: &BrowserMatchSummary,
        verified: bool,
    ) -> Result<StoredCipher, BwError> {
        self.require_unlocked()?;
        self.require_online()?;
        let stored = self.ciphers.get(&target.id).ok_or(BwError::NotFound)?;
        if browser_revision(stored)? != target.revision
            || !self.items.iter().any(|item| {
                item.id == target.id && item.state == ItemState::Active && item.item_type == "login"
            })
            || raw_get(&stored.raw, "organizationId").is_some()
        {
            return Err(BwError::Cli(
                "The selected login changed. Try again.".into(),
            ));
        }
        if self.item_requires_reprompt(&target.id) && !verified {
            return Err(BwError::RepromptRequired);
        }
        ensure_editable(&stored.raw)?;
        Ok(stored.clone())
    }

    pub fn browser_password_already_saved(
        &self,
        targets: &[BrowserMatchSummary],
        username: &str,
        password: &str,
    ) -> bool {
        targets.iter().any(|target| {
            self.ciphers.get(&target.id).is_some_and(|stored| {
                draft_from_raw(&stored.raw, &stored.item_key)
                    .ok()
                    .map(Zeroizing::new)
                    .is_some_and(|draft| {
                        draft.login.as_ref().is_some_and(|login| {
                            (username.is_empty() || login.username == username)
                                && login.password == password
                        })
                    })
            })
        })
    }

    pub fn browser_save_password(
        &mut self,
        url: &str,
        username: &str,
        password: &str,
        target: Option<&BrowserMatchSummary>,
        verified: bool,
    ) -> Result<(), BwError> {
        self.require_unlocked()?;
        self.require_online()?;
        if password.is_empty() || password.len() > 4096 || username.len() > 1024 {
            return Err(BwError::Cli("Invalid login fields".into()));
        }
        if let Some(target) = target {
            let stored = self.browser_write_target(target, verified)?;
            let mut draft = Zeroizing::new(draft_from_raw(&stored.raw, &stored.item_key)?);
            let login = draft.login.as_mut().ok_or(BwError::NotFound)?;
            if !username.is_empty() {
                login.username = username.into();
            }
            login.password.zeroize();
            login.password = password.into();
            let body = build_save_request(&stored, &draft, &iso8601_now())?;
            let response = self.send_authed(Method::PUT, &cipher_path(&target.id)?, Some(&body))?;
            let raw: Value = expect_success(response, "update browser password")?
                .json()
                .map_err(|_| BwError::Parse("Invalid save response".into()))?;
            if raw_get(&raw, "id").and_then(Value::as_str) != Some(target.id.as_str()) {
                return Err(BwError::Parse("Server returned a different item".into()));
            }
            self.replace_cipher(raw)?;
        } else {
            let parsed = Url::parse(url).map_err(|_| BwError::Cli("Invalid website".into()))?;
            self.create_item(&Zeroizing::new(ItemDraft {
                name: parsed.host_str().unwrap_or("Login").into(),
                login: Some(LoginDraft {
                    username: username.into(),
                    password: password.into(),
                    uris: vec![DraftUri {
                        uri: parsed.origin().ascii_serialization(),
                        original_index: None,
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }))?;
        }
        Ok(())
    }

    pub fn browser_totp_matches(
        &self,
        frame_url: &str,
        default_match: UriMatchType,
    ) -> Result<Vec<BrowserMatchSummary>, BwError> {
        let mut matches = self.browser_matches(frame_url, default_match)?;
        matches.retain(|summary| {
            self.items.iter().any(|item| {
                item.id == summary.id
                    && item
                        .totp
                        .as_deref()
                        .is_some_and(|seed| !seed.trim().is_empty())
            })
        });
        Ok(matches)
    }

    /// Browser grants are operation-specific; desktop item grants never authorize OTP release.
    pub fn browser_totp(
        &self,
        id: &str,
        revision: &str,
        frame_url: &str,
        default_match: UriMatchType,
        protected_authorized: bool,
    ) -> Result<TotpCode, BwError> {
        drop(self.browser_credentials(
            id,
            revision,
            frame_url,
            default_match,
            protected_authorized,
        )?);
        let seed = self
            .items
            .iter()
            .find(|item| item.id == id)
            .and_then(|item| item.totp.as_deref())
            .ok_or(BwError::NotFound)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| BwError::Cli(format!("system clock error: {e}")))?
            .as_secs();
        generate_totp(seed, now)
    }

    pub fn browser_credentials(
        &self,
        id: &str,
        revision: &str,
        frame_url: &str,
        default_match: UriMatchType,
        protected_authorized: bool,
    ) -> Result<BrowserCredentials, BwError> {
        self.require_unlocked()?;
        let item = self
            .items
            .iter()
            .find(|item| {
                item.id == id && item.state == ItemState::Active && item.item_type == "login"
            })
            .ok_or(BwError::NotFound)?;
        let stored = self.ciphers.get(id).ok_or(BwError::NotFound)?;
        if browser_revision(stored)? != revision {
            return Err(BwError::NotFound);
        }
        let insecure_downgrade =
            browser_uri_match(stored, frame_url, default_match).ok_or(BwError::NotFound)?;
        // Desktop grants deliberately cannot authorize browser requests.
        if self.item_requires_reprompt(id) && !protected_authorized {
            return Err(BwError::RepromptRequired);
        }
        Ok(BrowserCredentials {
            username: item.username.clone(),
            password: item.password.clone(),
            insecure_downgrade,
        })
    }

    /// Only the independently verified ES256, zero-counter profile is offered.
    /// Positive counters need a separately verified atomic persistence protocol;
    /// they fall back to another authenticator before any approval is requested.
    pub fn browser_passkey_candidates(
        &self,
        rp_id: &str,
        allow_ids: &[Vec<u8>],
    ) -> Result<Vec<PasskeySummary>, BwError> {
        self.require_unlocked()?;
        let mut candidates = Vec::new();
        for item in &self.items {
            if item.state != ItemState::Active || item.item_type != "login" {
                continue;
            }
            let Some(stored) = self.ciphers.get(&item.id) else {
                continue;
            };
            for raw in stored_passkeys(stored) {
                let Ok(credential) = decode_browser_passkey(raw, &stored.item_key, rp_id) else {
                    continue;
                };
                if !passkey_requested(&credential, allow_ids) {
                    continue;
                }
                let summary = PasskeySummary {
                    requires_password: self.item_requires_reprompt(&item.id),
                    id: item.id.clone(),
                    credential_id: crate::passkeys::encode(&credential.credential_id),
                    revision: browser_revision(stored)?,
                    name: item.name.clone(),
                    user_name: credential.user_name.clone(),
                    user_display_name: credential.user_display_name.clone(),
                };
                // An item may contain several credentials; never confuse their
                // array position with an index in the filtered result.
                if !candidates.iter().any(|candidate: &PasskeySummary| {
                    candidate.id == summary.id && candidate.credential_id == summary.credential_id
                }) {
                    candidates.push(summary);
                }
            }
        }
        candidates.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.id.cmp(&b.id))
                .then_with(|| a.credential_id.cmp(&b.credential_id))
        });
        Ok(candidates)
    }

    /// Exclusion is independent of whether this implementation can sign a
    /// credential. Unsupported counters and algorithms still exclude creation.
    pub fn browser_passkey_excluded(
        &self,
        rp_id: &str,
        exclude_ids: &[Vec<u8>],
    ) -> Result<bool, BwError> {
        self.require_unlocked()?;
        if exclude_ids.is_empty() {
            return Ok(false);
        }
        for item in &self.items {
            if item.state != ItemState::Active || item.item_type != "login" {
                continue;
            }
            let Some(stored) = self.ciphers.get(&item.id) else {
                continue;
            };
            for raw in stored_passkeys(stored) {
                let Ok(stored_rp) = passkey_field(raw, "rpId", &stored.item_key) else {
                    continue;
                };
                if stored_rp != rp_id {
                    continue;
                }
                let Ok(stored_id) = passkey_field(raw, "credentialId", &stored.item_key)
                    .and_then(|id| crate::passkeys::credential_id(&id).map_err(passkey_error))
                else {
                    continue;
                };
                if exclude_ids.contains(&stored_id) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub fn browser_passkey_can_create(&self) -> Result<(), BwError> {
        self.require_unlocked()?;
        self.require_online()
    }

    /// Called after request-bound desktop consent and required verification.
    /// Desktop item grants are deliberately irrelevant here.
    pub fn browser_passkey_assert(
        &mut self,
        selected: &PasskeySummary,
        context: &crate::passkeys::ValidatedRequest,
        options: &crate::passkeys::GetOptions,
        verification: PasskeyVerificationEvidence,
    ) -> Result<crate::passkeys::PasskeyResult, BwError> {
        self.require_unlocked()?;
        self.items
            .iter()
            .find(|item| {
                item.id == selected.id
                    && item.state == ItemState::Active
                    && item.item_type == "login"
            })
            .ok_or(BwError::NotFound)?;
        let stored = self.ciphers.get(&selected.id).ok_or(BwError::NotFound)?;
        if browser_revision(stored)? != selected.revision {
            return Err(BwError::NotFound);
        }
        if (verification == PasskeyVerificationEvidence::VaultUnlock && !self.has_verified_unlock())
            || (self.item_requires_reprompt(&selected.id)
                && verification != PasskeyVerificationEvidence::FreshPassword)
            || (!verification.verified()
                && (options.user_verification == "required" || context.requires_user_verification))
        {
            return Err(BwError::RepromptRequired);
        }
        let allow_ids = options
            .allow_credentials
            .iter()
            .map(|descriptor| crate::passkeys::decode(&descriptor.id, 1024).map_err(passkey_error))
            .collect::<Result<Vec<_>, _>>()?;
        let selected_id =
            crate::passkeys::decode(&selected.credential_id, 1024).map_err(passkey_error)?;
        let mut matching = stored_passkeys(stored)
            .filter_map(|raw| decode_browser_passkey(raw, &stored.item_key, &context.rp_id).ok())
            .filter(|credential| {
                credential.credential_id == selected_id && passkey_requested(credential, &allow_ids)
            });
        let credential = matching.next().ok_or(BwError::NotFound)?;
        if matching.next().is_some() {
            // Ambiguous duplicate credential IDs must never select an arbitrary key.
            return Err(BwError::Parse("duplicate passkey credential ID".into()));
        }
        crate::passkeys::sign_assertion(
            context,
            &credential.credential_id,
            credential.user_handle.as_deref(),
            &credential.pkcs8_der,
            0,
            verification.verified(),
        )
        .map_err(passkey_error)
    }

    /// Registers a new personal login only. The encrypted key must be accepted by
    /// the server and decoded locally before a successful response can escape.
    #[cfg(test)]
    pub fn browser_passkey_create(
        &mut self,
        context: &crate::passkeys::ValidatedRequest,
        options: &crate::passkeys::CreateOptions,
        verification: PasskeyVerificationEvidence,
    ) -> Result<crate::passkeys::PasskeyResult, BwError> {
        self.browser_passkey_create_on(context, options, verification, None)
    }

    pub fn browser_passkey_create_on(
        &mut self,
        context: &crate::passkeys::ValidatedRequest,
        options: &crate::passkeys::CreateOptions,
        verification: PasskeyVerificationEvidence,
        target: Option<&BrowserMatchSummary>,
    ) -> Result<crate::passkeys::PasskeyResult, BwError> {
        self.browser_passkey_can_create()?;
        let target_cipher = target
            .map(|target| {
                self.browser_write_target(
                    target,
                    verification == PasskeyVerificationEvidence::FreshPassword,
                )
            })
            .transpose()?;
        if (verification == PasskeyVerificationEvidence::VaultUnlock && !self.has_verified_unlock())
            || (!verification.verified()
                && (options.user_verification == "required" || context.requires_user_verification))
        {
            return Err(BwError::RepromptRequired);
        }
        let exclude_ids = options
            .exclude_credentials
            .iter()
            .map(|descriptor| crate::passkeys::decode(&descriptor.id, 1024).map_err(passkey_error))
            .collect::<Result<Vec<_>, _>>()?;
        if self.browser_passkey_excluded(&context.rp_id, &exclude_ids)? {
            return Err(BwError::Cli(
                "A passkey excluded by this site already exists".into(),
            ));
        }
        let generated =
            crate::passkeys::generate_credential(context, options, verification.verified())
                .map_err(passkey_error)?;
        let key = self.user_key.as_deref().ok_or(BwError::NotUnlocked)?;
        let (method, path, body) =
            if let (Some(target), Some(stored)) = (target, target_cipher.as_ref()) {
                let draft = Zeroizing::new(draft_from_raw(&stored.raw, &stored.item_key)?);
                let mut body = build_save_request(stored, &draft, &iso8601_now())?;
                let created =
                    build_passkey_create_request(context, options, &generated, &stored.item_key)?;
                let credential = created["login"]["fido2Credentials"][0].clone();
                let login = body
                    .get_mut("login")
                    .and_then(Value::as_object_mut)
                    .ok_or(BwError::NotFound)?;
                let mut credentials = login
                    .get("fido2Credentials")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                credentials.push(credential);
                login.insert("fido2Credentials".into(), Value::Array(credentials));
                (Method::PUT, cipher_path(&target.id)?, body)
            } else {
                (
                    Method::POST,
                    "/api/ciphers".into(),
                    build_passkey_create_request(context, options, &generated, key)?,
                )
            };
        let response = self.send_authed(method, &path, Some(&body))?;
        let raw: Value = expect_success(response, "create passkey")?
            .json()
            .map_err(|_| BwError::Parse("invalid create passkey response".into()))?;
        let id = raw_get(&raw, "id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| BwError::Parse("create response has no item id".into()))?
            .to_owned();
        if target.map_or_else(|| self.ciphers.contains_key(&id), |target| target.id != id)
            || raw_get(&raw, "organizationId").is_some()
        {
            return Err(BwError::Parse(
                "server did not create a new personal item".into(),
            ));
        }
        let (detail, stored) = decode_cipher(
            raw.clone(),
            self.user_key.as_deref().ok_or(BwError::NotUnlocked)?,
            &self.organization_keys,
            &self.folders,
        )?;
        if detail.state != ItemState::Active || detail.item_type != "login" {
            return Err(BwError::Parse(
                "server did not create an active login".into(),
            ));
        }
        let persisted = stored_passkeys(&stored)
            .find_map(|raw| {
                decode_browser_passkey(raw, &stored.item_key, &context.rp_id)
                    .ok()
                    .filter(|credential| credential.credential_id == generated.credential_id)
            })
            .ok_or_else(|| BwError::Parse("server did not retain the created passkey".into()))?;
        use subtle::ConstantTimeEq;
        let user_handle = crate::passkeys::decode(&options.user.id, 64).map_err(passkey_error)?;
        if !bool::from(
            persisted
                .pkcs8_der
                .as_slice()
                .ct_eq(generated.pkcs8_der.as_slice()),
        ) || persisted.user_handle.as_deref() != Some(user_handle.as_slice())
            || !persisted.discoverable
        {
            return Err(BwError::Parse("server returned a different passkey".into()));
        }
        self.replace_cipher(raw)?;
        Ok(generated.response)
    }

    pub fn revoke_item_grants(&mut self) {
        self.item_grants.clear();
    }

    pub fn get_item(&self, id: &str) -> Result<BwItemDetail, BwError> {
        self.require_unlocked()?;
        self.require_item_access(id)?;
        self.items
            .iter()
            .find(|item| item.id == id)
            .cloned()
            .ok_or(BwError::NotFound)
    }

    pub fn get_totp(&self, id: &str) -> Result<TotpCode, BwError> {
        let detail = Zeroizing::new(self.get_item(id)?);
        let seed = detail.totp.as_deref().ok_or(BwError::NotFound)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| BwError::Cli(format!("system clock error: {e}")))?
            .as_secs();
        generate_totp(seed, now)
    }

    pub fn ssh_keys(&self) -> Result<Vec<SshKey>, BwError> {
        self.require_unlocked()?;
        Ok(self
            .items
            .iter()
            .filter(|item| item.state == ItemState::Active)
            // Reprompt keys must never become silently available through the agent.
            .filter(|item| !self.item_requires_reprompt(&item.id))
            .filter_map(|item| item.ssh_key.clone())
            .collect())
    }

    pub fn apply_action(&mut self, id: &str, action: ItemAction) -> Result<(), BwError> {
        self.require_unlocked()?;
        self.require_online()?;
        let state = self.get_item(id)?.state;
        if !action_allowed(action, state) {
            return Err(BwError::Cli(format!(
                "{action:?} is not available for an item that is {state:?}"
            )));
        }
        if let ItemAction::Favorite | ItemAction::Unfavorite = action {
            return self.set_favorite(id, action == ItemAction::Favorite);
        }
        let (method, path) = match action {
            ItemAction::Favorite | ItemAction::Unfavorite => unreachable!("handled above"),
            ItemAction::Archive => (Method::PUT, format!("{}/archive", cipher_path(id)?)),
            ItemAction::Unarchive => (Method::PUT, format!("{}/unarchive", cipher_path(id)?)),
            ItemAction::Trash => (Method::PUT, format!("{}/delete", cipher_path(id)?)),
            ItemAction::Restore => (Method::PUT, format!("{}/restore", cipher_path(id)?)),
            ItemAction::DeleteForever => (Method::DELETE, cipher_path(id)?),
        };
        let response = self.send_authed(method, &path, None)?;
        let response = expect_success(response, &format!("{action:?}"))?;

        if action == ItemAction::DeleteForever {
            self.items.retain(|item| item.id != id);
            self.ciphers.remove(id);
            self.persist_offline_cache();
            return Ok(());
        }

        // Some endpoints answer with the updated cipher and some with nothing. Either way
        // the stored copy must carry the new revision date, or the next edit is rejected
        // as out of date.
        let body = response.text().unwrap_or_default();
        let raw = serde_json::from_str::<Value>(&body)
            .ok()
            .filter(looks_like_cipher)
            .map(Ok)
            .unwrap_or_else(|| self.fetch_cipher(id));
        match raw.and_then(|raw| self.replace_cipher(raw)) {
            Ok(()) => Ok(()),
            Err(_) => {
                // The change went through; keep the list right even if the refresh failed.
                if let Some(item) = self.items.iter_mut().find(|item| item.id == id) {
                    item.state = state_after(action, item.state);
                    item.dates.state_changed_at =
                        (item.state != ItemState::Active).then(iso8601_now);
                }
                if let Some(stored) = self.ciphers.get_mut(id) {
                    let field = match action {
                        ItemAction::Archive | ItemAction::Unarchive => "archivedDate",
                        _ => "deletedDate",
                    };
                    let value = match action {
                        ItemAction::Archive | ItemAction::Trash => json!(iso8601_now()),
                        _ => Value::Null,
                    };
                    raw_set(&mut stored.raw, field, value);
                }
                self.persist_offline_cache();
                Ok(())
            }
        }
    }

    /// Favorite and folder are per-user settings with their own endpoint, so starring or
    /// moving an item works even for items this app can't otherwise edit.
    fn set_favorite(&mut self, id: &str, favorite: bool) -> Result<(), BwError> {
        let stored = self.ciphers.get(id).ok_or(BwError::NotFound)?;
        let folder_id = raw_get(&stored.raw, "folderId")
            .and_then(Value::as_str)
            .map(str::to_string);
        self.update_partial(id, folder_id, favorite)
    }

    /// Moves an item into a folder, or out of all folders with `None`.
    pub fn move_item(&mut self, id: &str, folder_id: Option<&str>) -> Result<(), BwError> {
        self.require_unlocked()?;
        self.require_online()?;
        if let Some(folder_id) = folder_id
            && !self.folders.contains_key(folder_id)
        {
            return Err(BwError::Cli("that folder no longer exists".into()));
        }
        let favorite = self.get_item_unchecked(id)?.favorite;
        self.update_partial(id, folder_id.map(str::to_string), favorite)
    }

    fn update_partial(
        &mut self,
        id: &str,
        folder_id: Option<String>,
        favorite: bool,
    ) -> Result<(), BwError> {
        let body = json!({ "folderId": folder_id, "favorite": favorite });
        let path = format!("{}/partial", cipher_path(id)?);
        let response = self.send_authed(Method::PUT, &path, Some(&body))?;
        let body = expect_success(response, "update item")?
            .text()
            .unwrap_or_default();
        let raw = serde_json::from_str::<Value>(&body)
            .ok()
            .filter(looks_like_cipher)
            .map(Ok)
            .unwrap_or_else(|| self.fetch_cipher(id));
        match raw.and_then(|raw| self.replace_cipher(raw)) {
            Ok(()) => Ok(()),
            Err(_) => {
                // The change went through; keep the local copy right even if the refresh
                // failed, including the stored cipher that later edits are built from.
                let folder_name = folder_id
                    .as_ref()
                    .map(|id| self.folders.get(id).cloned().unwrap_or_else(|| id.clone()));
                if let Some(item) = self.items.iter_mut().find(|item| item.id == id) {
                    item.favorite = favorite;
                    item.folder_id = folder_id.clone();
                    item.folder = folder_name;
                }
                if let Some(stored) = self.ciphers.get_mut(id) {
                    raw_set(&mut stored.raw, "folderId", json!(folder_id));
                    raw_set(&mut stored.raw, "favorite", Value::Bool(favorite));
                }
                self.persist_offline_cache();
                Ok(())
            }
        }
    }

    /// Looks up an item without the master-password check: for changes that reveal
    /// nothing, such as moving it.
    fn get_item_unchecked(&self, id: &str) -> Result<&BwItemDetail, BwError> {
        self.items
            .iter()
            .find(|item| item.id == id)
            .ok_or(BwError::NotFound)
    }

    pub fn create_folder(&mut self, name: &str) -> Result<Folder, BwError> {
        self.require_unlocked()?;
        self.require_online()?;
        let name = validate_folder_name(name)?;
        let user_key = self.user_key.as_deref().ok_or(BwError::NotUnlocked)?;
        let body = json!({ "name": encrypt_string(&name, user_key)? });
        let response = self.send_authed(Method::POST, "/api/folders", Some(&body))?;
        let raw: Value = expect_success(response, "create folder")?
            .json()
            .map_err(|e| BwError::Parse(format!("create folder response: {e}")))?;
        let created: FolderResponse =
            serde_json::from_value(raw.clone()).map_err(|e| BwError::Parse(e.to_string()))?;
        self.raw_folders.push(raw);
        self.folders.insert(created.id.clone(), name.clone());
        self.persist_offline_cache();
        Ok(Folder {
            id: created.id,
            name,
        })
    }

    /// Renames several folders, then syncs so items pick up the new names. Renaming a
    /// parent means renaming each subfolder too: nesting is only a name prefix.
    pub fn rename_folders(&mut self, renames: &[(String, String)]) -> Result<(), BwError> {
        self.require_unlocked()?;
        self.require_online()?;
        let user_key = self.user_key.clone().ok_or(BwError::NotUnlocked)?;
        let user_key = Zeroizing::new(user_key);
        let mut result = Ok(());
        for (id, name) in renames {
            let step = (|| {
                let name = validate_folder_name(name)?;
                let body = json!({ "name": encrypt_string(&name, &user_key)? });
                let response = self.send_authed(Method::PUT, &folder_path(id)?, Some(&body))?;
                expect_success(response, "rename folder")?;
                if let Some(raw) = self
                    .raw_folders
                    .iter_mut()
                    .find(|v| raw_get(v, "id").and_then(Value::as_str) == Some(id))
                {
                    raw_set(raw, "name", body["name"].clone());
                }
                self.folders.insert(id.clone(), name.clone());
                for item in &mut self.items {
                    if item.folder_id.as_ref() == Some(id) {
                        item.folder = Some(name.clone());
                    }
                }
                self.persist_offline_cache();
                Ok(())
            })();
            if let Err(error) = step {
                result = Err(error);
                break;
            }
        }
        // Sync even after a partial failure, so the window shows what really changed.
        self.sync()?;
        result
    }

    /// Deletes folders. Their items stay in the vault without a folder.
    pub fn delete_folders(&mut self, ids: &[String]) -> Result<(), BwError> {
        self.require_unlocked()?;
        self.require_online()?;
        let mut result = Ok(());
        for id in ids {
            let step = folder_path(id).and_then(|path| {
                let response = self.send_authed(Method::DELETE, &path, None)?;
                expect_success(response, "delete folder")?;
                self.raw_folders
                    .retain(|v| raw_get(v, "id").and_then(Value::as_str) != Some(id));
                self.folders.remove(id);
                for item in &mut self.items {
                    if item.folder_id.as_ref() == Some(id) {
                        item.folder_id = None;
                        item.folder = None;
                    }
                }
                for raw in self
                    .ciphers
                    .values_mut()
                    .map(|s| &mut s.raw)
                    .chain(self.undecodable_ciphers.iter_mut())
                {
                    if raw_get(raw, "folderId").and_then(Value::as_str) == Some(id) {
                        raw_set(raw, "folderId", Value::Null);
                    }
                }
                self.persist_offline_cache();
                Ok(())
            });
            if let Err(error) = step {
                result = Err(error);
                break;
            }
        }
        self.sync()?;
        result
    }

    /// Every folder, sorted by name so parents come before their subfolders.
    pub fn folders(&self) -> Result<Vec<Folder>, BwError> {
        self.require_unlocked()?;
        let mut folders = self
            .folders
            .iter()
            .map(|(id, name)| Folder {
                id: id.clone(),
                name: name.clone(),
            })
            .collect::<Vec<_>>();
        folders.sort_by_key(|folder| folder.name.to_lowercase());
        Ok(folders)
    }

    pub fn health_report(
        &mut self,
        directory: &crate::health::Directory,
    ) -> Result<HealthReport, BwError> {
        use std::hash::{Hash, Hasher};
        self.require_unlocked()?;
        // Every edit changes the revision date, so this covers all inputs of the report.
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for item in &self.items {
            (&item.id, &item.dates.revision_date, item.state).hash(&mut hasher);
        }
        directory.fingerprint().hash(&mut hasher);
        crate::health::days_since_epoch(SystemTime::now()).hash(&mut hasher);
        let key = hasher.finish();
        if let Some((cached, report)) = &self.health_cache
            && *cached == key
        {
            return Ok(report.clone());
        }
        let report = crate::health::report(&self.items, directory, SystemTime::now());
        self.health_cache = Some((key, report.clone()));
        Ok(report)
    }

    pub fn edit_draft(&self, id: &str) -> Result<ItemDraft, BwError> {
        self.require_unlocked()?;
        self.require_online()?;
        self.require_item_access(id)?;
        let stored = self.ciphers.get(id).ok_or(BwError::NotFound)?;
        ensure_editable(&stored.raw)?;
        draft_from_raw(&stored.raw, &stored.item_key)
    }

    pub fn save_item(&mut self, id: &str, draft: &ItemDraft) -> Result<BwItemDetail, BwError> {
        self.require_unlocked()?;
        self.require_online()?;
        if self.get_item(id)?.state == ItemState::Deleted {
            return Err(BwError::Cli("restore the item before editing it".into()));
        }
        let stored = self.ciphers.get(id).cloned().ok_or(BwError::NotFound)?;
        let body = build_save_request(&stored, draft, &iso8601_now())?;
        let response = self.send_authed(Method::PUT, &cipher_path(id)?, Some(&body))?;
        let raw: Value = expect_success(response, "save")?
            .json()
            .map_err(|e| BwError::Parse(format!("save response: {e}")))?;
        self.replace_cipher(raw)?;
        self.get_item(id)
    }

    pub fn create_item(&mut self, draft: &ItemDraft) -> Result<BwItemDetail, BwError> {
        self.require_unlocked()?;
        self.require_online()?;
        let user_key = self.user_key.as_deref().ok_or(BwError::NotUnlocked)?;
        let body = build_create_request(draft, user_key)?;
        let response = self.send_authed(Method::POST, "/api/ciphers", Some(&body))?;
        let raw: Value = expect_success(response, "create")?
            .json()
            .map_err(|e| BwError::Parse(format!("create response: {e}")))?;
        let id = raw_get(&raw, "id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| BwError::Parse("create response has no item id".into()))?;
        self.replace_cipher(raw)?;
        self.get_item(&id)
    }

    fn fetch_cipher(&mut self, id: &str) -> Result<Value, BwError> {
        let response = self.send_authed(Method::GET, &cipher_path(id)?, None)?;
        expect_success(response, "load item")?
            .json()
            .map_err(|e| BwError::Parse(format!("cipher response: {e}")))
    }

    fn replace_cipher(&mut self, raw: Value) -> Result<(), BwError> {
        let user_key = self.user_key.as_deref().ok_or(BwError::NotUnlocked)?;
        let (detail, stored) =
            decode_cipher(raw, user_key, &self.organization_keys, &self.folders)?;
        let id = detail.id.clone();
        match self.items.iter_mut().find(|item| item.id == id) {
            Some(slot) => {
                slot.zeroize();
                *slot = detail;
            }
            None => self.items.push(detail),
        }
        self.ciphers.insert(id, stored);
        self.persist_offline_cache();
        Ok(())
    }

    /// Sends an authenticated API request, refreshing the access token once on HTTP 401.
    fn send_authed(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Response, BwError> {
        if method != Method::GET {
            self.require_online()?;
        }
        if self.access_token.is_none() && self.refresh_token.is_some() {
            self.refresh_session()?;
        }
        let response = self.send_authed_once(method.clone(), path, body)?;
        if response.status().as_u16() == 401 && self.refresh_token.is_some() {
            self.refresh_session()?;
            let response = self.send_authed_once(method, path, body)?;
            if response.status().as_u16() == 401 {
                self.invalidate_session();
            }
            return Ok(response);
        }
        Ok(response)
    }

    fn send_authed_once(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Response, BwError> {
        let token = self.access_token.as_deref().ok_or(BwError::NotUnlocked)?;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base_url))
            .bearer_auth(token)
            .header(sync_client_name_header().0, sync_client_name_header().1)
            .header(
                sync_client_version_header().0,
                sync_client_version_header().1,
            );
        if let Some(body) = body {
            request = request.json(body);
        }
        request
            .send()
            .map_err(|e| transport_error(e, &format!("request to {path}")))
    }

    fn require_online(&self) -> Result<(), BwError> {
        if self.sync_status.offline {
            Err(BwError::Cli(
                "Offline: editing needs a connection to the server".into(),
            ))
        } else {
            Ok(())
        }
    }

    fn invalidate_session(&mut self) {
        self.verified_unlock = false;
        // A confirmed revocation must also prevent subsequent offline unlocks.
        let _ = config::clear_saved_session();
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.user_key.zeroize();
        for item in &mut self.items {
            item.zeroize();
        }
        self.items.clear();
        self.ciphers.clear();
        for key in self.organization_keys.values_mut() {
            key.zeroize();
        }
        self.organization_keys.clear();
        self.sync_status.offline = false;
    }

    pub fn apply_offline_setting(&mut self) -> std::io::Result<()> {
        if !config::load_settings().keep_offline_copy {
            config::clear_vault_cache()?;
        } else {
            self.persist_offline_cache();
        }
        Ok(())
    }

    fn persist_offline_cache(&mut self) {
        if !config::load_settings().keep_offline_copy || self.sync_status.last_synced_unix.is_none()
        {
            return;
        }
        let Some(saved) = config::load_saved_session()
            .filter(|s| s.server_url == self.base_url && Some(&s.email) == self.email.as_ref())
        else {
            return;
        };
        let Some(key) = self.user_key.as_deref() else {
            return;
        };
        let snapshot = crate::offline_cache::Snapshot {
            synced_at_unix: self.sync_status.cache_synced_unix.unwrap_or_default(),
            profile: self.raw_profile.clone(),
            folders: self.raw_folders.clone(),
            ciphers: self
                .ciphers
                .values()
                .map(|c| c.raw.clone())
                .chain(self.undecodable_ciphers.iter().cloned())
                .collect(),
        };
        let result = crate::offline_cache::encode(&snapshot, key, &saved.server_url, &saved.email)
            .and_then(|bytes| {
                config::save_vault_cache(&bytes).map_err(|e| BwError::Cli(e.to_string()))
            });
        if let Err(error) = result {
            let previous = self.sync_warning.take().unwrap_or_default();
            self.sync_warning = Some(
                format!("{previous} Offline copy could not be saved: {error}")
                    .trim()
                    .to_string(),
            );
        }
    }

    fn load_offline_cache(&mut self) -> Result<(), BwError> {
        if !config::load_settings().keep_offline_copy {
            return Err(BwError::NotFound);
        }
        let data = config::load_vault_cache().ok_or(BwError::NotFound)?;
        let snapshot = crate::offline_cache::decode(
            &data,
            self.user_key.as_deref().ok_or(BwError::NotUnlocked)?,
            &self.base_url,
            self.email.as_deref().ok_or(BwError::NotUnlocked)?,
        )?;
        let body = Zeroizing::new(
            serde_json::to_string(&snapshot).map_err(|e| BwError::Parse(e.to_string()))?,
        );
        self.apply_sync_body(&body)?;
        self.sync_status.offline = true;
        self.sync_status.last_synced_unix = Some(snapshot.synced_at_unix);
        self.sync_status.cache_synced_unix = Some(snapshot.synced_at_unix);
        self.sync_warning = Some("Offline: showing encrypted local copy; sync to reconnect".into());
        Ok(())
    }

    fn require_unlocked(&self) -> Result<(), BwError> {
        if self.has_session() {
            Ok(())
        } else {
            Err(BwError::NotUnlocked)
        }
    }

    fn prelogin(&self, email: &str) -> Result<PreloginResponse, BwError> {
        let url = format!("{}/identity/accounts/prelogin", self.base_url);
        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({ "email": email }))
            .send()
            .map_err(|e| transport_error(e, "prelogin request"))?;

        if !response.status().is_success() {
            return Err(BwError::Cli(format!(
                "prelogin failed with HTTP {}",
                response.status()
            )));
        }

        response
            .json()
            .map_err(|e| BwError::Parse(format!("prelogin response: {e}")))
    }

    fn token(
        &self,
        email: &str,
        password_hash: &str,
        two_factor: Option<&TwoFactorSubmission>,
    ) -> Result<TokenResult, BwError> {
        let url = format!("{}/identity/connect/token", self.base_url);
        let mut params = vec![
            ("grant_type", "password"),
            ("username", email),
            ("password", password_hash),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("deviceType", "10"),
            ("deviceIdentifier", self.device_identifier.as_str()),
            ("deviceName", "Boltwarden"),
        ];
        let provider_id;
        let remember_value;
        if let Some(two_factor) = two_factor {
            provider_id = two_factor.provider.id().to_string();
            remember_value = if two_factor.remember { "1" } else { "0" };
            params.push(("twoFactorToken", two_factor.token.as_str()));
            params.push(("twoFactorProvider", provider_id.as_str()));
            params.push(("twoFactorRemember", remember_value));
        }

        let response = self
            .client
            .post(url)
            .form(&params)
            .send()
            .map_err(|e| transport_error(e, "login request"))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            if status.as_u16() == 400 {
                if let Ok(two_factor) = serde_json::from_str::<TwoFactorResponse>(&body) {
                    let providers = two_factor.available_providers();
                    if !providers.is_empty() {
                        return Ok(TokenResult::TwoFactor(TwoFactorResponse {
                            providers,
                            providers2: HashMap::new(),
                        }));
                    }
                }
            }
            return Err(BwError::Cli(format!(
                "login failed with HTTP {status}: {body}"
            )));
        }

        response
            .json()
            .map(TokenResult::Success)
            .map_err(|e| BwError::Parse(format!("token response: {e}")))
    }

    fn sync(&mut self) -> Result<(), BwError> {
        self.last_sync_attempt = Some(Instant::now());
        let response = self.send_authed(Method::GET, "/api/sync?excludeDomains=true", None)?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(BwError::Cli(format!(
                "sync failed with HTTP {status}: {body}"
            )));
        }

        let body = response
            .text()
            .map_err(|e| transport_error(e, "sync response body"))?;
        self.apply_sync_body(&body)?;
        self.retry_seconds = 60;
        self.persist_offline_cache();
        Ok(())
    }

    fn apply_sync_body(&mut self, body: &str) -> Result<(), BwError> {
        let user_key = self.user_key.as_deref().ok_or(BwError::NotUnlocked)?;
        let raw_body: Value =
            serde_json::from_str(body).map_err(|e| BwError::Parse(e.to_string()))?;
        let sync: SyncResponse = serde_json::from_str(body).map_err(|e| {
            BwError::Parse(format!(
                "sync response: {e}; body starts with: {}",
                body.chars().take(300).collect::<String>()
            ))
        })?;
        let server_ciphers = sync.ciphers.len();
        let folders = decrypt_folders(sync.folders, user_key)?;
        let organization_keys = decrypt_organization_keys(sync.profile, user_key)?;
        let mut undecodable = Vec::new();
        let mut skipped = 0usize;
        let mut first_error = None;
        let mut items = Vec::with_capacity(server_ciphers);
        let mut ciphers = HashMap::with_capacity(server_ciphers);
        for raw in sync.ciphers {
            match decode_cipher(raw.clone(), user_key, &organization_keys, &folders) {
                Ok((item, stored)) => {
                    ciphers.insert(item.id.clone(), stored);
                    items.push(item);
                }
                Err(e) => {
                    undecodable.push(raw);
                    skipped += 1;
                    first_error.get_or_insert_with(|| e.to_string());
                }
            }
        }
        for item in &mut self.items {
            item.zeroize();
        }
        for key in self.organization_keys.values_mut() {
            key.zeroize();
        }
        self.raw_profile = raw_get(&raw_body, "profile").cloned();
        self.raw_folders = raw_get(&raw_body, "folders")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        self.undecodable_ciphers = undecodable;
        self.items = items;
        self.ciphers = ciphers;
        self.folders = folders;
        self.organization_keys = organization_keys;
        self.sync_status = SyncStatus {
            last_synced_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
            server_ciphers,
            decrypted_items: self.items.len(),
            skipped_items: skipped,
            first_error: first_error.clone(),
            offline: false,
            cache_synced_unix: None,
        };
        self.sync_status.cache_synced_unix = self.sync_status.last_synced_unix;
        self.sync_warning = decrypt_skip_warning(skipped, first_error);
        Ok(())
    }
}

fn transport_error(error: reqwest::Error, context: &str) -> BwError {
    let message = format!("{context} failed: {error}");
    if error.is_connect()
        || error.is_timeout()
        || error.is_body()
        || error.is_decode()
        || (error.is_request() && error.status().is_none() && !error.is_builder())
    {
        BwError::Network(message)
    } else {
        BwError::Cli(message)
    }
}

fn sync_client_name_header() -> (&'static str, &'static str) {
    ("Bitwarden-Client-Name", CLIENT_NAME)
}

fn sync_client_version_header() -> (&'static str, &'static str) {
    ("Bitwarden-Client-Version", SYNC_COMPAT_CLIENT_VERSION)
}

fn decrypt_skip_warning(count: usize, first_error: Option<String>) -> Option<String> {
    match (count, first_error) {
        (0, _) => None,
        (1, Some(error)) => Some(format!("Skipped 1 vault item during decrypt: {error}")),
        (count, Some(error)) => Some(format!(
            "Skipped {count} vault items during decrypt; first error: {error}"
        )),
        (count, None) => Some(format!("Skipped {count} vault items during decrypt")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SearchRank {
    Empty,
    TitleExact,
    TitlePrefix,
    TitleWordPrefix,
    TitleContains,
    SecondaryField,
}

impl SearchRank {
    fn is_title_match(self) -> bool {
        matches!(
            self,
            Self::Empty
                | Self::TitleExact
                | Self::TitlePrefix
                | Self::TitleWordPrefix
                | Self::TitleContains
        )
    }
}

fn search_rank(item: &BwItemDetail, needle: &str) -> Option<SearchRank> {
    title_match_rank(&item.name, needle)
        .or_else(|| secondary_matches_search(item, needle).then_some(SearchRank::SecondaryField))
}

fn ranked_search_results<'a>(
    items: impl IntoIterator<Item = &'a BwItemDetail>,
    needle: &str,
) -> Vec<BwItem> {
    let mut ranked = items
        .into_iter()
        .filter_map(|item| {
            search_rank(item, needle).map(|rank| {
                (
                    rank,
                    BwItem {
                        id: item.id.clone(),
                        name: item.name.clone(),
                        username: item.username.clone(),
                        folder: item.folder.clone(),
                        folder_id: item.folder_id.clone(),
                        favorite: item.favorite,
                        item_type: item.item_type.clone(),
                        icon_host: crate::icons::icon_host(&item.uris),
                        state: item.state,
                        dates: item.dates.clone(),
                    },
                )
            })
        })
        .collect::<Vec<_>>();
    if ranked.iter().any(|(rank, _)| rank.is_title_match()) {
        ranked.retain(|(rank, _)| rank.is_title_match());
    }
    ranked.sort_by(|(a_rank, a), (b_rank, b)| {
        a_rank
            .cmp(b_rank)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    ranked.into_iter().map(|(_, item)| item).collect()
}

fn title_match_rank(name: &str, needle: &str) -> Option<SearchRank> {
    if needle.is_empty() {
        return Some(SearchRank::Empty);
    }

    let name = name.to_lowercase();
    if name == needle {
        Some(SearchRank::TitleExact)
    } else if name.starts_with(needle) {
        Some(SearchRank::TitlePrefix)
    } else if name
        .split(|ch: char| !ch.is_alphanumeric())
        .any(|part| part.starts_with(needle))
    {
        Some(SearchRank::TitleWordPrefix)
    } else if name.contains(needle) {
        Some(SearchRank::TitleContains)
    } else {
        None
    }
}

#[cfg(test)]
fn item_matches_search(item: &BwItemDetail, needle: &str) -> bool {
    search_rank(item, needle).is_some()
}

fn secondary_matches_search(item: &BwItemDetail, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }

    item.username
        .as_deref()
        .is_some_and(|value| text_matches(value, needle))
        || item
            .password
            .as_deref()
            .is_some_and(|value| text_matches(value, needle))
        || item
            .folder
            .as_deref()
            .is_some_and(|value| text_matches(value, needle))
        || text_matches(&item.item_type, needle)
        || item
            .notes
            .as_deref()
            .is_some_and(|value| text_matches(value, needle))
        || item.uris.iter().any(|value| text_matches(value, needle))
        || item
            .ssh_key
            .as_ref()
            .is_some_and(|ssh_key| ssh_key_matches_search(ssh_key, needle))
        || item
            .custom_fields
            .iter()
            .any(|field| text_matches(&field.name, needle) || text_matches(&field.value, needle))
}

fn ssh_key_matches_search(ssh_key: &SshKey, needle: &str) -> bool {
    text_matches("ssh key", needle)
        || text_matches("public key", needle)
        || text_matches("fingerprint", needle)
        || text_matches("signature", needle)
        || text_matches(&ssh_key.public_key, needle)
        || ssh_key
            .fingerprint
            .as_deref()
            .is_some_and(|value| text_matches(value, needle))
}

fn text_matches(value: &str, needle: &str) -> bool {
    value.to_lowercase().contains(needle)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreloginResponse {
    kdf: u32,
    kdf_iterations: u32,
    #[serde(default)]
    kdf_memory: Option<u32>,
    #[serde(default)]
    kdf_parallelism: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(rename = "Key")]
    key: Option<String>,
    #[serde(default, rename = "UserDecryptionOptions")]
    user_decryption_options: Option<UserDecryptionOptionsResponse>,
}

impl TokenResponse {
    fn master_key_encrypted_user_key(
        &self,
    ) -> Result<(&str, Option<&MasterPasswordUnlockResponse>), BwError> {
        if let Some(unlock) = self
            .user_decryption_options
            .as_ref()
            .and_then(|options| options.master_password_unlock.as_ref())
        {
            return Ok((unlock.master_key_encrypted_user_key.as_str(), Some(unlock)));
        }

        self.key.as_deref().map(|key| (key, None)).ok_or_else(|| {
            BwError::Cli("login succeeded but the server did not return a user key".into())
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UserDecryptionOptionsResponse {
    #[serde(default)]
    master_password_unlock: Option<MasterPasswordUnlockResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MasterPasswordUnlockResponse {
    salt: String,
    #[serde(rename = "MasterKeyEncryptedUserKey")]
    master_key_encrypted_user_key: String,
    kdf: UnlockKdfConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UnlockKdfConfig {
    #[serde(rename = "KdfType")]
    kdf_type: u32,
    iterations: u32,
    #[serde(default)]
    memory: Option<u32>,
    #[serde(default)]
    parallelism: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RefreshTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
}

struct TwoFactorSubmission {
    provider: TwoFactorProvider,
    token: String,
    remember: bool,
}

enum TokenResult {
    Success(TokenResponse),
    TwoFactor(TwoFactorResponse),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TwoFactorResponse {
    #[serde(default, rename = "TwoFactorProviders")]
    providers: Vec<TwoFactorProvider>,
    #[serde(default, rename = "TwoFactorProviders2")]
    providers2: HashMap<String, serde_json::Value>,
}

impl TwoFactorResponse {
    fn available_providers(&self) -> Vec<TwoFactorProvider> {
        if !self.providers.is_empty() {
            return self.providers.clone();
        }

        let mut providers = self
            .providers2
            .keys()
            .filter_map(|key| key.parse::<i64>().ok())
            .map(two_factor_provider_from_id)
            .collect::<Vec<_>>();
        providers.sort_by_key(|provider| provider.id());
        providers
    }
}

impl<'de> Deserialize<'de> for TwoFactorProvider {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let id = match value {
            serde_json::Value::Number(number) => number.as_i64().ok_or_else(|| {
                serde::de::Error::custom("two factor provider id is not an integer")
            })?,
            serde_json::Value::String(text) => text.parse::<i64>().map_err(|e| {
                serde::de::Error::custom(format!("invalid two factor provider id: {e}"))
            })?,
            other => {
                return Err(serde::de::Error::custom(format!(
                    "invalid two factor provider id type: {other}"
                )));
            }
        };
        Ok(two_factor_provider_from_id(id))
    }
}

impl serde::Serialize for TwoFactorProvider {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i64(self.id())
    }
}

fn two_factor_provider_from_id(id: i64) -> TwoFactorProvider {
    match id {
        0 => TwoFactorProvider::Authenticator,
        1 => TwoFactorProvider::Email,
        2 => TwoFactorProvider::Duo,
        3 => TwoFactorProvider::Yubikey,
        5 => TwoFactorProvider::Remember,
        6 => TwoFactorProvider::OrganizationDuo,
        7 => TwoFactorProvider::WebAuthn,
        8 => TwoFactorProvider::RecoveryCode,
        other => TwoFactorProvider::Unknown(other),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncResponse {
    #[serde(default, alias = "Profile")]
    profile: Option<SyncProfileResponse>,
    #[serde(default, alias = "Folders")]
    folders: Vec<FolderResponse>,
    /// Kept as raw JSON: edits send the server's own cipher back with only our changes.
    #[serde(default, alias = "Ciphers")]
    ciphers: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncProfileResponse {
    #[serde(default, alias = "Organizations")]
    organizations: Vec<OrganizationResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationResponse {
    #[serde(alias = "Id")]
    id: String,
    #[serde(default, alias = "Key")]
    key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FolderResponse {
    #[serde(alias = "Id")]
    id: String,
    #[serde(alias = "Name")]
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CipherResponse {
    #[serde(alias = "Id")]
    id: String,
    #[serde(default, alias = "OrganizationId")]
    organization_id: Option<String>,
    #[serde(default, alias = "FolderId")]
    folder_id: Option<String>,
    #[serde(rename = "type", alias = "Type")]
    item_type: i64,
    #[serde(default, alias = "Favorite")]
    favorite: bool,
    #[serde(default, alias = "Name")]
    name: Option<String>,
    #[serde(default, alias = "Notes")]
    notes: Option<String>,
    #[serde(default, alias = "Fields")]
    fields: Option<Vec<FieldResponse>>,
    #[serde(default, alias = "Login")]
    login: Option<LoginResponse>,
    #[serde(default, alias = "Card")]
    card: Option<CardResponse>,
    #[serde(default, alias = "Identity")]
    identity: Option<IdentityResponse>,
    #[serde(default, alias = "SshKey", alias = "SSHKey")]
    ssh_key: Option<SshKeyResponse>,
    #[serde(default, alias = "Key")]
    key: Option<String>,
    #[serde(default, alias = "DeletedDate")]
    deleted_date: Option<String>,
    #[serde(default, alias = "ArchivedDate")]
    archived_date: Option<String>,
    #[serde(default, alias = "Data")]
    data: Option<CipherDataResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    #[serde(default, alias = "Username")]
    username: Option<String>,
    #[serde(default, alias = "Password")]
    password: Option<String>,
    #[serde(default, alias = "Uris")]
    uris: Option<Vec<LoginUriResponse>>,
    #[serde(default, alias = "Totp")]
    totp: Option<String>,
    #[serde(default, alias = "Fido2Credentials")]
    fido2_credentials: Option<Vec<Fido2CredentialResponse>>,
}

/// The parts of a stored passkey worth showing. The key material is never decrypted.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fido2CredentialResponse {
    #[serde(default, alias = "RpId")]
    rp_id: Option<String>,
    #[serde(default, alias = "RpName")]
    rp_name: Option<String>,
    #[serde(default, alias = "UserName")]
    user_name: Option<String>,
    #[serde(default, alias = "UserDisplayName")]
    user_display_name: Option<String>,
    #[serde(default, alias = "CreationDate")]
    creation_date: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginUriResponse {
    #[serde(default, alias = "Uri")]
    uri: Option<String>,
    #[serde(
        default,
        rename = "match",
        alias = "Match",
        deserialize_with = "deserialize_uri_match"
    )]
    match_type: Option<UriMatchType>,
}

fn deserialize_uri_match<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<UriMatchType>, D::Error> {
    let value = Value::deserialize(deserializer)?;
    Ok(if value.is_null() {
        None
    } else {
        Some(
            value
                .as_u64()
                .map(UriMatchType::from_bitwarden)
                .unwrap_or(UriMatchType::Unsupported),
        )
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FieldResponse {
    #[serde(default, alias = "Name")]
    name: Option<String>,
    #[serde(default, alias = "Value")]
    value: Option<String>,
    #[serde(rename = "type", alias = "Type", default)]
    field_type: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CardResponse {
    #[serde(default, alias = "CardholderName")]
    cardholder_name: Option<String>,
    #[serde(default, alias = "Number")]
    number: Option<String>,
    #[serde(default, alias = "Code")]
    code: Option<String>,
    #[serde(default, alias = "Brand")]
    brand: Option<String>,
    #[serde(default, alias = "ExpMonth")]
    exp_month: Option<String>,
    #[serde(default, alias = "ExpYear")]
    exp_year: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityResponse {
    #[serde(default, alias = "FirstName")]
    first_name: Option<String>,
    #[serde(default, alias = "MiddleName")]
    middle_name: Option<String>,
    #[serde(default, alias = "LastName")]
    last_name: Option<String>,
    #[serde(default, alias = "Username")]
    username: Option<String>,
    #[serde(default, alias = "Email")]
    email: Option<String>,
    #[serde(default, alias = "Phone")]
    phone: Option<String>,
    #[serde(default, alias = "Address1")]
    address1: Option<String>,
    #[serde(default, alias = "City")]
    city: Option<String>,
    #[serde(default, alias = "State")]
    state: Option<String>,
    #[serde(default, alias = "PostalCode")]
    postal_code: Option<String>,
    #[serde(default, alias = "Country")]
    country: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SshKeyResponse {
    #[serde(default, alias = "PrivateKey")]
    private_key: Option<String>,
    #[serde(default, alias = "PublicKey")]
    public_key: Option<String>,
    #[serde(default, alias = "KeyFingerprint", alias = "Fingerprint")]
    key_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CipherDataResponse {
    #[serde(default, alias = "Name")]
    name: Option<String>,
    #[serde(default, alias = "Notes")]
    notes: Option<String>,
    #[serde(default, alias = "Fields")]
    fields: Option<Vec<FieldResponse>>,
    #[serde(default, alias = "Username")]
    username: Option<String>,
    #[serde(default, alias = "Password")]
    password: Option<String>,
    #[serde(default, alias = "Uris")]
    uris: Option<Vec<LoginUriResponse>>,
    #[serde(default, alias = "Totp")]
    totp: Option<String>,
    #[serde(default, alias = "Fido2Credentials")]
    fido2_credentials: Option<Vec<Fido2CredentialResponse>>,
    #[serde(default, alias = "CardholderName")]
    cardholder_name: Option<String>,
    #[serde(default, alias = "Number")]
    number: Option<String>,
    #[serde(default, alias = "Code")]
    code: Option<String>,
    #[serde(default, alias = "Brand")]
    brand: Option<String>,
    #[serde(default, alias = "ExpMonth")]
    exp_month: Option<String>,
    #[serde(default, alias = "ExpYear")]
    exp_year: Option<String>,
    #[serde(default, alias = "FirstName")]
    first_name: Option<String>,
    #[serde(default, alias = "MiddleName")]
    middle_name: Option<String>,
    #[serde(default, alias = "LastName")]
    last_name: Option<String>,
    #[serde(default, alias = "Email")]
    email: Option<String>,
    #[serde(default, alias = "Phone")]
    phone: Option<String>,
    #[serde(default, alias = "Address1")]
    address1: Option<String>,
    #[serde(default, alias = "City")]
    city: Option<String>,
    #[serde(default, alias = "State")]
    state: Option<String>,
    #[serde(default, alias = "PostalCode")]
    postal_code: Option<String>,
    #[serde(default, alias = "Country")]
    country: Option<String>,
    #[serde(default, alias = "SshKey", alias = "SSHKey")]
    ssh_key: Option<SshKeyResponse>,
    #[serde(default, alias = "PrivateKey")]
    private_key: Option<String>,
    #[serde(default, alias = "PublicKey")]
    public_key: Option<String>,
    #[serde(default, alias = "KeyFingerprint", alias = "Fingerprint")]
    key_fingerprint: Option<String>,
}

fn decrypt_folders(
    folders: Vec<FolderResponse>,
    user_key: &[u8],
) -> Result<HashMap<String, String>, BwError> {
    folders
        .into_iter()
        .map(|folder| {
            let name = decrypt_string(&folder.name, user_key)?.unwrap_or_default();
            Ok((folder.id, name))
        })
        .collect()
}

fn decrypt_organization_keys(
    profile: Option<SyncProfileResponse>,
    user_key: &[u8],
) -> Result<HashMap<String, Vec<u8>>, BwError> {
    profile
        .map(|profile| profile.organizations)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|organization| {
            organization
                .key
                .map(|key| Ok((organization.id, decrypt_symmetric_key(&key, user_key)?)))
        })
        .collect()
}

#[cfg(test)]
fn decrypt_cipher(
    cipher: CipherResponse,
    user_key: &[u8],
    organization_keys: &HashMap<String, Vec<u8>>,
    folders: &HashMap<String, String>,
) -> Result<BwItemDetail, BwError> {
    decrypt_cipher_with_uri_rules(cipher, user_key, organization_keys, folders)
        .map(|(detail, _)| detail)
}

fn decrypt_cipher_with_uri_rules(
    cipher: CipherResponse,
    user_key: &[u8],
    organization_keys: &HashMap<String, Vec<u8>>,
    folders: &HashMap<String, String>,
) -> Result<(BwItemDetail, Vec<LoginUri>), BwError> {
    let item_key = cipher_item_key(&cipher, user_key, organization_keys)?;
    let state = cipher_state(&cipher);
    let state_changed_at = match state {
        ItemState::Deleted => cipher.deleted_date.clone(),
        ItemState::Archived => cipher.archived_date.clone(),
        ItemState::Active => None,
    };
    let data = cipher.data.as_ref();
    let encrypted_name = data
        .and_then(|data| data.name.as_deref())
        .or(cipher.name.as_deref())
        .ok_or_else(|| BwError::Parse("cipher is missing encrypted name".into()))?;
    let encrypted_notes = data
        .and_then(|data| data.notes.as_deref())
        .or(cipher.notes.as_deref());
    let name = decrypt_string(encrypted_name, &item_key)?.unwrap_or_default();
    let notes = decrypt_opt_string(encrypted_notes, &item_key)?;
    let mut username = None;
    let mut password = None;
    let mut uris = Vec::new();
    let mut totp = None;
    let mut ssh_key = None;
    let mut passkeys = Vec::new();

    if let Some(data) = data {
        username = decrypt_opt_string(data.username.as_deref(), &item_key)?;
        password = decrypt_opt_string(data.password.as_deref(), &item_key)?;
        totp = decrypt_opt_string(data.totp.as_deref(), &item_key)?;
        uris = decrypt_uris(data.uris.as_deref(), &item_key)?;
        passkeys = decrypt_passkeys(data.fido2_credentials.as_deref(), &item_key)?;
        if let Some(ssh_response) = data.ssh_key.as_ref() {
            ssh_key = decrypt_ssh_key_data(
                cipher.id.as_str(),
                &name,
                ssh_response.private_key.as_deref(),
                ssh_response.public_key.as_deref(),
                ssh_response.key_fingerprint.as_deref(),
                &item_key,
            )?;
        } else {
            ssh_key = decrypt_ssh_key_data(
                cipher.id.as_str(),
                &name,
                data.private_key.as_deref(),
                data.public_key.as_deref(),
                data.key_fingerprint.as_deref(),
                &item_key,
            )?;
        }
    }

    if let Some(login) = cipher.login {
        username = decrypt_opt_string(login.username.as_deref(), &item_key)?;
        password = decrypt_opt_string(login.password.as_deref(), &item_key)?;
        totp = decrypt_opt_string(login.totp.as_deref(), &item_key)?;
        uris = decrypt_uris(login.uris.as_deref(), &item_key)?;
        passkeys = decrypt_passkeys(login.fido2_credentials.as_deref(), &item_key)?;
    }

    if let Some(ssh_response) = cipher.ssh_key {
        ssh_key = decrypt_ssh_key_data(
            cipher.id.as_str(),
            &name,
            ssh_response.private_key.as_deref(),
            ssh_response.public_key.as_deref(),
            ssh_response.key_fingerprint.as_deref(),
            &item_key,
        )?;
    }

    let field_responses = data
        .and_then(|data| data.fields.as_deref())
        .or(cipher.fields.as_deref())
        .unwrap_or(&[]);
    let mut custom_fields = decrypt_custom_fields(field_responses, &item_key)?;

    if let Some(data) = data {
        push_card_field(
            &mut custom_fields,
            "Cardholder",
            data.cardholder_name.clone(),
            &item_key,
            false,
        )?;
        push_card_field(
            &mut custom_fields,
            "Number",
            data.number.clone(),
            &item_key,
            false,
        )?;
        push_card_field(
            &mut custom_fields,
            "Brand",
            data.brand.clone(),
            &item_key,
            false,
        )?;
        push_card_field(
            &mut custom_fields,
            "Exp Month",
            data.exp_month.clone(),
            &item_key,
            false,
        )?;
        push_card_field(
            &mut custom_fields,
            "Exp Year",
            data.exp_year.clone(),
            &item_key,
            false,
        )?;
        push_card_field(
            &mut custom_fields,
            "CVV",
            data.code.clone(),
            &item_key,
            true,
        )?;
        push_identity_data_fields(&mut custom_fields, data, &item_key)?;
    }

    if let Some(card) = cipher.card {
        push_card_field(
            &mut custom_fields,
            "Cardholder",
            card.cardholder_name,
            &item_key,
            false,
        )?;
        push_card_field(&mut custom_fields, "Number", card.number, &item_key, false)?;
        push_card_field(&mut custom_fields, "Brand", card.brand, &item_key, false)?;
        push_card_field(
            &mut custom_fields,
            "Exp Month",
            card.exp_month,
            &item_key,
            false,
        )?;
        push_card_field(
            &mut custom_fields,
            "Exp Year",
            card.exp_year,
            &item_key,
            false,
        )?;
        push_card_field(&mut custom_fields, "CVV", card.code, &item_key, true)?;
    }

    if let Some(identity) = cipher.identity {
        push_identity_fields(&mut custom_fields, identity, &item_key)?;
    }

    let browser_uris = uris;
    Ok((
        BwItemDetail {
            id: cipher.id,
            name,
            username,
            password,
            uris: browser_uris.iter().map(|uri| uri.uri.clone()).collect(),
            totp,
            notes,
            custom_fields,
            folder: cipher
                .folder_id
                .as_ref()
                .and_then(|id| folders.get(id).cloned().or(Some(id.clone()))),
            folder_id: cipher.folder_id,
            favorite: cipher.favorite,
            passkeys,
            item_type: item_type_name(cipher.item_type).to_string(),
            ssh_key,
            state,
            dates: ItemDates {
                state_changed_at,
                ..ItemDates::default()
            },
        },
        browser_uris,
    ))
}

/// The key the cipher's fields are encrypted with: its own key when it has one, otherwise
/// the organization key or the user key.
fn cipher_item_key(
    cipher: &CipherResponse,
    user_key: &[u8],
    organization_keys: &HashMap<String, Vec<u8>>,
) -> Result<Vec<u8>, BwError> {
    let wrapping_key = match cipher.organization_id.as_deref() {
        Some(organization_id) => organization_keys.get(organization_id).ok_or_else(|| {
            BwError::Cli(format!(
                "organization cipher {organization_id} is missing an organization key"
            ))
        })?,
        None => user_key,
    };
    match &cipher.key {
        Some(key) => decrypt_symmetric_key(key, wrapping_key),
        None => Ok(wrapping_key.to_vec()),
    }
}

fn cipher_state(cipher: &CipherResponse) -> ItemState {
    if cipher.deleted_date.is_some() {
        ItemState::Deleted
    } else if cipher.archived_date.is_some() {
        ItemState::Archived
    } else {
        ItemState::Active
    }
}

fn decode_cipher(
    raw: Value,
    user_key: &[u8],
    organization_keys: &HashMap<String, Vec<u8>>,
    folders: &HashMap<String, String>,
) -> Result<(BwItemDetail, StoredCipher), BwError> {
    let cipher: CipherResponse =
        serde_json::from_value(raw.clone()).map_err(|e| BwError::Parse(format!("cipher: {e}")))?;
    let item_key = cipher_item_key(&cipher, user_key, organization_keys)?;
    let (mut detail, browser_uris) =
        decrypt_cipher_with_uri_rules(cipher, user_key, organization_keys, folders)?;
    let revision_date = raw_get(&raw, "revisionDate")
        .and_then(Value::as_str)
        .map(str::to_string);
    detail.dates.revision_date = revision_date.clone();
    detail.dates.creation_date = raw_get(&raw, "creationDate")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok((
        detail,
        StoredCipher {
            raw,
            item_key,
            revision_date,
            browser_uris,
        },
    ))
}

/// Hash the encrypted source, not plaintext passwords or server timestamps alone.
/// This also detects changes from servers that omit revisionDate.
fn browser_revision(stored: &StoredCipher) -> Result<String, BwError> {
    let source = serde_json::to_vec(&stored.raw)
        .map_err(|error| BwError::Parse(format!("cipher revision: {error}")))?;
    let hash = <Sha256 as sha2::Digest>::digest(source);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash))
}

fn browser_uri_match(
    stored: &StoredCipher,
    frame_url: &str,
    default_match: UriMatchType,
) -> Option<bool> {
    let mut insecure_downgrade = None;
    for uri in &stored.browser_uris {
        let result =
            uri_match::matches(&uri.uri, uri.match_type.unwrap_or(default_match), frame_url);
        if result.matched {
            insecure_downgrade =
                Some(insecure_downgrade.unwrap_or(false) || result.insecure_downgrade);
        }
    }
    insecure_downgrade
}

pub(crate) fn action_allowed(action: ItemAction, state: ItemState) -> bool {
    match action {
        ItemAction::Archive => state == ItemState::Active,
        ItemAction::Unarchive => state == ItemState::Archived,
        ItemAction::Trash => state != ItemState::Deleted,
        ItemAction::Restore | ItemAction::DeleteForever => state == ItemState::Deleted,
        ItemAction::Favorite | ItemAction::Unfavorite => state != ItemState::Deleted,
    }
}

pub(crate) fn state_after(action: ItemAction, state: ItemState) -> ItemState {
    match action {
        ItemAction::Archive => ItemState::Archived,
        ItemAction::Trash | ItemAction::DeleteForever => ItemState::Deleted,
        ItemAction::Unarchive | ItemAction::Restore => ItemState::Active,
        ItemAction::Favorite | ItemAction::Unfavorite => state,
    }
}

fn folder_path(id: &str) -> Result<String, BwError> {
    if id.is_empty() || !id.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-') {
        return Err(BwError::Cli(format!("invalid folder id {id:?}")));
    }
    Ok(format!("/api/folders/{id}"))
}

/// Trims each level of a "Parent/Child" folder name and rejects empty levels.
pub(crate) fn validate_folder_name(name: &str) -> Result<String, BwError> {
    let parts = name.split('/').map(str::trim).collect::<Vec<_>>();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(BwError::Cli(
            "folder names can't be empty or start or end with /".into(),
        ));
    }
    Ok(parts.join("/"))
}

/// Cipher ids are UUIDs; anything else must not end up in a request path.
fn cipher_path(id: &str) -> Result<String, BwError> {
    if id.is_empty() || !id.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-') {
        return Err(BwError::Cli(format!("invalid item id {id:?}")));
    }
    Ok(format!("/api/ciphers/{id}"))
}

fn looks_like_cipher(value: &Value) -> bool {
    raw_get(value, "id").is_some() && raw_get(value, "type").is_some()
}

fn expect_success(response: Response, what: &str) -> Result<Response, BwError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().unwrap_or_default();
    Err(BwError::Cli(format!(
        "{what} failed with HTTP {}: {}",
        status.as_u16(),
        server_error_message(&body)
    )))
}

/// Bitwarden and Vaultwarden put a readable reason in `message`; fall back to the body.
fn server_error_message(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            raw_get(&value, "message")
                .and_then(Value::as_str)
                .filter(|message| !message.trim().is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| body.chars().take(200).collect())
}

fn raw_set(value: &mut Value, key: &str, data: Value) {
    if let Some(object) = value.as_object_mut() {
        let pascal = key[..1].to_ascii_uppercase() + &key[1..];
        object.remove(&pascal);
        object.insert(key.into(), data);
    }
}

/// Reads a key from server JSON, which uses camelCase but older servers use PascalCase.
fn raw_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let object = value.as_object()?;
    object
        .get(key)
        .or_else(|| {
            let mut chars = key.chars();
            let pascal = chars
                .next()
                .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())?;
            object.get(&pascal)
        })
        .filter(|value| !value.is_null())
}

fn passkey_error(error: crate::passkeys::PasskeyError) -> BwError {
    BwError::Cli(error.message.into())
}

fn stored_passkeys(stored: &StoredCipher) -> impl Iterator<Item = &Value> {
    raw_get(&stored.raw, "login")
        .and_then(|login| raw_get(login, "fido2Credentials"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn passkey_field(raw: &Value, field: &str, key: &[u8]) -> Result<String, BwError> {
    passkey_optional_field(raw, field, key)?
        .ok_or_else(|| BwError::Parse("missing passkey field".into()))
}

fn passkey_optional_field(raw: &Value, field: &str, key: &[u8]) -> Result<Option<String>, BwError> {
    let Some(value) = raw_get(raw, field) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .filter(|value| value.len() <= 32_768)
        .ok_or_else(|| BwError::Parse("invalid passkey field".into()))?;
    decrypt_string(value, key)
}

fn decode_browser_passkey(
    raw: &Value,
    key: &[u8],
    rp_id: &str,
) -> Result<PasskeyMaterial, BwError> {
    use p256::pkcs8::DecodePrivateKey;
    let unsupported = || BwError::Cli("This passkey format is not supported by Boltwarden".into());
    if passkey_field(raw, "rpId", key)? != rp_id {
        return Err(BwError::NotFound);
    }
    if passkey_field(raw, "keyType", key)? != "public-key"
        || passkey_field(raw, "keyAlgorithm", key)? != "ECDSA"
        || passkey_field(raw, "keyCurve", key)? != "P-256"
        || passkey_field(raw, "counter", key)? != "0"
    {
        return Err(unsupported());
    }
    let discoverable = match passkey_field(raw, "discoverable", key)?.as_str() {
        "true" => true,
        "false" => false,
        _ => return Err(unsupported()),
    };
    let credential_id = crate::passkeys::credential_id(&passkey_field(raw, "credentialId", key)?)
        .map_err(passkey_error)?;
    let user_handle = passkey_optional_field(raw, "userHandle", key)?
        .map(|value| crate::passkeys::decode(&value, 64).map_err(passkey_error))
        .transpose()?;
    if user_handle.as_ref().is_some_and(Vec::is_empty) || (discoverable && user_handle.is_none()) {
        return Err(unsupported());
    }
    // The decrypted key and its DER representation exist only for this operation.
    // They never become part of BwItemDetail, diagnostics, or a wire response.
    let encoded = Zeroizing::new(passkey_field(raw, "keyValue", key)?);
    let pkcs8_der = Zeroizing::new(crate::passkeys::decode(&encoded, 4096).map_err(passkey_error)?);
    p256::SecretKey::from_pkcs8_der(&pkcs8_der).map_err(|_| unsupported())?;
    Ok(PasskeyMaterial {
        credential_id,
        user_handle,
        user_name: passkey_optional_field(raw, "userName", key)?,
        user_display_name: passkey_optional_field(raw, "userDisplayName", key)?,
        discoverable,
        pkcs8_der,
    })
}

fn passkey_requested(credential: &PasskeyMaterial, allow_ids: &[Vec<u8>]) -> bool {
    if allow_ids.is_empty() {
        credential.discoverable
    } else {
        allow_ids.contains(&credential.credential_id)
    }
}

fn build_passkey_create_request(
    context: &crate::passkeys::ValidatedRequest,
    options: &crate::passkeys::CreateOptions,
    generated: &crate::passkeys::GeneratedCredential,
    key: &[u8],
) -> Result<Value, BwError> {
    let credential_id = uuid::Uuid::from_slice(&generated.credential_id)
        .map_err(|_| BwError::Parse("invalid generated passkey ID".into()))?
        .hyphenated()
        .to_string();
    let private_key = Zeroizing::new(crate::passkeys::encode(&generated.pkcs8_der));
    Ok(json!({
        "type": 1,
        "organizationId": null,
        "folderId": null,
        "name": encrypt_value(if options.rp.name.is_empty() { &context.rp_id } else { &options.rp.name }, key)?,
        "notes": null,
        "favorite": false,
        "reprompt": 0,
        "fields": null,
        "login": {
            "username": encrypt_value(&options.user.name, key)?,
            "password": null,
            "totp": null,
            "uris": [{
                "uri": encrypt_value(&context.origin, key)?,
                "uriChecksum": uri_checksum(&context.origin, key)?,
                "match": null,
            }],
            "fido2Credentials": [{
                "credentialId": encrypt_value(&credential_id, key)?,
                "keyType": encrypt_value("public-key", key)?,
                "keyAlgorithm": encrypt_value("ECDSA", key)?,
                "keyCurve": encrypt_value("P-256", key)?,
                "keyValue": encrypt_value(&private_key, key)?,
                "rpId": encrypt_value(&context.rp_id, key)?,
                "userHandle": encrypt_value(&options.user.id, key)?,
                "userName": encrypt_value(&options.user.name, key)?,
                "userDisplayName": encrypt_value(&options.user.display_name, key)?,
                "counter": encrypt_value("0", key)?,
                "rpName": encrypt_value(&options.rp.name, key)?,
                "discoverable": encrypt_value("true", key)?,
                "creationDate": iso8601_now(),
            }],
        },
        "secureNote": null,
    }))
}

fn raw_decrypt(value: &Value, key: &str, item_key: &[u8]) -> Result<String, BwError> {
    Ok(
        decrypt_opt_string(raw_get(value, key).and_then(Value::as_str), item_key)?
            .unwrap_or_default(),
    )
}

/// The type-specific object each item type must carry at the top level.
fn type_object_key(item_type: i64) -> Option<&'static str> {
    match item_type {
        1 => Some("login"),
        2 => Some("secureNote"),
        3 => Some("card"),
        4 => Some("identity"),
        5 => Some("sshKey"),
        _ => None,
    }
}

/// Edits are sent as the server's own JSON with our changes applied. That only works
/// for the current camelCase format with the type data at the top level; anything else
/// could lose data, so it is refused.
fn ensure_editable(raw: &Value) -> Result<(), BwError> {
    let unsupported =
        || BwError::Cli("this item uses a server format that can't be edited here".into());
    let object = raw.as_object().ok_or_else(unsupported)?;
    let item_type = object
        .get("type")
        .and_then(Value::as_i64)
        .ok_or_else(unsupported)?;
    let type_key = type_object_key(item_type).ok_or_else(unsupported)?;
    if !object.get("name").is_some_and(Value::is_string) {
        return Err(unsupported());
    }
    if !object.get(type_key).is_some_and(Value::is_object) {
        return Err(unsupported());
    }
    Ok(())
}

fn draft_from_raw(raw: &Value, item_key: &[u8]) -> Result<ItemDraft, BwError> {
    let login = match raw_get(raw, "type").and_then(Value::as_i64) {
        Some(1) => {
            let login = raw_get(raw, "login").cloned().unwrap_or(Value::Null);
            let uris = raw_get(&login, "uris")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[])
                .iter()
                .enumerate()
                .map(|(idx, uri)| {
                    Ok(DraftUri {
                        uri: raw_decrypt(uri, "uri", item_key)?,
                        original_index: Some(idx),
                    })
                })
                .collect::<Result<Vec<_>, BwError>>()?;
            let credentials: Option<Vec<Fido2CredentialResponse>> =
                raw_get(&login, "fido2Credentials")
                    .map(|value| serde_json::from_value(value.clone()))
                    .transpose()
                    .map_err(|e| BwError::Parse(format!("passkeys: {e}")))?;
            let passkeys = decrypt_passkeys(credentials.as_deref(), item_key)?
                .into_iter()
                .enumerate()
                .map(|(original_index, passkey)| DraftPasskey {
                    passkey,
                    original_index,
                })
                .collect();
            Some(LoginDraft {
                username: raw_decrypt(&login, "username", item_key)?,
                password: raw_decrypt(&login, "password", item_key)?,
                totp: raw_decrypt(&login, "totp", item_key)?,
                uris,
                passkeys,
            })
        }
        _ => None,
    };
    let fields = raw_get(raw, "fields")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .enumerate()
        .map(|(idx, field)| {
            Ok(DraftField {
                name: raw_decrypt(field, "name", item_key)?,
                value: raw_decrypt(field, "value", item_key)?,
                kind: DraftFieldKind::from_type(
                    raw_get(field, "type").and_then(Value::as_i64).unwrap_or(0),
                ),
                original_index: Some(idx),
            })
        })
        .collect::<Result<Vec<_>, BwError>>()?;
    Ok(ItemDraft {
        name: raw_decrypt(raw, "name", item_key)?,
        notes: raw_decrypt(raw, "notes", item_key)?,
        login,
        fields,
        folder_id: raw_get(raw, "folderId")
            .and_then(Value::as_str)
            .map(str::to_string),
        favorite: raw_get(raw, "favorite")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn encrypt_value(plaintext: &str, key: &[u8]) -> Result<Value, BwError> {
    encrypt_string(plaintext, key).map(Value::String)
}

/// Empty text is stored as null, the way the official clients do.
fn encrypt_optional(plaintext: &str, key: &[u8]) -> Result<Value, BwError> {
    if plaintext.is_empty() {
        Ok(Value::Null)
    } else {
        encrypt_value(plaintext, key)
    }
}

fn uri_checksum(uri: &str, key: &[u8]) -> Result<Value, BwError> {
    let digest = <Sha256 as sha2::Digest>::digest(uri.as_bytes());
    encrypt_value(
        &base64::engine::general_purpose::STANDARD.encode(digest),
        key,
    )
}

fn validate_draft(draft: &ItemDraft) -> Result<(), BwError> {
    if draft.name.trim().is_empty() {
        return Err(BwError::Cli("name is required".into()));
    }
    if draft
        .fields
        .iter()
        .any(|field| field.name.trim().is_empty() && !field.value.is_empty())
    {
        return Err(BwError::Cli(
            "custom fields with a value need a name".into(),
        ));
    }
    Ok(())
}

/// Builds the `POST /api/ciphers` body for a new personal item: a login when the draft
/// has login data, otherwise a secure note. Everything is encrypted with the user key.
fn build_create_request(draft: &ItemDraft, key: &[u8]) -> Result<Value, BwError> {
    validate_draft(draft)?;
    let fields = draft
        .fields
        .iter()
        .filter(|field| !field.name.trim().is_empty())
        .map(|field| {
            let kind = match field.kind {
                DraftFieldKind::Linked => DraftFieldKind::Text,
                kind => kind,
            };
            Ok(json!({
                "type": kind.type_id(),
                "name": encrypt_value(&field.name, key)?,
                "value": encrypt_optional(&field.value, key)?,
                "linkedId": null,
            }))
        })
        .collect::<Result<Vec<_>, BwError>>()?;
    let mut body = json!({
        "type": if draft.login.is_some() { 1 } else { 2 },
        "organizationId": null,
        "folderId": draft.folder_id,
        "name": encrypt_value(&draft.name, key)?,
        "notes": encrypt_optional(&draft.notes, key)?,
        "favorite": draft.favorite,
        "reprompt": 0,
        "fields": if fields.is_empty() { Value::Null } else { Value::Array(fields) },
        "login": null,
        "secureNote": null,
    });
    match &draft.login {
        Some(login) => {
            let uris = login
                .uris
                .iter()
                .filter(|uri| !uri.uri.trim().is_empty())
                .map(|uri| {
                    Ok(json!({
                        "uri": encrypt_value(&uri.uri, key)?,
                        "uriChecksum": uri_checksum(&uri.uri, key)?,
                        "match": null,
                    }))
                })
                .collect::<Result<Vec<_>, BwError>>()?;
            body["login"] = json!({
                "username": encrypt_optional(&login.username, key)?,
                "password": encrypt_optional(&login.password, key)?,
                "totp": encrypt_optional(&login.totp, key)?,
                "uris": if uris.is_empty() { Value::Null } else { Value::Array(uris) },
            });
        }
        None => body["secureNote"] = json!({ "type": 0 }),
    }
    Ok(body)
}

/// Builds the `PUT /api/ciphers/{id}` body: the stored cipher with only the fields that
/// differ from the stored plaintext re-encrypted. Everything else (passkeys, URI match
/// rules, favorite, reprompt, per-cipher key, ...) is sent back untouched.
fn build_save_request(
    stored: &StoredCipher,
    draft: &ItemDraft,
    now: &str,
) -> Result<Value, BwError> {
    ensure_editable(&stored.raw)?;
    let key = stored.item_key.as_slice();
    let original = draft_from_raw(&stored.raw, key)?;
    validate_draft(draft)?;

    let mut body = stored.raw.as_object().cloned().unwrap_or_default();
    // Vaultwarden's duplicate of the item data; the request only reads the top level.
    body.remove("data");

    if draft.name != original.name {
        body.insert("name".into(), encrypt_value(&draft.name, key)?);
    }
    if draft.notes != original.notes {
        body.insert("notes".into(), encrypt_optional(&draft.notes, key)?);
    }
    if draft.folder_id != original.folder_id {
        body.insert("folderId".into(), json!(draft.folder_id));
    }
    if draft.favorite != original.favorite {
        body.insert("favorite".into(), Value::Bool(draft.favorite));
    }

    if let (Some(new), Some(old)) = (&draft.login, &original.login) {
        let mut login = body
            .get("login")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if new.username != old.username {
            login.insert("username".into(), encrypt_optional(&new.username, key)?);
        }
        if new.totp != old.totp {
            login.insert("totp".into(), encrypt_optional(&new.totp, key)?);
        }
        if new.password != old.password {
            login.insert("password".into(), encrypt_optional(&new.password, key)?);
            login.insert("passwordRevisionDate".into(), Value::String(now.into()));
            if !old.password.is_empty() {
                let mut history = body
                    .get("passwordHistory")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                history.insert(
                    0,
                    json!({ "password": encrypt_value(&old.password, key)?, "lastUsedDate": now }),
                );
                history.truncate(PASSWORD_HISTORY_LIMIT);
                body.insert("passwordHistory".into(), Value::Array(history));
            }
        }
        let raw_uris = login
            .get("uris")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut uris = Vec::new();
        for uri in new.uris.iter().filter(|uri| !uri.uri.trim().is_empty()) {
            let source = uri
                .original_index
                .and_then(|idx| Some((raw_uris.get(idx)?, old.uris.get(idx)?)));
            match source {
                Some((raw_uri, old_uri)) if old_uri.uri == uri.uri => uris.push(raw_uri.clone()),
                Some((raw_uri, _)) => {
                    let mut entry = raw_uri.as_object().cloned().unwrap_or_default();
                    entry.insert("uri".into(), encrypt_value(&uri.uri, key)?);
                    entry.insert("uriChecksum".into(), uri_checksum(&uri.uri, key)?);
                    uris.push(Value::Object(entry));
                }
                None => uris.push(json!({
                    "uri": encrypt_value(&uri.uri, key)?,
                    "uriChecksum": uri_checksum(&uri.uri, key)?,
                    "match": null,
                })),
            }
        }
        login.insert(
            "uris".into(),
            if uris.is_empty() {
                Value::Null
            } else {
                Value::Array(uris)
            },
        );
        // Passkeys can only be removed. Kept ones go back exactly as stored.
        if new.passkeys != old.passkeys {
            let raw_passkeys = login
                .get("fido2Credentials")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if new
                .passkeys
                .iter()
                .any(|passkey| passkey.original_index >= raw_passkeys.len())
            {
                return Err(BwError::Cli("passkeys can't be added here".into()));
            }
            let kept = raw_passkeys
                .into_iter()
                .enumerate()
                .filter(|(idx, _)| {
                    new.passkeys
                        .iter()
                        .any(|passkey| passkey.original_index == *idx)
                })
                .map(|(_, raw)| raw)
                .collect::<Vec<_>>();
            login.insert(
                "fido2Credentials".into(),
                if kept.is_empty() {
                    Value::Null
                } else {
                    Value::Array(kept)
                },
            );
        }
        body.insert("login".into(), Value::Object(login));
    }

    let raw_fields = body
        .get("fields")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut fields = Vec::new();
    for field in &draft.fields {
        if field.original_index.is_none() && field.name.trim().is_empty() {
            continue;
        }
        let source = field
            .original_index
            .and_then(|idx| Some((raw_fields.get(idx)?, original.fields.get(idx)?)));
        match source {
            Some((raw_field, old_field)) => {
                let mut entry = raw_field.as_object().cloned().unwrap_or_default();
                if field.name != old_field.name {
                    entry.insert("name".into(), encrypt_optional(&field.name, key)?);
                }
                if field.kind != DraftFieldKind::Linked && field.value != old_field.value {
                    entry.insert("value".into(), encrypt_optional(&field.value, key)?);
                }
                entry.insert("type".into(), json!(field.kind.type_id()));
                fields.push(Value::Object(entry));
            }
            None => {
                // A new field has nothing to link to, so it can't be a linked field.
                let kind = match field.kind {
                    DraftFieldKind::Linked => DraftFieldKind::Text,
                    kind => kind,
                };
                fields.push(json!({
                    "type": kind.type_id(),
                    "name": encrypt_optional(&field.name, key)?,
                    "value": encrypt_optional(&field.value, key)?,
                    "linkedId": null,
                }));
            }
        }
    }
    body.insert(
        "fields".into(),
        if fields.is_empty() {
            Value::Null
        } else {
            Value::Array(fields)
        },
    );

    if let Some(revision) = &stored.revision_date {
        body.insert(
            "lastKnownRevisionDate".into(),
            Value::String(revision.clone()),
        );
    }
    Ok(Value::Object(body))
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SS.mmmZ`, the format the server uses.
pub(crate) fn iso8601_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    iso8601_from_unix_ms(now.as_millis() as i64)
}

fn iso8601_from_unix_ms(unix_ms: i64) -> String {
    let secs = unix_ms.div_euclid(1000);
    let millis = unix_ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let second_of_day = secs.rem_euclid(86_400);
    // Civil-from-days, from Howard Hinnant's date algorithms.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        second_of_day / 3600,
        second_of_day % 3600 / 60,
        second_of_day % 60
    )
}

fn decrypt_ssh_key_data(
    id: &str,
    name: &str,
    encrypted_private_key: Option<&str>,
    encrypted_public_key: Option<&str>,
    encrypted_fingerprint: Option<&str>,
    key: &[u8],
) -> Result<Option<SshKey>, BwError> {
    let Some(private_key) = decrypt_opt_string(encrypted_private_key, key)? else {
        return Ok(None);
    };
    let Some(public_key) = decrypt_opt_string(encrypted_public_key, key)? else {
        return Ok(None);
    };
    let fingerprint = decrypt_opt_string(encrypted_fingerprint, key)?;
    Ok(Some(SshKey {
        id: id.to_string(),
        name: name.to_string(),
        public_key,
        private_key,
        fingerprint,
    }))
}

fn push_card_field(
    fields: &mut Vec<CustomField>,
    name: &str,
    encrypted_value: Option<String>,
    key: &[u8],
    hidden: bool,
) -> Result<(), BwError> {
    if let Some(value) = decrypt_opt_string(encrypted_value.as_deref(), key)? {
        fields.push(CustomField {
            name: name.to_string(),
            value,
            hidden,
        });
    }
    Ok(())
}

fn decrypt_passkeys(
    credentials: Option<&[Fido2CredentialResponse]>,
    key: &[u8],
) -> Result<Vec<Passkey>, BwError> {
    credentials
        .unwrap_or(&[])
        .iter()
        .map(|credential| {
            Ok(Passkey {
                rp_id: decrypt_opt_string(credential.rp_id.as_deref(), key)?.unwrap_or_default(),
                rp_name: decrypt_opt_string(credential.rp_name.as_deref(), key)?,
                user_name: decrypt_opt_string(credential.user_name.as_deref(), key)?,
                user_display_name: decrypt_opt_string(
                    credential.user_display_name.as_deref(),
                    key,
                )?,
                creation_date: credential.creation_date.clone(),
            })
        })
        .collect()
}

fn decrypt_uris(uris: Option<&[LoginUriResponse]>, key: &[u8]) -> Result<Vec<LoginUri>, BwError> {
    uris.unwrap_or(&[])
        .iter()
        .filter_map(|uri| {
            decrypt_opt_string(uri.uri.as_deref(), key)
                .map(|value| {
                    value.map(|value| LoginUri {
                        uri: value,
                        match_type: uri.match_type,
                    })
                })
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()
}

fn decrypt_custom_fields(
    fields: &[FieldResponse],
    key: &[u8],
) -> Result<Vec<CustomField>, BwError> {
    fields
        .iter()
        .map(|field| {
            let name = decrypt_opt_string(field.name.as_deref(), key)?.unwrap_or_default();
            let value = decrypt_opt_string(field.value.as_deref(), key)?.unwrap_or_default();
            Ok(CustomField {
                name,
                value,
                hidden: field.field_type == Some(1),
            })
        })
        .collect()
}

fn push_identity_fields(
    fields: &mut Vec<CustomField>,
    identity: IdentityResponse,
    key: &[u8],
) -> Result<(), BwError> {
    let first = decrypt_opt_string(identity.first_name.as_deref(), key)?;
    let middle = decrypt_opt_string(identity.middle_name.as_deref(), key)?;
    let last = decrypt_opt_string(identity.last_name.as_deref(), key)?;
    let full = [first.as_deref(), middle.as_deref(), last.as_deref()]
        .into_iter()
        .flatten()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if !full.is_empty() {
        fields.push(CustomField {
            name: "Full Name".into(),
            value: full,
            hidden: false,
        });
    }

    let rest = [
        ("Username", identity.username),
        ("Email", identity.email),
        ("Phone", identity.phone),
        ("Address", identity.address1),
        ("City", identity.city),
        ("State", identity.state),
        ("Postal Code", identity.postal_code),
        ("Country", identity.country),
    ];
    for (label, encrypted) in rest {
        push_card_field(fields, label, encrypted, key, false)?;
    }
    Ok(())
}

fn push_identity_data_fields(
    fields: &mut Vec<CustomField>,
    identity: &CipherDataResponse,
    key: &[u8],
) -> Result<(), BwError> {
    let first = decrypt_opt_string(identity.first_name.as_deref(), key)?;
    let middle = decrypt_opt_string(identity.middle_name.as_deref(), key)?;
    let last = decrypt_opt_string(identity.last_name.as_deref(), key)?;
    let full = [first.as_deref(), middle.as_deref(), last.as_deref()]
        .into_iter()
        .flatten()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if !full.is_empty() {
        fields.push(CustomField {
            name: "Full Name".into(),
            value: full,
            hidden: false,
        });
    }

    let rest = [
        ("Email", identity.email.as_deref()),
        ("Phone", identity.phone.as_deref()),
        ("Address", identity.address1.as_deref()),
        ("City", identity.city.as_deref()),
        ("State", identity.state.as_deref()),
        ("Postal Code", identity.postal_code.as_deref()),
        ("Country", identity.country.as_deref()),
    ];
    for (label, encrypted) in rest {
        if let Some(value) = decrypt_opt_string(encrypted, key)? {
            fields.push(CustomField {
                name: label.into(),
                value,
                hidden: false,
            });
        }
    }
    Ok(())
}

fn item_type_name(item_type: i64) -> &'static str {
    match item_type {
        1 => "login",
        2 => "secureNote",
        3 => "card",
        4 => "identity",
        5 => "sshKey",
        _ => "other",
    }
}

fn normalize_server_url(server_url: &str) -> Result<String, BwError> {
    let parsed = Url::parse(server_url.trim())
        .map_err(|_| BwError::Cli("Enter a valid HTTPS server URL".into()))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(BwError::Cli(
            "Server URL must use HTTPS without credentials, query, or fragment".into(),
        ));
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn master_key(
    email: &str,
    password: &str,
    prelogin: &PreloginResponse,
) -> Result<Vec<u8>, BwError> {
    let salt = email.trim().to_lowercase();
    derive_master_key(
        password,
        &salt,
        prelogin.kdf,
        prelogin.kdf_iterations,
        prelogin.kdf_memory,
        prelogin.kdf_parallelism,
    )
}

fn master_key_from_unlock(
    password: &str,
    unlock: &MasterPasswordUnlockResponse,
) -> Result<Vec<u8>, BwError> {
    let salt = unlock.salt.trim().to_lowercase();
    derive_master_key(
        password,
        &salt,
        unlock.kdf.kdf_type,
        unlock.kdf.iterations,
        unlock.kdf.memory,
        unlock.kdf.parallelism,
    )
}

fn master_key_from_saved(password: &str, saved: &SavedSession) -> Result<Vec<u8>, BwError> {
    derive_master_key(
        password,
        &saved.salt.trim().to_lowercase(),
        saved.kdf.kdf_type,
        saved.kdf.iterations,
        saved.kdf.memory,
        saved.kdf.parallelism,
    )
}

fn saved_kdf_from_login(
    email: &str,
    prelogin: &PreloginResponse,
    unlock: Option<&MasterPasswordUnlockResponse>,
) -> (String, SavedKdf) {
    if let Some(unlock) = unlock {
        return (
            unlock.salt.clone(),
            SavedKdf {
                kdf_type: unlock.kdf.kdf_type,
                iterations: unlock.kdf.iterations,
                memory: unlock.kdf.memory,
                parallelism: unlock.kdf.parallelism,
            },
        );
    }

    (
        email.trim().to_lowercase(),
        SavedKdf {
            kdf_type: prelogin.kdf,
            iterations: prelogin.kdf_iterations,
            memory: prelogin.kdf_memory,
            parallelism: prelogin.kdf_parallelism,
        },
    )
}

fn saved_kdf_from_challenge(
    email: &str,
    challenge_kdf: &SavedKdf,
    unlock: Option<&MasterPasswordUnlockResponse>,
) -> (String, SavedKdf) {
    if let Some(unlock) = unlock {
        return (
            unlock.salt.clone(),
            SavedKdf {
                kdf_type: unlock.kdf.kdf_type,
                iterations: unlock.kdf.iterations,
                memory: unlock.kdf.memory,
                parallelism: unlock.kdf.parallelism,
            },
        );
    }

    (email.trim().to_lowercase(), challenge_kdf.clone())
}

// Derive a separate key for local session storage, bound to account and server.
fn session_storage_key(
    session: &SavedSession,
    user_key: &[u8],
) -> Result<Zeroizing<[u8; 64]>, BwError> {
    let context = serde_json::to_vec(&(&session.server_url, &session.email))
        .map_err(|e| BwError::Parse(e.to_string()))?;
    // Keeps the pre-rename label: changing it would make every saved session unreadable.
    let kdf = hkdf::Hkdf::<Sha256>::new(Some(b"bw-quick-access/session-token/v1"), user_key);
    let mut key = Zeroizing::new([0u8; 64]);
    kdf.expand(&context, key.as_mut())
        .map_err(|_| BwError::Parse("Session key derivation failed".into()))?;
    Ok(key)
}

fn encrypt_session_token(
    session: &mut SavedSession,
    token: &str,
    user_key: &[u8],
) -> Result<(), BwError> {
    let key = session_storage_key(session, user_key)?;
    session.encrypted_refresh_token = Some(encrypt_string(token, key.as_ref())?);
    session.refresh_token.zeroize();
    Ok(())
}

fn saved_session_token(session: &SavedSession, user_key: &[u8]) -> Result<String, BwError> {
    match &session.encrypted_refresh_token {
        Some(encrypted) => {
            if !encrypted.starts_with("2.") {
                return Err(BwError::Parse(
                    "Unsupported saved-session encryption".into(),
                ));
            }
            let key = session_storage_key(session, user_key)?;
            decrypt_string(encrypted, key.as_ref())?
                .ok_or_else(|| BwError::Parse("Empty saved-session token".into()))
        }
        // Legacy sessions are migrated after a successful token refresh.
        None if !session.refresh_token.is_empty() => Ok(session.refresh_token.clone()),
        None => Err(BwError::Parse(
            "Saved session contains no refresh token".into(),
        )),
    }
}

fn save_successful_session(
    server_url: &str,
    email: &str,
    refresh_token: Option<&str>,
    master_key_encrypted_user_key: &str,
    (salt, kdf): (String, SavedKdf),
    user_key: &[u8],
) -> Result<(), BwError> {
    let Some(refresh_token) = refresh_token else {
        return Ok(());
    };
    let mut session = SavedSession {
        server_url: server_url.to_string(),
        email: email.trim().to_string(),
        refresh_token: String::new(),
        encrypted_refresh_token: None,
        master_key_encrypted_user_key: master_key_encrypted_user_key.to_string(),
        salt,
        kdf,
    };
    encrypt_session_token(&mut session, refresh_token, user_key)?;
    config::save_session(&session)
        .map_err(|e| BwError::Cli(format!("Could not save encrypted session: {e}")))
}

fn derive_master_key(
    password: &str,
    salt: &str,
    kdf: u32,
    kdf_iterations: u32,
    kdf_memory: Option<u32>,
    kdf_parallelism: Option<u32>,
) -> Result<Vec<u8>, BwError> {
    let mut key = [0u8; 32];
    match kdf {
        0 => {
            // Prelogin and saved-session parameters are untrusted. Bound work before
            // entering the KDF, while retaining support for legacy iteration counts.
            if !(1..=2_000_000).contains(&kdf_iterations) {
                return Err(BwError::Parse(
                    "PBKDF2 iterations must be between 1 and 2000000".into(),
                ));
            }
            pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                salt.as_bytes(),
                kdf_iterations,
                &mut key,
            );
        }
        1 => {
            let memory_mib = kdf_memory
                .ok_or_else(|| BwError::Parse("Argon2 prelogin response missing memory".into()))?;
            let parallelism = kdf_parallelism.ok_or_else(|| {
                BwError::Parse("Argon2 prelogin response missing parallelism".into())
            })?;
            if !(1..=10).contains(&kdf_iterations)
                || !(1..=1024).contains(&memory_mib)
                || !(1..=16).contains(&parallelism)
            {
                return Err(BwError::Parse(
                    "Argon2 parameters exceed supported resource limits".into(),
                ));
            }
            let params = Params::new(
                memory_mib
                    .checked_mul(1024)
                    .ok_or_else(|| BwError::Parse("Argon2 memory value is too large".into()))?,
                kdf_iterations,
                parallelism,
                Some(32),
            )
            .map_err(|e| BwError::Parse(format!("invalid Argon2 parameters: {e}")))?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key)
                .map_err(|e| BwError::Parse(format!("Argon2 key derivation failed: {e}")))?;
        }
        other => {
            return Err(BwError::Cli(format!("unsupported KDF {other} from server")));
        }
    }
    Ok(key.to_vec())
}

fn password_hash(password: &str, master_key: &[u8]) -> String {
    let mut hash = [0u8; 32];
    pbkdf2_hmac::<Sha256>(master_key, password.as_bytes(), 1, &mut hash);
    base64::engine::general_purpose::STANDARD.encode(hash)
}

fn unwrap_user_key(encrypted_key: &str, master_key: &[u8]) -> Result<Vec<u8>, BwError> {
    decrypt_symmetric_key(encrypted_key, master_key)
}

fn decrypt_symmetric_key(encrypted_key: &str, wrapping_key: &[u8]) -> Result<Vec<u8>, BwError> {
    let plain = decrypt_bytes(encrypted_key, wrapping_key)?;
    if matches!(plain.len(), 32 | 64) {
        return Ok(plain);
    }
    if let Ok(text) = String::from_utf8(plain.clone()) {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(text.trim()) {
            if matches!(decoded.len(), 32 | 64) {
                return Ok(decoded);
            }
        }
    }
    Err(BwError::Parse(format!(
        "decrypted symmetric key has unsupported length {}",
        plain.len()
    )))
}

/// Encrypts as type 2 (AES-256-CBC with HMAC-SHA256) under a fresh random IV.
fn encrypt_string(plaintext: &str, key: &[u8]) -> Result<String, BwError> {
    encrypt_bytes(plaintext.as_bytes(), key)
}

pub(crate) fn encrypt_bytes(plaintext: &[u8], key: &[u8]) -> Result<String, BwError> {
    let iv = crate::random::random_bytes::<16>()
        .map_err(|e| BwError::Cli(format!("could not read random bytes: {e}")))?;
    encrypt_bytes_with_iv(plaintext, key, iv)
}

fn encrypt_bytes_with_iv(plaintext: &[u8], key: &[u8], iv: [u8; 16]) -> Result<String, BwError> {
    let stretched_key;
    let key = if key.len() == 32 {
        stretched_key = stretch_key(key)?;
        stretched_key.as_slice()
    } else {
        key
    };
    if key.len() < 64 {
        return Err(BwError::Parse(
            "AES-CBC-HMAC encryption needs a 64 byte symmetric key".into(),
        ));
    }
    let ciphertext = Aes256CbcEnc::new_from_slices(&key[..32], &iv)
        .map_err(|e| BwError::Parse(format!("invalid AES-CBC key/iv: {e}")))?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    let mut mac = HmacSha256::new_from_slice(&key[32..64])
        .map_err(|e| BwError::Parse(format!("invalid HMAC key: {e}")))?;
    mac.update(&iv);
    mac.update(&ciphertext);
    let engine = base64::engine::general_purpose::STANDARD;
    Ok(format!(
        "2.{}|{}|{}",
        engine.encode(iv),
        engine.encode(ciphertext),
        engine.encode(mac.finalize().into_bytes())
    ))
}

fn decrypt_opt_string(value: Option<&str>, key: &[u8]) -> Result<Option<String>, BwError> {
    value
        .map(|value| decrypt_string(value, key))
        .transpose()
        .map(|value| value.flatten())
}

fn decrypt_string(value: &str, key: &[u8]) -> Result<Option<String>, BwError> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    let bytes = decrypt_bytes(value, key)?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|e| BwError::Parse(format!("decrypted value is not UTF-8: {e}")))
}

pub(crate) fn decrypt_bytes(value: &str, key: &[u8]) -> Result<Vec<u8>, BwError> {
    let enc = EncString::parse(value)?;
    match enc.enc_type {
        0 => {
            let encryption_key = key.get(..32).ok_or_else(|| {
                BwError::Parse("AES-CBC value needs at least a 32 byte key".into())
            })?;
            decrypt_aes_cbc(encryption_key, &enc.iv, &enc.data)
        }
        2 => {
            let stretched_key;
            let key = if key.len() == 32 {
                stretched_key = stretch_key(key)?;
                stretched_key.as_slice()
            } else {
                key
            };
            if key.len() < 64 {
                return Err(BwError::Parse(
                    "AES-CBC-HMAC value needs a 64 byte symmetric key".into(),
                ));
            }
            let encryption_key = &key[..32];
            let authentication_key = &key[32..64];
            let expected_mac = enc
                .mac
                .as_deref()
                .ok_or_else(|| BwError::Parse("AES-CBC-HMAC value is missing MAC".into()))?;
            verify_hmac(authentication_key, &enc.iv, &enc.data, expected_mac)?;
            decrypt_aes_cbc(encryption_key, &enc.iv, &enc.data)
        }
        other => Err(BwError::Parse(format!(
            "unsupported encryption type {other}; only AES-CBC personal vault data is implemented"
        ))),
    }
}

fn stretch_key(key: &[u8]) -> Result<Vec<u8>, BwError> {
    if key.len() != 32 {
        return Err(BwError::Parse(format!(
            "only 32 byte keys can be stretched, got {} bytes",
            key.len()
        )));
    }
    let encryption_key = hkdf_expand(key, b"enc")?;
    let authentication_key = hkdf_expand(key, b"mac")?;
    Ok([encryption_key, authentication_key].concat())
}

fn hkdf_expand(input_key_material: &[u8], info: &[u8]) -> Result<Vec<u8>, BwError> {
    let mut expand = HmacSha256::new_from_slice(input_key_material)
        .map_err(|e| BwError::Parse(format!("invalid HKDF key: {e}")))?;
    expand.update(info);
    expand.update(&[1]);
    Ok(expand.finalize().into_bytes().to_vec())
}

fn decrypt_aes_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, BwError> {
    Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| BwError::Parse(format!("invalid AES-CBC key/iv: {e}")))?
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|e| BwError::Parse(format!("AES-CBC decrypt failed: {e}")))
}

fn verify_hmac(
    authentication_key: &[u8],
    iv: &[u8],
    data: &[u8],
    expected_mac: &[u8],
) -> Result<(), BwError> {
    let mut mac = HmacSha256::new_from_slice(authentication_key)
        .map_err(|e| BwError::Parse(format!("invalid HMAC key: {e}")))?;
    mac.update(iv);
    mac.update(data);
    mac.verify_slice(expected_mac)
        .map_err(|_| BwError::Parse("encrypted value HMAC check failed".into()))
}

struct EncString {
    enc_type: i64,
    iv: Vec<u8>,
    data: Vec<u8>,
    mac: Option<Vec<u8>>,
}

impl EncString {
    fn parse(value: &str) -> Result<Self, BwError> {
        let (enc_type, body) = match value.split_once('.') {
            Some((header, body)) => (
                header
                    .parse::<i64>()
                    .map_err(|e| BwError::Parse(format!("invalid encrypted header: {e}")))?,
                body,
            ),
            None => (0, value),
        };
        let parts = body.split('|').collect::<Vec<_>>();
        let decode = |part: &str| {
            base64::engine::general_purpose::STANDARD
                .decode(part)
                .map_err(|e| BwError::Parse(format!("invalid base64 encrypted value: {e}")))
        };
        match (enc_type, parts.as_slice()) {
            (0, [iv, data]) => Ok(Self {
                enc_type,
                iv: decode(iv)?,
                data: decode(data)?,
                mac: None,
            }),
            (2, [iv, data, mac]) => Ok(Self {
                enc_type,
                iv: decode(iv)?,
                data: decode(data)?,
                mac: Some(decode(mac)?),
            }),
            _ => Err(BwError::Parse(format!(
                "encrypted value type {enc_type} has {} parts",
                parts.len()
            ))),
        }
    }
}

pub(crate) fn generate_totp(seed: &str, now_unix: u64) -> Result<TotpCode, BwError> {
    let (secret, digits, period) = parse_totp_seed(seed)?;
    let step = now_unix / period;
    let mut mac = HmacSha1::new_from_slice(&secret)
        .map_err(|e| BwError::Parse(format!("invalid TOTP key: {e}")))?;
    mac.update(&step.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[19] & 0x0f) as usize;
    let code = (((hash[offset] & 0x7f) as u64) << 24)
        | ((hash[offset + 1] as u64) << 16)
        | ((hash[offset + 2] as u64) << 8)
        | (hash[offset + 3] as u64);
    let modulo = 10u64.pow(digits);
    Ok(TotpCode {
        code: format!("{:0width$}", code % modulo, width = digits as usize),
        period,
        step,
    })
}

fn parse_totp_seed(seed: &str) -> Result<(Vec<u8>, u32, u64), BwError> {
    let trimmed = seed.trim();
    let mut secret = trimmed.to_string();
    let mut digits = 6;
    let mut period = 30;

    if let Ok(url) = Url::parse(trimmed) {
        if url.scheme() == "otpauth" {
            for (key, value) in url.query_pairs() {
                match key.as_ref() {
                    "secret" => secret = value.to_string(),
                    "digits" => digits = value.parse().unwrap_or(6),
                    "period" => period = value.parse().unwrap_or(30),
                    "algorithm" if !value.eq_ignore_ascii_case("SHA1") => {
                        return Err(BwError::Cli(format!(
                            "TOTP algorithm {value} is not implemented yet"
                        )));
                    }
                    _ => {}
                }
            }
        }
    }

    let normalized = secret
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    let decoded = BASE32_NOPAD
        .decode(normalized.as_bytes())
        .or_else(|_| BASE32.decode(normalized.as_bytes()))
        .map_err(|e| BwError::Parse(format!("invalid TOTP secret: {e}")))?;
    // Item data is untrusted: period 0 would divide by zero and more than 10 digits
    // overflows the modulo. Bitwarden itself only produces 6..=10 digits.
    if !(1..=10).contains(&digits) {
        return Err(BwError::Parse(format!("unsupported TOTP digits: {digits}")));
    }
    if period == 0 {
        return Err(BwError::Parse("TOTP period must be greater than 0".into()));
    }
    Ok((decoded, digits, period))
}

#[cfg(test)]
#[path = "passkey_vault_tests.rs"]
mod passkey_vault_tests;

#[cfg(test)]
mod tests {
    #[test]
    fn rejects_untrusted_kdf_costs_before_derivation() {
        for iterations in [0, 2_000_001, u32::MAX] {
            assert!(
                super::derive_master_key("password", "salt", 0, iterations, None, None).is_err()
            );
        }
        for (iterations, memory, parallelism) in [
            (0, 64, 4),
            (11, 64, 4),
            (3, 0, 4),
            (3, 1025, 4),
            (3, u32::MAX, 4),
            (3, 64, 0),
            (3, 64, 17),
        ] {
            assert!(
                super::derive_master_key(
                    "password",
                    "salt",
                    1,
                    iterations,
                    Some(memory),
                    Some(parallelism)
                )
                .is_err()
            );
        }
        assert!(super::derive_master_key("password", "salt", 0, 1000, None, None).is_ok());
        assert!(super::derive_master_key("password", "12345678", 1, 1, Some(1), Some(1)).is_ok());
    }

    use super::*;

    fn encrypt_string(plaintext: &str, key: &[u8]) -> String {
        encrypt_bytes(plaintext.as_bytes(), key)
    }

    fn encrypt_bytes(plaintext: &[u8], key: &[u8]) -> String {
        encrypt_bytes_with_iv(plaintext, key, [11u8; 16]).unwrap()
    }

    fn empty_cipher(id: &str, name: String) -> CipherResponse {
        CipherResponse {
            id: id.to_string(),
            favorite: false,
            organization_id: None,
            folder_id: None,
            item_type: 1,
            name: Some(name),
            notes: None,
            fields: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            key: None,
            deleted_date: None,
            archived_date: None,
            data: None,
        }
    }

    #[test]
    fn decrypts_aes_cbc_hmac_enc_string() {
        let key = [7u8; 64];
        let iv = [3u8; 16];
        let plaintext = b"hello vault";
        let ciphertext = Aes256CbcEnc::new_from_slices(&key[..32], &iv)
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        let mut mac = HmacSha256::new_from_slice(&key[32..64]).unwrap();
        mac.update(&iv);
        mac.update(&ciphertext);
        let mac = mac.finalize().into_bytes();
        let enc = format!(
            "2.{}|{}|{}",
            base64::engine::general_purpose::STANDARD.encode(iv),
            base64::engine::general_purpose::STANDARD.encode(ciphertext),
            base64::engine::general_purpose::STANDARD.encode(mac)
        );

        let decrypted = decrypt_string(&enc, &key).unwrap();

        assert_eq!(decrypted.as_deref(), Some("hello vault"));
    }

    #[test]
    fn decrypts_aes_cbc_hmac_with_stretched_32_byte_key() {
        let key = [12u8; 32];
        let stretched_key = stretch_key(&key).unwrap();
        let enc = encrypt_string("hello stretched vault", &stretched_key);

        let decrypted = decrypt_string(&enc, &key).unwrap();

        assert_eq!(decrypted.as_deref(), Some("hello stretched vault"));
    }

    #[test]
    fn stretches_32_byte_key_with_bitwarden_hkdf_expand() {
        let key = [12u8; 32];
        let stretched_key = stretch_key(&key).unwrap();

        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(&stretched_key[..32]),
            "MQMS4qTklapLQ8wIc7ldbs8R7t6KwteTEs+eZ6G7Njk="
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(&stretched_key[32..64]),
            "c6pSuIMy1M+BGE/TRUm1W9lozGpbVsBr2qXvC1rbd98="
        );
    }

    #[test]
    fn rejects_tampered_aes_cbc_hmac_enc_string() {
        let key = [9u8; 64];
        let iv = [4u8; 16];
        let ciphertext = Aes256CbcEnc::new_from_slices(&key[..32], &iv)
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(b"secret");
        let enc = format!(
            "2.{}|{}|{}",
            base64::engine::general_purpose::STANDARD.encode(iv),
            base64::engine::general_purpose::STANDARD.encode(ciphertext),
            base64::engine::general_purpose::STANDARD.encode([0u8; 32])
        );

        let error = decrypt_string(&enc, &key).unwrap_err().to_string();

        assert!(error.contains("HMAC"));
    }

    #[test]
    fn parses_otpauth_totp_settings() {
        let (secret, digits, period) =
            parse_totp_seed("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=8&period=60")
                .unwrap();

        assert_eq!(secret, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(digits, 8);
        assert_eq!(period, 60);
    }

    // RFC 6238 appendix B, SHA1 variant (secret is ASCII "12345678901234567890").
    #[test]
    fn generates_rfc6238_totp_codes() {
        let seed = "otpauth://totp/rfc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
        for (time, expected) in [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(
                generate_totp(seed, time).unwrap().code,
                expected,
                "time {time}"
            );
        }
    }

    #[test]
    fn totp_code_tracks_its_time_step() {
        let code = generate_totp("JBSWY3DPEHPK3PXP", 65).unwrap();

        assert_eq!(code.code.len(), 6);
        assert_eq!((code.period, code.step), (30, 2));
        assert_eq!(code.seconds_remaining(65), 25);
        assert!(code.is_current(89));
        assert!(!code.is_current(90));
    }

    #[test]
    fn rejects_totp_settings_that_would_panic() {
        for seed in [
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=0",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=11",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4294967295",
        ] {
            assert!(generate_totp(seed, 59).is_err(), "{seed}");
        }
    }

    #[test]
    fn formats_decrypt_skip_warning() {
        assert_eq!(decrypt_skip_warning(0, None), None);
        assert_eq!(
            decrypt_skip_warning(2, Some("unsupported encryption type".into())).as_deref(),
            Some("Skipped 2 vault items during decrypt; first error: unsupported encryption type")
        );
    }

    #[test]
    fn decrypts_organization_cipher_with_per_cipher_key() {
        let user_key = [1u8; 64];
        let org_key = [2u8; 64];
        let item_key = [3u8; 64];
        let profile = SyncProfileResponse {
            organizations: vec![OrganizationResponse {
                id: "org-1".into(),
                key: Some(encrypt_bytes(&org_key, &user_key)),
            }],
        };
        let organization_keys = decrypt_organization_keys(Some(profile), &user_key).unwrap();
        let mut cipher = empty_cipher("cipher-1", encrypt_string("Shared Login", &item_key));
        cipher.organization_id = Some("org-1".into());
        cipher.key = Some(encrypt_bytes(&item_key, &org_key));

        let item = decrypt_cipher(cipher, &user_key, &organization_keys, &HashMap::new()).unwrap();

        assert_eq!(item.name, "Shared Login");
    }

    #[test]
    fn decrypts_organization_cipher_without_per_cipher_key() {
        let user_key = [4u8; 64];
        let org_key = [5u8; 64];
        let profile = SyncProfileResponse {
            organizations: vec![OrganizationResponse {
                id: "org-2".into(),
                key: Some(encrypt_bytes(&org_key, &user_key)),
            }],
        };
        let organization_keys = decrypt_organization_keys(Some(profile), &user_key).unwrap();
        let mut cipher = empty_cipher("cipher-2", encrypt_string("Shared Secure Note", &org_key));
        cipher.organization_id = Some("org-2".into());

        let item = decrypt_cipher(cipher, &user_key, &organization_keys, &HashMap::new()).unwrap();

        assert_eq!(item.name, "Shared Secure Note");
    }

    #[test]
    fn decrypts_and_searches_vaultwarden_nested_data_cipher() {
        let user_key = [6u8; 64];
        let cipher = CipherResponse {
            id: "cipher-telegram".into(),
            favorite: false,
            organization_id: None,
            folder_id: None,
            item_type: 1,
            name: None,
            notes: None,
            fields: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            key: None,
            deleted_date: None,
            archived_date: None,
            data: Some(CipherDataResponse {
                fido2_credentials: None,
                name: Some(encrypt_string("Telegram", &user_key)),
                notes: Some(encrypt_string("chat account", &user_key)),
                fields: Some(vec![FieldResponse {
                    name: Some(encrypt_string("Recovery", &user_key)),
                    value: Some(encrypt_string("paper-key", &user_key)),
                    field_type: Some(1),
                }]),
                username: Some(encrypt_string("bermcs-agent", &user_key)),
                password: Some(encrypt_string("telegram-password", &user_key)),
                uris: Some(vec![LoginUriResponse {
                    uri: Some(encrypt_string("https://web.telegram.org", &user_key)),
                    match_type: None,
                }]),
                totp: None,
                cardholder_name: None,
                number: None,
                code: None,
                brand: None,
                exp_month: None,
                exp_year: None,
                first_name: None,
                middle_name: None,
                last_name: None,
                email: None,
                phone: None,
                address1: None,
                city: None,
                state: None,
                postal_code: None,
                country: None,
                ssh_key: None,
                private_key: None,
                public_key: None,
                key_fingerprint: None,
            }),
        };

        let item = decrypt_cipher(cipher, &user_key, &HashMap::new(), &HashMap::new()).unwrap();

        assert_eq!(item.name, "Telegram");
        assert_eq!(item.username.as_deref(), Some("bermcs-agent"));
        assert_eq!(item.password.as_deref(), Some("telegram-password"));
        assert_eq!(item.uris, vec!["https://web.telegram.org"]);
        assert!(item_matches_search(&item, "telegram"));
        assert!(item_matches_search(&item, "bermcs"));
        assert!(item_matches_search(&item, "paper-key"));
    }

    #[test]
    fn decrypts_official_ssh_key_cipher() {
        let user_key = [9u8; 64];
        let cipher = CipherResponse {
            id: "ssh-key-1".into(),
            favorite: false,
            organization_id: None,
            folder_id: None,
            item_type: 5,
            name: Some(encrypt_string("GitHub deploy key", &user_key)),
            notes: None,
            fields: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: Some(SshKeyResponse {
                private_key: Some(encrypt_string(
                    "-----BEGIN OPENSSH PRIVATE KEY-----",
                    &user_key,
                )),
                public_key: Some(encrypt_string("ssh-ed25519 AAAATEST", &user_key)),
                key_fingerprint: Some(encrypt_string("SHA256:test", &user_key)),
            }),
            key: None,
            deleted_date: None,
            archived_date: None,
            data: None,
        };

        let item = decrypt_cipher(cipher, &user_key, &HashMap::new(), &HashMap::new()).unwrap();
        assert_eq!(item.item_type, "sshKey");
        let ssh_key = item.ssh_key.as_ref().unwrap();
        assert_eq!(ssh_key.id, "ssh-key-1");
        assert_eq!(ssh_key.name, "GitHub deploy key");
        assert_eq!(ssh_key.public_key, "ssh-ed25519 AAAATEST");
        assert_eq!(ssh_key.fingerprint.as_deref(), Some("SHA256:test"));
        assert!(item_matches_search(&item, "aaaatest"));
        assert!(item_matches_search(&item, "sha256:test"));
        assert!(item_matches_search(&item, "public key"));
        assert!(item_matches_search(&item, "fingerprint"));
        assert!(item_matches_search(&item, "signature"));
    }

    #[test]
    fn sync_request_uses_ssh_key_compatible_client_metadata() {
        assert_eq!(
            sync_client_name_header(),
            ("Bitwarden-Client-Name", "boltwarden")
        );
        assert_eq!(
            sync_client_version_header(),
            ("Bitwarden-Client-Version", "2024.12.0")
        );
    }

    #[test]
    fn decrypts_nested_data_ssh_key_cipher() {
        let user_key = [7u8; 64];
        let cipher = CipherResponse {
            id: "ssh-key-data-1".into(),
            favorite: false,
            organization_id: None,
            folder_id: None,
            item_type: 5,
            name: None,
            notes: None,
            fields: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            key: None,
            deleted_date: None,
            archived_date: None,
            data: Some(CipherDataResponse {
                fido2_credentials: None,
                name: Some(encrypt_string("Nested SSH key", &user_key)),
                notes: None,
                fields: None,
                username: None,
                password: None,
                uris: None,
                totp: None,
                cardholder_name: None,
                number: None,
                code: None,
                brand: None,
                exp_month: None,
                exp_year: None,
                first_name: None,
                middle_name: None,
                last_name: None,
                email: None,
                phone: None,
                address1: None,
                city: None,
                state: None,
                postal_code: None,
                country: None,
                ssh_key: Some(SshKeyResponse {
                    private_key: Some(encrypt_string(
                        "-----BEGIN OPENSSH PRIVATE KEY-----",
                        &user_key,
                    )),
                    public_key: Some(encrypt_string("ssh-ed25519 AAAANESTED", &user_key)),
                    key_fingerprint: Some(encrypt_string("SHA256:nested", &user_key)),
                }),
                private_key: None,
                public_key: None,
                key_fingerprint: None,
            }),
        };

        let item = decrypt_cipher(cipher, &user_key, &HashMap::new(), &HashMap::new()).unwrap();
        assert_eq!(item.item_type, "sshKey");
        let ssh_key = item.ssh_key.unwrap();
        assert_eq!(ssh_key.id, "ssh-key-data-1");
        assert_eq!(ssh_key.name, "Nested SSH key");
        assert_eq!(ssh_key.public_key, "ssh-ed25519 AAAANESTED");
        assert_eq!(ssh_key.fingerprint.as_deref(), Some("SHA256:nested"));
    }

    #[test]
    fn parses_two_factor_required_response() {
        let response: TwoFactorResponse = serde_json::from_str(
            r#"{
                "MasterPasswordPolicy": {"Object": "masterPasswordPolicy"},
                "TwoFactorProviders": ["0"],
                "TwoFactorProviders2": {"0": null},
                "error": "invalid_grant",
                "error_description": "Two factor required."
            }"#,
        )
        .unwrap();

        assert_eq!(response.providers, vec![TwoFactorProvider::Authenticator]);
        assert_eq!(
            response.available_providers(),
            vec![TwoFactorProvider::Authenticator]
        );
    }

    #[test]
    fn parses_numeric_two_factor_provider_response() {
        let response: TwoFactorResponse = serde_json::from_str(
            r#"{
                "TwoFactorProviders": [0],
                "error": "invalid_grant",
                "error_description": "Two factor required."
            }"#,
        )
        .unwrap();

        assert_eq!(
            response.available_providers(),
            vec![TwoFactorProvider::Authenticator]
        );
    }

    #[test]
    fn token_response_prefers_master_password_unlock_key() {
        let response: TokenResponse = serde_json::from_str(
            r#"{
                "access_token": "access",
                "refresh_token": "refresh",
                "Key": "legacy-key",
                "UserDecryptionOptions": {
                    "HasMasterPassword": true,
                    "MasterPasswordUnlock": {
                        "Salt": "custom@example.test",
                        "Kdf": {
                            "KdfType": 0,
                            "Iterations": 600000
                        },
                        "MasterKeyEncryptedUserKey": "nested-key"
                    }
                }
            }"#,
        )
        .unwrap();

        let (key, unlock) = response.master_key_encrypted_user_key().unwrap();

        assert_eq!(key, "nested-key");
        assert_eq!(unlock.unwrap().salt, "custom@example.test");
    }

    #[test]
    fn search_matches_notes_folder_type_and_custom_fields() {
        let item = BwItemDetail {
            id: "1".into(),
            folder_id: None,
            favorite: false,
            passkeys: Vec::new(),
            name: "Primary".into(),
            username: Some("user@example.test".into()),
            password: Some("secret-password".into()),
            uris: vec!["https://example.test".into()],
            totp: None,
            notes: Some("production admin".into()),
            custom_fields: vec![CustomField {
                name: "Environment".into(),
                value: "staging".into(),
                hidden: false,
            }],
            folder: Some("Infrastructure".into()),
            item_type: "login".into(),
            ssh_key: None,
            state: ItemState::Active,
            dates: ItemDates::default(),
        };

        assert!(item_matches_search(&item, "production"));
        assert!(item_matches_search(&item, "staging"));
        assert!(item_matches_search(&item, "infrastructure"));
        assert!(item_matches_search(&item, "login"));
        assert!(!item_matches_search(&item, "missing"));
    }

    #[test]
    fn search_prefers_title_matches_over_secondary_fields() {
        let items = vec![
            test_item("1", "Telegram", Some("user@example.test")),
            test_item("2", "Marktplaats", Some("tele-sales@example.test")),
            test_item("3", "Max ICT", Some("telecom@example.test")),
            test_item("4", "Tele2", None),
        ];

        let title_results = ranked_search_results(&items, "tele");
        assert_eq!(
            title_results
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Tele2", "Telegram"]
        );

        let fallback_results = ranked_search_results(&items, "telecom");
        assert_eq!(
            fallback_results
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Max ICT"]
        );
    }

    fn test_item(id: &str, name: &str, username: Option<&str>) -> BwItemDetail {
        BwItemDetail {
            id: id.into(),
            folder_id: None,
            favorite: false,
            passkeys: Vec::new(),
            name: name.into(),
            username: username.map(str::to_string),
            password: None,
            uris: Vec::new(),
            totp: None,
            notes: None,
            custom_fields: Vec::new(),
            folder: None,
            item_type: "login".into(),
            ssh_key: None,
            state: ItemState::Active,
            dates: ItemDates::default(),
        }
    }

    #[test]
    fn parses_camel_case_sync_response() {
        let sync: SyncResponse = serde_json::from_str(
            r#"{
                "profile": {
                    "organizations": [
                        {"id": "org-1", "key": "2.iv|data|mac"}
                    ]
                },
                "folders": [
                    {"id": "folder-1", "name": "2.iv|data|mac"}
                ],
                "ciphers": [
                    {
                        "id": "cipher-1",
                        "organizationId": "org-1",
                        "folderId": "folder-1",
                        "type": 1,
                        "name": "2.iv|data|mac",
                        "notes": null,
                        "fields": [
                            {"name": "2.iv|data|mac", "value": "2.iv|data|mac", "type": 0}
                        ],
                        "login": {
                            "username": "2.iv|data|mac",
                            "password": "2.iv|data|mac",
                            "uris": [{"uri": "2.iv|data|mac"}],
                            "totp": null
                        },
                        "key": null,
                        "deletedDate": null,
                        "archivedDate": null
                    }
                ]
            }"#,
        )
        .unwrap();

        assert_eq!(sync.profile.unwrap().organizations[0].id, "org-1");
        assert_eq!(sync.folders[0].id, "folder-1");
        let cipher: CipherResponse = serde_json::from_value(sync.ciphers[0].clone()).unwrap();
        assert_eq!(cipher.id, "cipher-1");
        assert_eq!(cipher.organization_id.as_deref(), Some("org-1"));
        assert_eq!(cipher.folder_id.as_deref(), Some("folder-1"));
        assert_eq!(cipher.item_type, 1);
        assert_eq!(
            cipher.login.as_ref().unwrap().uris.as_ref().unwrap()[0]
                .uri
                .as_deref(),
            Some("2.iv|data|mac")
        );
    }

    #[test]
    fn parses_vaultwarden_nested_data_cipher() {
        let sync: SyncResponse = serde_json::from_str(
            r#"{
                "ciphers": [
                    {
                        "id": "cipher-1",
                        "type": 1,
                        "data": {
                            "fields": [],
                            "name": "2.iv|data|mac",
                            "notes": null,
                            "password": "2.iv|data|mac",
                            "username": "2.iv|data|mac",
                            "uris": [{"uri": "2.iv|data|mac"}],
                            "totp": null
                        },
                        "key": null,
                        "deletedDate": null,
                        "archivedDate": null
                    }
                ]
            }"#,
        )
        .unwrap();

        let cipher: CipherResponse = serde_json::from_value(sync.ciphers[0].clone()).unwrap();
        assert!(cipher.name.is_none());
        assert_eq!(
            cipher.data.as_ref().unwrap().name.as_deref(),
            Some("2.iv|data|mac")
        );
        assert_eq!(
            cipher.data.as_ref().unwrap().uris.as_ref().unwrap()[0]
                .uri
                .as_deref(),
            Some("2.iv|data|mac")
        );
    }

    #[test]
    fn parses_two_factor_provider_map_response() {
        let response: TwoFactorResponse = serde_json::from_str(
            r#"{
                "TwoFactorProviders2": {"1": {"Email": "m@example.com"}, "0": null},
                "error": "invalid_grant",
                "error_description": "Two factor required."
            }"#,
        )
        .unwrap();

        assert_eq!(
            response.available_providers(),
            vec![TwoFactorProvider::Authenticator, TwoFactorProvider::Email]
        );
    }

    #[test]
    fn encrypt_string_round_trips_with_random_iv() {
        for key in [vec![21u8; 32], vec![22u8; 64]] {
            let first = super::encrypt_string("hunter2", &key).unwrap();
            let second = super::encrypt_string("hunter2", &key).unwrap();

            assert_ne!(first, second, "each value gets its own IV");
            assert_eq!(
                decrypt_string(&first, &key).unwrap().as_deref(),
                Some("hunter2")
            );
            assert_eq!(
                decrypt_string(&second, &key).unwrap().as_deref(),
                Some("hunter2")
            );
        }
    }

    #[test]
    fn formats_iso8601_timestamps() {
        assert_eq!(iso8601_from_unix_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            iso8601_from_unix_ms(951_782_400_123),
            "2000-02-29T00:00:00.123Z"
        );
        assert_eq!(
            iso8601_from_unix_ms(1_790_762_163_576),
            "2026-09-30T09:56:03.576Z"
        );
    }

    #[test]
    fn decodes_item_state_from_dates() {
        let key = [23u8; 64];
        let cipher = |deleted: Value, archived: Value| {
            json!({
                "id": "c", "type": 2, "name": encrypt_string("Note", &key),
                "secureNote": {"type": 0},
                "deletedDate": deleted, "archivedDate": archived,
                "revisionDate": "2026-01-01T00:00:00.000Z",
            })
        };
        let state = |raw: Value| {
            decode_cipher(raw, &key, &HashMap::new(), &HashMap::new())
                .unwrap()
                .0
                .state
        };

        assert_eq!(state(cipher(Value::Null, Value::Null)), ItemState::Active);
        assert_eq!(
            state(cipher(Value::Null, json!("2026-02-02"))),
            ItemState::Archived
        );
        assert_eq!(
            state(cipher(json!("2026-02-02"), json!("2026-02-02"))),
            ItemState::Deleted
        );
        let (_, stored) = decode_cipher(
            cipher(Value::Null, Value::Null),
            &key,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(
            stored.revision_date.as_deref(),
            Some("2026-01-01T00:00:00.000Z")
        );
    }

    #[test]
    fn only_allows_actions_that_fit_the_item_state() {
        use ItemAction::*;
        assert!(action_allowed(Archive, ItemState::Active));
        assert!(!action_allowed(Archive, ItemState::Archived));
        assert!(action_allowed(Unarchive, ItemState::Archived));
        assert!(action_allowed(Trash, ItemState::Archived));
        assert!(!action_allowed(Trash, ItemState::Deleted));
        assert!(action_allowed(Restore, ItemState::Deleted));
        assert!(!action_allowed(DeleteForever, ItemState::Active));
        assert!(action_allowed(DeleteForever, ItemState::Deleted));
    }

    #[test]
    fn rejects_ids_that_are_not_uuids_in_paths() {
        assert_eq!(cipher_path("0b6f-AB12").unwrap(), "/api/ciphers/0b6f-AB12");
        assert!(cipher_path("../sync").is_err());
        assert!(cipher_path("").is_err());
    }

    fn editable_login(key: &[u8]) -> StoredCipher {
        let enc = |value: &str| encrypt_string(value, key);
        let history = (0..5)
            .map(
                |idx| json!({"password": enc(&format!("old-{idx}")), "lastUsedDate": "2025-01-01"}),
            )
            .collect::<Vec<_>>();
        let raw = json!({
            "id": "cipher-edit",
            "type": 1,
            "name": enc("Example"),
            "notes": null,
            "favorite": true,
            "reprompt": 1,
            "key": null,
            "revisionDate": "2026-03-04T05:06:07.000Z",
            "login": {
                "username": enc("alice"),
                "password": enc("current-password"),
                "totp": null,
                "uris": [
                    {"uri": enc("https://one.example"), "match": 0, "uriChecksum": enc("x")},
                    {"uri": enc("https://two.example"), "match": 3, "uriChecksum": enc("y")},
                ],
                "fido2Credentials": [
                    {"credentialId": enc("passkey"), "rpId": enc("one.example"), "userName": enc("alice"), "keyValue": enc("secret-key"), "creationDate": "2026-01-02T03:04:05.000Z"},
                    {"credentialId": enc("passkey-2"), "rpId": enc("two.example"), "keyValue": enc("secret-key-2")},
                ],
            },
            "fields": [
                {"type": 0, "name": enc("Env"), "value": enc("prod"), "linkedId": null},
                {"type": 3, "name": enc("Linked"), "value": null, "linkedId": 100},
            ],
            "passwordHistory": history,
            "data": {"name": enc("Example")},
        });
        StoredCipher {
            raw,
            item_key: key.to_vec(),
            revision_date: Some("2026-03-04T05:06:07.000Z".into()),
            browser_uris: Vec::new(),
        }
    }

    #[test]
    fn draft_reads_login_uris_and_fields() {
        let key = [24u8; 64];
        let stored = editable_login(&key);

        let draft = draft_from_raw(&stored.raw, &key).unwrap();

        assert_eq!(draft.name, "Example");
        let login = draft.login.unwrap();
        assert_eq!(login.username, "alice");
        assert_eq!(login.password, "current-password");
        assert_eq!(login.uris[1].uri, "https://two.example");
        assert_eq!(login.uris[1].original_index, Some(1));
        assert_eq!(draft.fields[0].name, "Env");
        assert_eq!(draft.fields[1].kind, DraftFieldKind::Linked);
    }

    #[test]
    fn save_request_changes_only_edited_fields() {
        let key = [25u8; 64];
        let stored = editable_login(&key);
        let mut draft = draft_from_raw(&stored.raw, &key).unwrap();
        let login = draft.login.as_mut().unwrap();
        login.password = "new-password".into();
        login.uris[1].uri = "https://three.example".into();
        draft.fields[0].name = "Environment".into();
        draft.fields.push(DraftField {
            name: "PIN".into(),
            value: "1234".into(),
            kind: DraftFieldKind::Hidden,
            original_index: None,
        });

        let body = build_save_request(&stored, &draft, "2026-09-30T10:00:00.000Z").unwrap();
        let raw = &stored.raw;
        let dec = |value: &Value| {
            decrypt_string(value.as_str().unwrap(), &key)
                .unwrap()
                .unwrap()
        };

        // Untouched data goes back byte for byte.
        assert_eq!(body["name"], raw["name"]);
        assert_eq!(body["favorite"], raw["favorite"]);
        assert_eq!(body["reprompt"], raw["reprompt"]);
        assert_eq!(body["login"]["username"], raw["login"]["username"]);
        assert_eq!(
            body["login"]["fido2Credentials"],
            raw["login"]["fido2Credentials"]
        );
        assert_eq!(body["login"]["uris"][0], raw["login"]["uris"][0]);
        assert!(body.get("data").is_none());
        // Edited values are re-encrypted, keeping their extra settings.
        assert_eq!(dec(&body["login"]["password"]), "new-password");
        assert_eq!(
            body["login"]["passwordRevisionDate"],
            "2026-09-30T10:00:00.000Z"
        );
        assert_eq!(
            dec(&body["login"]["uris"][1]["uri"]),
            "https://three.example"
        );
        assert_eq!(body["login"]["uris"][1]["match"], 3);
        assert_eq!(dec(&body["fields"][0]["name"]), "Environment");
        assert_eq!(body["fields"][0]["value"], raw["fields"][0]["value"]);
        assert_eq!(body["fields"][1], raw["fields"][1]);
        assert_eq!(body["fields"][2]["type"], 1);
        assert_eq!(dec(&body["fields"][2]["value"]), "1234");
        // The old password leads the history, which stays at five entries.
        let history = body["passwordHistory"].as_array().unwrap();
        assert_eq!(history.len(), 5);
        assert_eq!(dec(&history[0]["password"]), "current-password");
        assert_eq!(dec(&history[1]["password"]), "old-0");
        assert_eq!(body["lastKnownRevisionDate"], "2026-03-04T05:06:07.000Z");
    }

    #[test]
    fn save_request_drops_removed_uris_and_fields() {
        let key = [26u8; 64];
        let stored = editable_login(&key);
        let mut draft = draft_from_raw(&stored.raw, &key).unwrap();
        draft.login.as_mut().unwrap().uris.remove(0);
        draft.fields.clear();

        let body = build_save_request(&stored, &draft, "now").unwrap();

        assert_eq!(body["login"]["uris"].as_array().unwrap().len(), 1);
        assert_eq!(body["login"]["uris"][0], stored.raw["login"]["uris"][1]);
        assert!(body["fields"].is_null());
        assert!(body["passwordHistory"] == stored.raw["passwordHistory"]);
    }

    #[test]
    fn draft_and_detail_show_passkeys_without_key_material() {
        let key = [27u8; 64];
        let stored = editable_login(&key);

        let draft = draft_from_raw(&stored.raw, &key).unwrap();
        let passkeys = &draft.login.as_ref().unwrap().passkeys;
        assert_eq!(passkeys.len(), 2);
        assert_eq!(passkeys[0].passkey.rp_id, "one.example");
        assert_eq!(passkeys[0].passkey.user_name.as_deref(), Some("alice"));
        assert_eq!(
            passkeys[0].passkey.creation_date.as_deref(),
            Some("2026-01-02T03:04:05.000Z")
        );
        assert_eq!(passkeys[1].original_index, 1);
        assert!(draft.favorite);

        let (detail, _) =
            decode_cipher(stored.raw.clone(), &key, &HashMap::new(), &HashMap::new()).unwrap();
        assert_eq!(detail.passkeys.len(), 2);
        assert!(detail.favorite);
        let shown = serde_json::to_string(&detail).unwrap();
        assert!(!shown.contains("secret-key"));
        // Passkeys take a field slot but can't be copied.
        let passkey_slot = 2; // username, password, then the first passkey
        assert!(detail.copy_value(passkey_slot).is_err());
        assert_eq!(
            detail.copy_value(passkey_slot + 2).unwrap(),
            "https://one.example"
        );
    }

    #[test]
    fn save_request_removes_only_the_dropped_passkey() {
        let key = [28u8; 64];
        let stored = editable_login(&key);
        let mut draft = draft_from_raw(&stored.raw, &key).unwrap();
        draft.login.as_mut().unwrap().passkeys.remove(0);

        let body = build_save_request(&stored, &draft, "now").unwrap();

        let passkeys = body["login"]["fido2Credentials"].as_array().unwrap();
        assert_eq!(passkeys.len(), 1);
        assert_eq!(passkeys[0], stored.raw["login"]["fido2Credentials"][1]);

        draft.login.as_mut().unwrap().passkeys.clear();
        let body = build_save_request(&stored, &draft, "now").unwrap();
        assert!(body["login"]["fido2Credentials"].is_null());
    }

    #[test]
    fn save_request_cannot_add_or_duplicate_passkeys() {
        let key = [29u8; 64];
        let stored = editable_login(&key);
        let mut draft = draft_from_raw(&stored.raw, &key).unwrap();
        let passkeys = &mut draft.login.as_mut().unwrap().passkeys;
        let mut extra = passkeys[0].clone();
        extra.original_index = 7;
        passkeys.push(extra);
        assert!(build_save_request(&stored, &draft, "now").is_err());

        let passkeys = &mut draft.login.as_mut().unwrap().passkeys;
        passkeys.pop();
        let duplicate = passkeys[0].clone();
        passkeys[1] = duplicate;
        let body = build_save_request(&stored, &draft, "now").unwrap();
        assert_eq!(
            body["login"]["fido2Credentials"].as_array().unwrap().len(),
            1
        );
    }

    #[test]
    fn save_request_moves_folder_and_toggles_favorite() {
        let key = [30u8; 64];
        let stored = editable_login(&key);
        let mut draft = draft_from_raw(&stored.raw, &key).unwrap();
        draft.folder_id = Some("folder-1".into());
        draft.favorite = false;

        let body = build_save_request(&stored, &draft, "now").unwrap();

        assert_eq!(body["folderId"], "folder-1");
        assert_eq!(body["favorite"], false);
        assert_eq!(
            body["login"]["fido2Credentials"],
            stored.raw["login"]["fido2Credentials"]
        );
    }

    #[test]
    fn validates_folder_names_and_ids() {
        assert_eq!(
            validate_folder_name(" Work / Servers ").unwrap(),
            "Work/Servers"
        );
        for bad in ["", " ", "/Work", "Work/", "Work//Servers"] {
            assert!(validate_folder_name(bad).is_err(), "{bad:?}");
        }
        assert_eq!(folder_path("0b5e-11aa").unwrap(), "/api/folders/0b5e-11aa");
        assert!(folder_path("../ciphers").is_err());
    }

    #[test]
    fn save_request_validates_draft() {
        let key = [27u8; 64];
        let stored = editable_login(&key);
        let mut draft = draft_from_raw(&stored.raw, &key).unwrap();
        draft.name = "  ".into();
        assert!(build_save_request(&stored, &draft, "now").is_err());

        let mut draft = draft_from_raw(&stored.raw, &key).unwrap();
        draft.fields[0].name.clear();
        assert!(build_save_request(&stored, &draft, "now").is_err());
    }

    #[test]
    fn refuses_to_edit_nested_only_ciphers() {
        let key = [28u8; 64];
        let raw = json!({
            "id": "c", "type": 1,
            "data": {"name": encrypt_string("Old format", &key), "username": null},
        });

        assert!(ensure_editable(&raw).is_err());
        assert!(ensure_editable(&editable_login(&key).raw).is_ok());
    }

    #[test]
    fn create_request_encrypts_login_and_decodes_back() {
        let key = [29u8; 64];
        let draft = ItemDraft {
            folder_id: None,
            favorite: false,
            name: "Throwaway".into(),
            notes: String::new(),
            login: Some(LoginDraft {
                passkeys: Vec::new(),
                username: "tester".into(),
                password: "pw".into(),
                totp: String::new(),
                uris: vec![DraftUri {
                    uri: "https://t.example".into(),
                    original_index: None,
                }],
            }),
            fields: vec![DraftField {
                name: "Pin".into(),
                value: "42".into(),
                kind: DraftFieldKind::Hidden,
                original_index: None,
            }],
        };

        let mut body = build_create_request(&draft, &key).unwrap();

        assert_eq!(body["type"], 1);
        assert!(body["notes"].is_null());
        assert!(body["login"]["totp"].is_null());
        assert!(body["secureNote"].is_null());
        // Round-trip the request as if the server echoed it back.
        body["id"] = json!("new-id");
        let (detail, _) = decode_cipher(body, &key, &HashMap::new(), &HashMap::new()).unwrap();
        assert_eq!(detail.name, "Throwaway");
        assert_eq!(detail.username.as_deref(), Some("tester"));
        assert_eq!(detail.password.as_deref(), Some("pw"));
        assert_eq!(detail.uris, vec!["https://t.example".to_string()]);
        assert_eq!(detail.custom_fields[0].value, "42");
        assert!(detail.custom_fields[0].hidden);
    }

    #[test]
    fn create_request_without_login_is_a_secure_note() {
        let key = [30u8; 32];
        let draft = ItemDraft {
            folder_id: None,
            favorite: false,
            name: "Note".into(),
            notes: "text".into(),
            ..ItemDraft::default()
        };

        let body = build_create_request(&draft, &key).unwrap();

        assert_eq!(body["type"], 2);
        assert_eq!(body["secureNote"]["type"], 0);
        assert!(body["login"].is_null());
        assert_eq!(
            decrypt_string(body["notes"].as_str().unwrap(), &key)
                .unwrap()
                .as_deref(),
            Some("text")
        );
        assert!(
            build_create_request(&ItemDraft::default(), &key).is_err(),
            "name is required"
        );
    }
    fn offline_fixture() -> (BwClient, SavedSession) {
        let mut client = protected_fixture();
        client.base_url = "https://127.0.0.1:1".into();
        client.email = Some("audit@example.test".into());
        client.client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        let (salt, kdf, wrapped) = client.reauth.clone().unwrap();
        let mut saved = SavedSession {
            server_url: client.base_url.clone(),
            email: client.email.clone().unwrap(),
            refresh_token: String::new(),
            encrypted_refresh_token: None,
            master_key_encrypted_user_key: wrapped,
            salt,
            kdf,
        };
        encrypt_session_token(&mut saved, "refresh", client.user_key.as_ref().unwrap()).unwrap();
        config::save_session(&saved).unwrap();
        let mut raw = client.ciphers["cipher-edit"].raw.clone();
        raw_set(&mut raw, "reprompt", json!(0));
        raw["login"]["totp"] = json!(
            super::encrypt_string("JBSWY3DPEHPK3PXP", client.user_key.as_ref().unwrap()).unwrap()
        );
        let body = json!({"profile": {"organizations": []}, "folders": [], "ciphers": [raw, {"id": "unknown", "type": 99}]}).to_string();
        client.apply_sync_body(&body).unwrap();
        client.sync_status.cache_synced_unix = Some(123);
        client.persist_offline_cache();
        (client, saved)
    }

    #[test]
    fn cold_offline_unlock_preserves_items_totp_and_unknown_ciphers() {
        config::with_test_config(|_| {
            let (mut client, saved) = offline_fixture();
            let original = config::load_vault_cache().unwrap();
            client.access_token = None;
            client.user_key = None;
            client.reauth = None;
            client.items.clear();
            client.ciphers.clear();
            client.verified_unlock = false;
            assert!(!client.has_verified_unlock());
            client.unlock_saved_session(&saved, "correct").unwrap();
            assert!(client.has_session());
            assert!(client.has_verified_unlock());
            assert!(client.sync_status.offline);
            assert_eq!(client.sync_status.cache_synced_unix, Some(123));
            assert_eq!(
                client
                    .list_items_in(ItemState::Active, "Example")
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                client.get_item("cipher-edit").unwrap().password.as_deref(),
                Some("current-password")
            );
            assert!(client.get_totp("cipher-edit").is_ok());
            assert_eq!(client.undecodable_ciphers.len(), 1);
            assert_eq!(client.sync_status.skipped_items, 1);
            // Wrong passwords fail locally without overwriting the snapshot.
            assert!(client.unlock_saved_session(&saved, "wrong").is_err());
            assert!(!client.has_verified_unlock());
            assert_eq!(config::load_vault_cache().unwrap(), original);
            // A cache read is not a new server sync.
            client.persist_offline_cache();
            let snapshot = crate::offline_cache::decode(
                &config::load_vault_cache().unwrap(),
                client.user_key.as_ref().unwrap(),
                &saved.server_url,
                &saved.email,
            )
            .unwrap();
            assert_eq!(snapshot.synced_at_unix, 123);
            assert_eq!(snapshot.ciphers.len(), 2);
        });
    }

    #[test]
    fn offline_write_guards_and_retry_backoff() {
        let mut client = protected_fixture();
        client.access_token = None;
        client.sync_status.offline = true;
        assert!(client.has_session());
        let draft = ItemDraft::default();
        let errors = [
            client
                .apply_action("cipher-edit", ItemAction::Trash)
                .unwrap_err(),
            client.move_item("cipher-edit", None).unwrap_err(),
            client.create_folder("folder").unwrap_err(),
            client.rename_folders(&[]).unwrap_err(),
            client.delete_folders(&[]).unwrap_err(),
            client.edit_draft("cipher-edit").unwrap_err(),
            client.save_item("cipher-edit", &draft).unwrap_err(),
            client.create_item(&draft).unwrap_err(),
        ];
        for error in errors {
            assert!(error.to_string().starts_with("Offline: editing"));
        }
        client.last_sync_attempt = Some(Instant::now());
        client.sync_if_stale();
        assert!(client.sync_warning.is_none());
    }

    #[test]
    fn disabled_missing_and_corrupt_cache_do_not_unlock() {
        config::with_test_config(|_| {
            let (client, saved) = offline_fixture();
            config::save_settings(&config::AppSettings {
                keep_offline_copy: false,
                ..Default::default()
            })
            .unwrap();
            let mut candidate = client.clone();
            candidate.access_token = None;
            assert!(matches!(
                candidate.unlock_saved_session(&saved, "correct"),
                Err(BwError::Network(_))
            ));
            assert!(!candidate.has_verified_unlock());
            candidate.apply_offline_setting().unwrap();
            assert!(config::load_vault_cache().is_none());
            config::save_settings(&config::AppSettings::default()).unwrap();
            assert!(matches!(
                candidate.unlock_saved_session(&saved, "correct"),
                Err(BwError::Network(_))
            ));
            assert!(!candidate.has_verified_unlock());
            config::save_vault_cache(b"corrupt").unwrap();
            assert!(matches!(
                candidate.unlock_saved_session(&saved, "correct"),
                Err(BwError::Network(_))
            ));
            assert!(!candidate.has_verified_unlock());
            client.clone().apply_offline_setting().unwrap();
            assert!(config::load_vault_cache().unwrap().contains("version"));
        });
    }

    // A local HTTP server exercises transport/status handling without external services.
    pub(super) fn serve_responses(
        responses: Vec<(u16, String)>,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                let headers = String::from_utf8_lossy(&request);
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        line.to_lowercase()
                            .strip_prefix("content-length:")
                            .map(|s| s.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                let mut body_buffer = vec![0; length];
                stream.read_exact(&mut body_buffer).unwrap();
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        (url, thread)
    }

    #[test]
    fn reconnect_refreshes_token_syncs_and_replaces_snapshot() {
        config::with_test_config(|_| {
            let (mut client, mut saved) = offline_fixture();
            let body =
                json!({"profile": {"organizations": []}, "folders": [], "ciphers": []}).to_string();
            let (url, thread) = serve_responses(vec![
                (
                    200,
                    json!({"access_token": "new-access", "refresh_token": "rotated"}).to_string(),
                ),
                (200, body),
            ]);
            saved.server_url = url.clone();
            encrypt_session_token(&mut saved, "refresh", client.user_key.as_ref().unwrap())
                .unwrap();
            config::save_session(&saved).unwrap();
            client.base_url = url;
            client.refresh_token = Some("refresh".into());
            client.access_token = None;
            client.sync_status.offline = true;
            client.retry_seconds = 300;
            let status = client.sync_now().unwrap();
            thread.join().unwrap();
            assert!(!status.offline);
            assert_eq!(client.retry_seconds, 60);
            assert!(client.items.is_empty());
            assert!(client.sync_warning.is_none());
            let loaded = config::load_saved_session().unwrap();
            assert_eq!(
                saved_session_token(&loaded, client.user_key.as_ref().unwrap()).unwrap(),
                "rotated"
            );
            let cache = crate::offline_cache::decode(
                &config::load_vault_cache().unwrap(),
                client.user_key.as_ref().unwrap(),
                &saved.server_url,
                &saved.email,
            )
            .unwrap();
            assert!(cache.ciphers.is_empty());
        });
    }

    #[test]
    fn confirmed_revocation_clears_cache_session_and_unlocked_keys() {
        config::with_test_config(|_| {
            for responses in [
                vec![(400, json!({"error": "invalid_grant"}).to_string())],
                vec![
                    (200, json!({"access_token": "revoked"}).to_string()),
                    (401, "{}".into()),
                    (200, json!({"access_token": "still-revoked"}).to_string()),
                    (401, "{}".into()),
                ],
            ] {
                let (mut client, _) = offline_fixture();
                let (url, thread) = serve_responses(responses);
                client.base_url = url;
                client.refresh_token = Some("refresh".into());
                client.access_token = None;
                client.sync_status.offline = true;
                assert!(client.sync_now().is_err());
                thread.join().unwrap();
                assert!(!client.has_session());
                assert!(!client.has_verified_unlock());
                assert!(client.ssh_keys().is_err());
                assert!(config::load_vault_cache().is_none());
                assert!(config::load_saved_session().is_none());
            }
        });
    }

    #[test]
    fn successful_writes_update_cache_even_when_followup_fetch_fails() {
        config::with_test_config(|_| {
            let (mut client, mut saved) = offline_fixture();
            let folder = json!({"id": "folder", "name": super::encrypt_string("Work", client.user_key.as_ref().unwrap()).unwrap()});
            let (url, thread) = serve_responses(vec![
                (200, folder.to_string()), // create folder
                (204, String::new()),
                (500, "{}".into()), // move item, fetch
                (204, String::new()),
                (500, "{}".into()), // archive, fetch
                (204, String::new()),
                (500, "{}".into()), // unfavorite, fetch
                (200, "{}".into()),
                (500, "{}".into()), // rename folder, sync
                (200, "{}".into()),
                (500, "{}".into()), // delete folder, sync
                (204, String::new()),
                (500, "{}".into()), // trash, fetch
                (200, "{}".into()), // delete forever
            ]);
            saved.server_url = url.clone();
            encrypt_session_token(&mut saved, "refresh", client.user_key.as_ref().unwrap())
                .unwrap();
            config::save_session(&saved).unwrap();
            client.base_url = url;
            let snapshot = |client: &BwClient| {
                crate::offline_cache::decode(
                    &config::load_vault_cache().unwrap(),
                    client.user_key.as_ref().unwrap(),
                    &saved.server_url,
                    &saved.email,
                )
                .unwrap()
            };
            client.create_folder("Work").unwrap();
            assert_eq!(snapshot(&client).folders.len(), 1);
            client.move_item("cipher-edit", Some("folder")).unwrap();
            client
                .apply_action("cipher-edit", ItemAction::Archive)
                .unwrap();
            client
                .apply_action("cipher-edit", ItemAction::Unfavorite)
                .unwrap();
            let copy = snapshot(&client);
            let raw = copy
                .ciphers
                .iter()
                .find(|v| v["id"] == "cipher-edit")
                .unwrap();
            assert_eq!(raw["folderId"], "folder");
            assert_eq!(raw["favorite"], false);
            assert!(raw["archivedDate"].is_string());
            assert!(
                client
                    .rename_folders(&[("folder".into(), "Renamed".into())])
                    .is_err()
            );
            let copy = snapshot(&client);
            assert_eq!(
                decrypt_string(
                    copy.folders[0]["name"].as_str().unwrap(),
                    client.user_key.as_ref().unwrap()
                )
                .unwrap(),
                Some("Renamed".into())
            );
            assert!(client.delete_folders(&["folder".into()]).is_err());
            let copy = snapshot(&client);
            assert!(copy.folders.is_empty());
            assert!(
                copy.ciphers
                    .iter()
                    .find(|v| v["id"] == "cipher-edit")
                    .unwrap()["folderId"]
                    .is_null()
            );
            client
                .apply_action("cipher-edit", ItemAction::Trash)
                .unwrap();
            assert!(
                snapshot(&client)
                    .ciphers
                    .iter()
                    .find(|v| v["id"] == "cipher-edit")
                    .unwrap()["deletedDate"]
                    .is_string()
            );
            client
                .apply_action("cipher-edit", ItemAction::DeleteForever)
                .unwrap();
            assert_eq!(snapshot(&client).ciphers.len(), 1); // unknown cipher remains
            thread.join().unwrap();
        });
    }

    #[test]
    fn response_body_disconnect_is_network_but_server_errors_are_not() {
        use std::io::{Read, Write};
        let mut client = protected_fixture();
        client.client = Client::builder().no_proxy().build().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        client.base_url = format!("http://{}", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\nConnection: close\r\n\r\n{}",
                )
                .unwrap();
        });
        assert!(matches!(client.sync_now(), Err(BwError::Network(_))));
        assert!(client.sync_status.offline);
        thread.join().unwrap();
        for (status, body) in [(503, "{}"), (200, "invalid JSON")] {
            let (url, thread) = serve_responses(vec![(status, body.into())]);
            client.base_url = url;
            client.sync_status.offline = false;
            assert!(!matches!(
                client.sync_now().unwrap_err(),
                BwError::Network(_)
            ));
            assert!(!client.sync_status.offline);
            thread.join().unwrap();
        }
    }

    pub(super) fn protected_fixture() -> BwClient {
        let user_key = vec![24u8; 64];
        let salt = "audit@example.test".to_string();
        let kdf = SavedKdf {
            kdf_type: 0,
            iterations: 1000,
            memory: None,
            parallelism: None,
        };
        let master = derive_master_key("correct", &salt, 0, 1000, None, None).unwrap();
        let wrapped = super::encrypt_bytes_with_iv(&user_key, &master, [4u8; 16]).unwrap();
        let stored = editable_login(&user_key);
        let (detail, stored) = decode_cipher(
            stored.raw.clone(),
            &user_key,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        let mut client = BwClient {
            email: None,
            raw_profile: None,
            raw_folders: Vec::new(),
            undecodable_ciphers: Vec::new(),
            retry_seconds: 60,
            client: Client::new(),
            reauth: Some((salt, kdf, wrapped)),
            verified_unlock: false,
            item_grants: HashMap::new(),
            base_url: "https://example.test".into(),
            device_identifier: "test".into(),
            access_token: Some("test".into()),
            refresh_token: None,
            user_key: Some(user_key),
            items: vec![detail],
            ciphers: HashMap::from([("cipher-edit".into(), stored)]),
            folders: HashMap::new(),
            organization_keys: HashMap::new(),
            sync_warning: None,
            sync_status: SyncStatus::default(),
            last_sync_attempt: None,
            health_cache: None,
        };
        client.verify_master_password("correct").unwrap();
        client.verified_unlock = true;
        client
    }

    #[test]
    fn browser_cards_mask_summaries_and_recheck_type_revision_reprompt_and_state() {
        let mut client = BwClient::browser_card_test_fixture(true);
        let cards = client.browser_cards().unwrap();
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].username.as_deref(), Some("Visa •••• 1111"));
        let revision = cards[0].revision.clone();
        assert!(matches!(
            client.browser_card("cipher-edit", &revision, false),
            Err(BwError::RepromptRequired)
        ));
        assert!(client.browser_card("cipher-edit", "stale", true).is_err());
        let card = client.browser_card("cipher-edit", &revision, true).unwrap();
        assert_eq!(card.number, "4111111111111111");
        assert_eq!(card.code, "123");
        assert!(!format!("{card:?}").contains("4111"));
        client.items[0].state = ItemState::Deleted;
        assert!(client.browser_cards().unwrap().is_empty());
        assert!(client.browser_card("cipher-edit", &revision, true).is_err());
        client.items[0].state = ItemState::Active;
        client.items[0].item_type = "login".into();
        assert!(client.browser_card("cipher-edit", &revision, true).is_err());
        client.user_key = None;
        assert!(client.browser_cards().is_err());
    }

    #[test]
    fn browser_uri_rules_keep_alignment_and_accept_server_aliases() {
        let key = [55u8; 64];
        let uris: Vec<LoginUriResponse> = serde_json::from_value(json!([
            { "uri": null, "match": 5 },
            { "Uri": encrypt_string("example.com", &key), "Match": 1 },
            { "uri": encrypt_string("^https://example", &key), "match": 4 },
            { "uri": encrypt_string("unknown.example", &key), "match": 200 },
            { "uri": encrypt_string("invalid.example", &key), "match": "host" },
            { "uri": encrypt_string("default.example", &key), "match": null }
        ]))
        .unwrap();
        let decoded = decrypt_uris(Some(&uris), &key).unwrap();
        assert_eq!(decoded.len(), 5);
        assert_eq!(decoded[0].uri, "example.com");
        assert_eq!(decoded[0].match_type, Some(UriMatchType::Host));
        assert_eq!(decoded[1].match_type, Some(UriMatchType::RegularExpression));
        assert_eq!(decoded[2].match_type, Some(UriMatchType::Unsupported));
        assert_eq!(decoded[3].match_type, Some(UriMatchType::Unsupported));
        assert_eq!(decoded[4].match_type, None);
    }

    #[test]
    fn browser_matching_uses_active_logins_and_the_frame_uri() {
        let mut client = protected_fixture();
        let matches = client
            .browser_matches("https://one.example/login", UriMatchType::Host)
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert!(matches[0].reprompt);
        assert!(!matches[0].insecure_downgrade);
        assert!(
            client
                .browser_matches("https://unrelated.example/", UriMatchType::Host)
                .unwrap()
                .is_empty()
        );
        assert!(
            client
                .browser_matches("javascript:one.example", UriMatchType::Host)
                .unwrap()
                .is_empty()
        );
        for state in [ItemState::Archived, ItemState::Deleted] {
            client.items[0].state = state;
            assert!(
                client
                    .browser_matches("https://one.example/", UriMatchType::Host)
                    .unwrap()
                    .is_empty()
            );
            assert!(matches!(
                client.browser_credentials(
                    "cipher-edit",
                    &matches[0].revision,
                    "https://one.example/",
                    UriMatchType::Host,
                    true
                ),
                Err(BwError::NotFound)
            ));
        }
        client.items[0].state = ItemState::Active;
        client.items[0].item_type = "secureNote".into();
        assert!(
            client
                .browser_matches("https://one.example/", UriMatchType::Host)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn browser_totp_rechecks_authorization_revision_uri_and_lock() {
        let mut client = protected_fixture();
        client.items[0].totp = Some("JBSWY3DPEHPK3PXP".into());
        let summary = client
            .browser_totp_matches("https://one.example/", UriMatchType::Host)
            .unwrap()
            .remove(0);
        assert!(matches!(
            client.browser_totp(
                "cipher-edit",
                &summary.revision,
                "https://one.example/",
                UriMatchType::Host,
                false
            ),
            Err(BwError::RepromptRequired)
        ));
        assert!(matches!(
            client.browser_totp(
                "cipher-edit",
                &summary.revision,
                "https://unrelated.example/",
                UriMatchType::Host,
                true
            ),
            Err(BwError::NotFound)
        ));
        assert!(matches!(
            client.browser_totp(
                "cipher-edit",
                "stale",
                "https://one.example/",
                UriMatchType::Host,
                true
            ),
            Err(BwError::NotFound)
        ));
        let code = client
            .browser_totp(
                "cipher-edit",
                &summary.revision,
                "https://one.example/",
                UriMatchType::Host,
                true,
            )
            .unwrap();
        assert_eq!(code.code.len(), 6);
        assert!(code.code.bytes().all(|b| b.is_ascii_digit()));
        client.items[0].totp = None;
        assert!(
            client
                .browser_totp_matches("https://one.example/", UriMatchType::Host)
                .unwrap()
                .is_empty()
        );
        client.user_key = None;
        assert!(
            client
                .browser_totp(
                    "cipher-edit",
                    &summary.revision,
                    "https://one.example/",
                    UriMatchType::Host,
                    true
                )
                .is_err()
        );
    }

    #[test]
    fn browser_credentials_recheck_rules_revision_and_browser_authorization() {
        let mut client = protected_fixture();
        let summary = client
            .browser_matches("https://one.example/", UriMatchType::Host)
            .unwrap()
            .remove(0);
        client.authorize_item("cipher-edit", "correct").unwrap();
        assert!(matches!(
            client.browser_credentials(
                "cipher-edit",
                &summary.revision,
                "https://one.example/",
                UriMatchType::Host,
                false
            ),
            Err(BwError::RepromptRequired)
        ));
        assert!(matches!(
            client.browser_credentials(
                "cipher-edit",
                &summary.revision,
                "https://unrelated.example/",
                UriMatchType::Host,
                true
            ),
            Err(BwError::NotFound)
        ));
        let credentials = client
            .browser_credentials(
                "cipher-edit",
                &summary.revision,
                "https://one.example/",
                UriMatchType::Host,
                true,
            )
            .unwrap();
        assert_eq!(credentials.username.as_deref(), Some("alice"));
        assert_eq!(credentials.password.as_deref(), Some("current-password"));
        let serialized = serde_json::to_value(&credentials).unwrap();
        assert_eq!(serialized.as_object().unwrap().len(), 3);
        assert!(!format!("{credentials:?}").contains("current-password"));
        client.ciphers.get_mut("cipher-edit").unwrap().raw["favorite"] = json!(false);
        assert!(matches!(
            client.browser_credentials(
                "cipher-edit",
                &summary.revision,
                "https://one.example/",
                UriMatchType::Host,
                true
            ),
            Err(BwError::NotFound)
        ));
    }

    #[test]
    fn browser_rules_are_daemon_only_and_default_is_used_only_for_null_rules() {
        let mut client = protected_fixture();
        let key = client.user_key.clone().unwrap();
        let mut raw = client.ciphers["cipher-edit"].raw.clone();
        raw["login"]["uris"] = json!([
            { "uri": null, "match": 0 },
            { "uri": encrypt_string("https://example.com", &key), "match": null }
        ]);
        client.replace_cipher(raw.clone()).unwrap();
        assert!(
            client
                .browser_matches("https://sub.example.com", UriMatchType::Host)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            client
                .browser_matches("https://sub.example.com", UriMatchType::Domain)
                .unwrap()
                .len(),
            1
        );
        let detail_json = serde_json::to_value(&client.items[0]).unwrap();
        assert_eq!(detail_json["uris"], json!(["https://example.com"]));
        assert!(detail_json.get("browser_uris").is_none());
        assert!(detail_json.get("uri_matches").is_none());
        raw["login"]["uris"][1]["match"] = json!(5);
        client.replace_cipher(raw).unwrap();
        assert!(
            client
                .browser_matches("https://example.com", UriMatchType::Domain)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn browser_downgrade_is_reported_by_listing_and_secret_request() {
        let client = protected_fixture();
        let summary = client
            .browser_matches("http://one.example/", UriMatchType::Host)
            .unwrap()
            .remove(0);
        assert!(summary.insecure_downgrade);
        assert!(
            client
                .browser_credentials(
                    "cipher-edit",
                    &summary.revision,
                    "http://one.example/",
                    UriMatchType::Host,
                    true
                )
                .unwrap()
                .insecure_downgrade
        );
    }

    #[test]
    fn master_password_verification_never_creates_an_item_grant() {
        let mut client = protected_fixture();
        assert!(client.verify_master_password("wrong").is_err());
        client.verify_master_password("correct").unwrap();
        assert!(client.item_grants.is_empty());
        assert!(matches!(
            client.get_item("cipher-edit"),
            Err(BwError::RepromptRequired)
        ));
        client.user_key = None;
        assert!(matches!(
            client.verify_master_password("correct"),
            Err(BwError::NotUnlocked)
        ));
        assert!(matches!(
            client.browser_matches("https://one.example/", UriMatchType::Host),
            Err(BwError::NotUnlocked)
        ));
    }

    #[test]
    fn server_url_requires_https_and_rejects_ambiguous_authority() {
        for url in [
            "http://vault.example.com",
            "http://localhost",
            "https://user:pass@example.com",
            "https://example.com?q=x",
            "https://example.com/#x",
            "not a URL",
        ] {
            assert!(normalize_server_url(url).is_err(), "{url}");
        }
        assert_eq!(
            normalize_server_url(" https://example.com/vault/ ").unwrap(),
            "https://example.com/vault"
        );
    }

    fn session_fixture() -> SavedSession {
        SavedSession {
            server_url: "https://vault.example.test".into(),
            email: "fixture@example.test".into(),
            refresh_token: "legacy-refresh-secret".into(),
            encrypted_refresh_token: None,
            master_key_encrypted_user_key: "encrypted-key".into(),
            salt: "fixture@example.test".into(),
            kdf: SavedKdf {
                kdf_type: 0,
                iterations: 1,
                memory: None,
                parallelism: None,
            },
        }
    }

    #[test]
    fn saved_token_migration_and_rotation_never_serialize_plaintext() {
        let key = [42u8; 64];
        let mut saved = session_fixture();
        assert_eq!(
            saved_session_token(&saved, &key).unwrap(),
            "legacy-refresh-secret"
        );
        assert!(config::save_session(&saved).is_err());
        encrypt_session_token(&mut saved, "legacy-refresh-secret", &key).unwrap();
        assert!(saved.refresh_token.is_empty());
        let encoded = serde_json::to_string(&saved).unwrap();
        assert!(!encoded.contains("legacy-refresh-secret"));
        assert!(!encoded.contains("\"refresh_token\""));
        let mut loaded: SavedSession = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            saved_session_token(&loaded, &key).unwrap(),
            "legacy-refresh-secret"
        );
        encrypt_session_token(&mut loaded, "rotated-refresh-secret", &key).unwrap();
        assert_eq!(
            saved_session_token(&loaded, &key).unwrap(),
            "rotated-refresh-secret"
        );
        assert_ne!(
            loaded.encrypted_refresh_token,
            saved.encrypted_refresh_token
        );
        assert!(!format!("{:?}", session_fixture()).contains("legacy-refresh-secret"));
    }

    #[test]
    fn saved_token_rejects_wrong_key_tampering_and_account_substitution() {
        let key = [42u8; 64];
        let mut saved = session_fixture();
        encrypt_session_token(&mut saved, "secret", &key).unwrap();
        assert!(saved_session_token(&saved, &[43u8; 64]).is_err());
        let original = saved.encrypted_refresh_token.clone().unwrap();
        let mut bytes = original.as_bytes().to_vec();
        bytes[2] = if bytes[2] == b'A' { b'B' } else { b'A' };
        saved.encrypted_refresh_token = Some(String::from_utf8(bytes).unwrap());
        assert!(saved_session_token(&saved, &key).is_err());
        saved.encrypted_refresh_token = Some(original);
        saved.email = "other@example.test".into();
        assert!(saved_session_token(&saved, &key).is_err());
        saved.encrypted_refresh_token = Some("0.unauthenticated".into());
        assert!(saved_session_token(&saved, &key).is_err());
    }

    #[test]
    fn copying_rejects_a_stale_item_after_fields_shift() {
        let mut client = protected_fixture();
        let item = &mut client.items[0];
        item.username = Some("fixture user".into());
        item.password = Some("fixture password".into());
        let version = item.copy_version();
        assert_eq!(
            item.copy_value_checked(0, &version).unwrap(),
            "fixture user"
        );
        item.username = None;
        assert!(item.copy_value_checked(0, &version).is_err());
        assert_eq!(
            item.copy_value_checked(0, &item.copy_version()).unwrap(),
            "fixture password"
        );
    }

    #[test]
    fn protected_item_requires_password_and_expires_or_revokes_access() {
        let mut client = protected_fixture();
        assert!(matches!(
            client.get_item("cipher-edit"),
            Err(BwError::RepromptRequired)
        ));
        assert!(matches!(
            client.edit_draft("cipher-edit"),
            Err(BwError::RepromptRequired)
        ));
        assert!(client.authorize_item("cipher-edit", "wrong").is_err());
        assert!(client.item_grants.is_empty());
        assert_eq!(
            client
                .authorize_item("cipher-edit", "correct")
                .unwrap()
                .password
                .as_deref(),
            Some("current-password")
        );
        assert!(client.edit_draft("cipher-edit").is_ok());
        client.item_grants.insert(
            "cipher-edit".into(),
            Instant::now() - Duration::from_secs(61),
        );
        assert!(matches!(
            client.get_item("cipher-edit"),
            Err(BwError::RepromptRequired)
        ));
        client.authorize_item("cipher-edit", "correct").unwrap();
        client.revoke_item_grants();
        assert!(matches!(
            client.get_item("cipher-edit"),
            Err(BwError::RepromptRequired)
        ));
    }
}
