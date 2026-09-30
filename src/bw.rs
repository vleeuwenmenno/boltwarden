use crate::config;
use crate::config::{SavedKdf, SavedSession};
use crate::model::{
    BwItem, BwItemDetail, CustomField, DraftField, DraftFieldKind, DraftUri, ItemAction,
    ItemDates, ItemDraft, ItemState, LoginDraft, SshKey, SyncStatus, TotpCode,
};
use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use reqwest::Method;
use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use sha1::Sha1;
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const HTTP_TIMEOUT: Duration = Duration::from_secs(12);
const CLIENT_NAME: &str = "bw-quick-access";
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
    client: Client,
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
}

#[derive(Clone)]
struct StoredCipher {
    raw: Value,
    item_key: Vec<u8>,
    revision_date: Option<String>,
}

#[derive(Debug)]
pub enum BwError {
    NotUnlocked,
    TwoFactorRequired(TwoFactorChallenge),
    Cli(String),
    Parse(String),
    NotFound,
}

impl std::fmt::Display for BwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BwError::NotUnlocked => write!(f, "vault is not unlocked"),
            BwError::TwoFactorRequired(_) => write!(f, "two factor required"),
            BwError::Cli(s) => write!(f, "{s}"),
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

impl Default for BwClient {
    fn default() -> Self {
        Self::new()
    }
}

impl BwClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(HTTP_TIMEOUT)
                .user_agent("bw-quick-access/0.1")
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
        }
    }

    pub fn has_session(&self) -> bool {
        self.access_token.is_some() && self.user_key.is_some()
    }

    pub fn unlock_saved_session(
        &mut self,
        saved: &SavedSession,
        password: &str,
    ) -> Result<(), BwError> {
        self.base_url = normalize_server_url(&saved.server_url)?;
        let master_key = master_key_from_saved(password, saved)?;
        let user_key = unwrap_user_key(&saved.master_key_encrypted_user_key, &master_key)?;
        self.refresh_token = Some(saved.refresh_token.clone());
        self.refresh_session()?;
        self.user_key = Some(user_key);
        self.sync()?;
        Ok(())
    }

    pub fn login(
        &mut self,
        server_url: &str,
        email: &str,
        password: &str,
        remember: bool,
    ) -> Result<(), BwError> {
        self.base_url = normalize_server_url(server_url)?;
        let prelogin = self.prelogin(email)?;
        let master_key = master_key(email, password, &prelogin)?;
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
                    master_key,
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
            None => master_key,
        };
        let user_key = unwrap_user_key(wrapped_user_key, &master_key)?;
        save_successful_session(
            &self.base_url,
            email,
            token.refresh_token.as_deref(),
            wrapped_user_key,
            saved_kdf_from_login(email, &prelogin, unlock_data),
        );

        self.refresh_token = token.refresh_token;
        self.access_token = Some(token.access_token);
        self.user_key = Some(user_key);
        self.sync()?;
        Ok(())
    }

    pub fn complete_two_factor(
        &mut self,
        challenge: &TwoFactorChallenge,
        provider: TwoFactorProvider,
        token_code: &str,
        remember: bool,
    ) -> Result<(), BwError> {
        self.base_url = challenge.base_url.clone();
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
        let user_key = unwrap_user_key(wrapped_user_key, &master_key)?;
        save_successful_session(
            &self.base_url,
            &challenge.email,
            token.refresh_token.as_deref(),
            wrapped_user_key,
            saved_kdf_from_challenge(&challenge.email, &challenge.kdf, unlock_data),
        );

        self.refresh_token = token.refresh_token;
        self.access_token = Some(token.access_token);
        self.user_key = Some(user_key);
        self.sync()
    }

    pub fn list_items_in(&self, state: ItemState, search: &str) -> Result<Vec<BwItem>, BwError> {
        self.require_unlocked()?;
        let needle = search.trim().to_lowercase();
        Ok(ranked_search_results(
            self.items.iter().filter(|item| item.state == state),
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
            .map_err(|e| BwError::Cli(format!("refresh request failed: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            return Err(BwError::Cli(format!("refresh failed with HTTP {status}: {body}")));
        }
        let token: RefreshTokenResponse = response
            .json()
            .map_err(|e| BwError::Parse(format!("refresh response: {e}")))?;
        self.access_token = Some(token.access_token);
        if let Some(refresh_token) = token.refresh_token {
            self.refresh_token = Some(refresh_token);
        }
        Ok(())
    }

    pub fn get_item(&self, id: &str) -> Result<BwItemDetail, BwError> {
        self.require_unlocked()?;
        self.items
            .iter()
            .find(|item| item.id == id)
            .cloned()
            .ok_or(BwError::NotFound)
    }

    pub fn get_totp(&self, id: &str) -> Result<TotpCode, BwError> {
        let detail = self.get_item(id)?;
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
            .filter_map(|item| item.ssh_key.clone())
            .collect())
    }

    pub fn apply_action(&mut self, id: &str, action: ItemAction) -> Result<(), BwError> {
        self.require_unlocked()?;
        let state = self.get_item(id)?.state;
        if !action_allowed(action, state) {
            return Err(BwError::Cli(format!(
                "{action:?} is not available for an item that is {state:?}"
            )));
        }
        let (method, path) = match action {
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
                    item.state = state_after(action);
                    item.dates.state_changed_at =
                        (item.state != ItemState::Active).then(iso8601_now);
                }
                Ok(())
            }
        }
    }

    pub fn edit_draft(&self, id: &str) -> Result<ItemDraft, BwError> {
        self.require_unlocked()?;
        let stored = self.ciphers.get(id).ok_or(BwError::NotFound)?;
        ensure_editable(&stored.raw)?;
        draft_from_raw(&stored.raw, &stored.item_key)
    }

    pub fn save_item(&mut self, id: &str, draft: &ItemDraft) -> Result<BwItemDetail, BwError> {
        self.require_unlocked()?;
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
            Some(slot) => *slot = detail,
            None => self.items.push(detail),
        }
        self.ciphers.insert(id, stored);
        Ok(())
    }

    /// Sends an authenticated API request, refreshing the access token once on HTTP 401.
    fn send_authed(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Response, BwError> {
        let response = self.send_authed_once(method.clone(), path, body)?;
        if response.status().as_u16() == 401 && self.refresh_token.is_some() {
            self.refresh_session()?;
            return self.send_authed_once(method, path, body);
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
            .header(sync_client_version_header().0, sync_client_version_header().1);
        if let Some(body) = body {
            request = request.json(body);
        }
        request
            .send()
            .map_err(|e| BwError::Cli(format!("request to {path} failed: {e}")))
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
            .map_err(|e| BwError::Cli(format!("prelogin request failed: {e}")))?;

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
            ("deviceName", "bw-quick-access"),
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
            .map_err(|e| BwError::Cli(format!("login request failed: {e}")))?;

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
            return Err(BwError::Cli(format!("login failed with HTTP {status}: {body}")));
        }

        response
            .json()
            .map(TokenResult::Success)
            .map_err(|e| BwError::Parse(format!("token response: {e}")))
    }

    fn sync(&mut self) -> Result<(), BwError> {
        let response = self.send_authed(Method::GET, "/api/sync?excludeDomains=true", None)?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(BwError::Cli(format!("sync failed with HTTP {status}: {body}")));
        }

        let user_key = self.user_key.as_deref().ok_or(BwError::NotUnlocked)?;
        let body = response
            .text()
            .map_err(|e| BwError::Parse(format!("sync response body: {e}")))?;
        let sync: SyncResponse = serde_json::from_str(&body).map_err(|e| {
            BwError::Parse(format!(
                "sync response: {e}; body starts with: {}",
                body.chars().take(300).collect::<String>()
            ))
        })?;
        let server_ciphers = sync.ciphers.len();
        let folders = decrypt_folders(sync.folders, user_key)?;
        let organization_keys = decrypt_organization_keys(sync.profile, user_key)?;
        let mut skipped = 0usize;
        let mut first_error = None;
        let mut items = Vec::with_capacity(server_ciphers);
        let mut ciphers = HashMap::with_capacity(server_ciphers);
        for raw in sync.ciphers {
            match decode_cipher(raw, user_key, &organization_keys, &folders) {
                Ok((item, stored)) => {
                    ciphers.insert(item.id.clone(), stored);
                    items.push(item);
                }
                Err(e) => {
                    skipped += 1;
                    first_error.get_or_insert_with(|| e.to_string());
                }
            }
        }
        self.items = items;
        self.ciphers = ciphers;
        self.folders = folders;
        self.organization_keys = organization_keys;
        self.sync_status = SyncStatus {
            server_ciphers,
            decrypted_items: self.items.len(),
            skipped_items: skipped,
            first_error: first_error.clone(),
        };
        self.sync_warning = decrypt_skip_warning(skipped, first_error);
        Ok(())
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
    title_match_rank(&item.name, needle).or_else(|| {
        secondary_matches_search(item, needle).then_some(SearchRank::SecondaryField)
    })
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

    item.username.as_deref().is_some_and(|value| text_matches(value, needle))
        || item.password.as_deref().is_some_and(|value| text_matches(value, needle))
        || item.folder.as_deref().is_some_and(|value| text_matches(value, needle))
        || text_matches(&item.item_type, needle)
        || item.notes.as_deref().is_some_and(|value| text_matches(value, needle))
        || item.uris.iter().any(|value| text_matches(value, needle))
        || item
            .ssh_key
            .as_ref()
            .is_some_and(|ssh_key| ssh_key_matches_search(ssh_key, needle))
        || item.custom_fields.iter().any(|field| {
            text_matches(&field.name, needle) || text_matches(&field.value, needle)
        })
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
            serde_json::Value::Number(number) => number
                .as_i64()
                .ok_or_else(|| serde::de::Error::custom("two factor provider id is not an integer"))?,
            serde_json::Value::String(text) => text
                .parse::<i64>()
                .map_err(|e| serde::de::Error::custom(format!("invalid two factor provider id: {e}")))?,
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
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginUriResponse {
    #[serde(default, alias = "Uri")]
    uri: Option<String>,
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

fn decrypt_cipher(
    cipher: CipherResponse,
    user_key: &[u8],
    organization_keys: &HashMap<String, Vec<u8>>,
    folders: &HashMap<String, String>,
) -> Result<BwItemDetail, BwError> {
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

    if let Some(data) = data {
        username = decrypt_opt_string(data.username.as_deref(), &item_key)?;
        password = decrypt_opt_string(data.password.as_deref(), &item_key)?;
        totp = decrypt_opt_string(data.totp.as_deref(), &item_key)?;
        uris = decrypt_uris(data.uris.as_deref(), &item_key)?;
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
        push_card_field(&mut custom_fields, "Number", data.number.clone(), &item_key, false)?;
        push_card_field(&mut custom_fields, "Brand", data.brand.clone(), &item_key, false)?;
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
        push_card_field(&mut custom_fields, "CVV", data.code.clone(), &item_key, true)?;
        push_identity_data_fields(&mut custom_fields, data, &item_key)?;
    }

    if let Some(card) = cipher.card {
        push_card_field(&mut custom_fields, "Cardholder", card.cardholder_name, &item_key, false)?;
        push_card_field(&mut custom_fields, "Number", card.number, &item_key, false)?;
        push_card_field(&mut custom_fields, "Brand", card.brand, &item_key, false)?;
        push_card_field(&mut custom_fields, "Exp Month", card.exp_month, &item_key, false)?;
        push_card_field(&mut custom_fields, "Exp Year", card.exp_year, &item_key, false)?;
        push_card_field(&mut custom_fields, "CVV", card.code, &item_key, true)?;
    }

    if let Some(identity) = cipher.identity {
        push_identity_fields(&mut custom_fields, identity, &item_key)?;
    }

    Ok(BwItemDetail {
        id: cipher.id,
        name,
        username,
        password,
        uris,
        totp,
        notes,
        custom_fields,
        folder: cipher
            .folder_id
            .and_then(|id| folders.get(&id).cloned().or(Some(id))),
        item_type: item_type_name(cipher.item_type).to_string(),
        ssh_key,
        state,
        dates: ItemDates {
            state_changed_at,
            ..ItemDates::default()
        },
    })
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
    let cipher: CipherResponse = serde_json::from_value(raw.clone())
        .map_err(|e| BwError::Parse(format!("cipher: {e}")))?;
    let item_key = cipher_item_key(&cipher, user_key, organization_keys)?;
    let mut detail = decrypt_cipher(cipher, user_key, organization_keys, folders)?;
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
        },
    ))
}

pub(crate) fn action_allowed(action: ItemAction, state: ItemState) -> bool {
    match action {
        ItemAction::Archive => state == ItemState::Active,
        ItemAction::Unarchive => state == ItemState::Archived,
        ItemAction::Trash => state != ItemState::Deleted,
        ItemAction::Restore | ItemAction::DeleteForever => state == ItemState::Deleted,
    }
}

pub(crate) fn state_after(action: ItemAction) -> ItemState {
    match action {
        ItemAction::Archive => ItemState::Archived,
        ItemAction::Trash | ItemAction::DeleteForever => ItemState::Deleted,
        ItemAction::Unarchive | ItemAction::Restore => ItemState::Active,
    }
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
    let item_type = object.get("type").and_then(Value::as_i64).ok_or_else(unsupported)?;
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
            Some(LoginDraft {
                username: raw_decrypt(&login, "username", item_key)?,
                password: raw_decrypt(&login, "password", item_key)?,
                totp: raw_decrypt(&login, "totp", item_key)?,
                uris,
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
    encrypt_value(&base64::engine::general_purpose::STANDARD.encode(digest), key)
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
        return Err(BwError::Cli("custom fields with a value need a name".into()));
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
        "folderId": null,
        "name": encrypt_value(&draft.name, key)?,
        "notes": encrypt_optional(&draft.notes, key)?,
        "favorite": false,
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
            if uris.is_empty() { Value::Null } else { Value::Array(uris) },
        );
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
        if fields.is_empty() { Value::Null } else { Value::Array(fields) },
    );

    if let Some(revision) = &stored.revision_date {
        body.insert("lastKnownRevisionDate".into(), Value::String(revision.clone()));
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

fn decrypt_uris(uris: Option<&[LoginUriResponse]>, key: &[u8]) -> Result<Vec<String>, BwError> {
    uris.unwrap_or(&[])
        .iter()
        .filter_map(|uri| decrypt_opt_string(uri.uri.as_deref(), key).transpose())
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
    let trimmed = server_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(BwError::Cli("server URL is required".into()));
    }
    if !trimmed.starts_with("https://") && !trimmed.starts_with("http://") {
        return Err(BwError::Cli(
            "server URL must start with https:// or http://".into(),
        ));
    }
    Ok(trimmed.to_string())
}

fn master_key(email: &str, password: &str, prelogin: &PreloginResponse) -> Result<Vec<u8>, BwError> {
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

    (
        email.trim().to_lowercase(),
        challenge_kdf.clone(),
    )
}

fn save_successful_session(
    server_url: &str,
    email: &str,
    refresh_token: Option<&str>,
    master_key_encrypted_user_key: &str,
    (salt, kdf): (String, SavedKdf),
) {
    let Some(refresh_token) = refresh_token else {
        return;
    };
    let session = SavedSession {
        server_url: server_url.to_string(),
        email: email.trim().to_string(),
        refresh_token: refresh_token.to_string(),
        master_key_encrypted_user_key: master_key_encrypted_user_key.to_string(),
        salt,
        kdf,
    };
    let _ = config::save_session(&session);
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
    let iv = crate::random::random_bytes::<16>()
        .map_err(|e| BwError::Cli(format!("could not read random bytes: {e}")))?;
    encrypt_bytes_with_iv(plaintext.as_bytes(), key, iv)
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
    value.map(|value| decrypt_string(value, key))
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

fn decrypt_bytes(value: &str, key: &[u8]) -> Result<Vec<u8>, BwError> {
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
mod tests {
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
            assert_eq!(generate_totp(seed, time).unwrap().code, expected, "time {time}");
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
                private_key: Some(encrypt_string("-----BEGIN OPENSSH PRIVATE KEY-----", &user_key)),
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
            ("Bitwarden-Client-Name", "bw-quick-access")
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
            cipher
                .login
                .as_ref()
                .unwrap()
                .uris
                .as_ref()
                .unwrap()[0]
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
            cipher
                .data
                .as_ref()
                .unwrap()
                .uris
                .as_ref()
                .unwrap()[0]
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
            assert_eq!(decrypt_string(&first, &key).unwrap().as_deref(), Some("hunter2"));
            assert_eq!(decrypt_string(&second, &key).unwrap().as_deref(), Some("hunter2"));
        }
    }

    #[test]
    fn formats_iso8601_timestamps() {
        assert_eq!(iso8601_from_unix_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601_from_unix_ms(951_782_400_123), "2000-02-29T00:00:00.123Z");
        assert_eq!(iso8601_from_unix_ms(1_790_762_163_576), "2026-09-30T09:56:03.576Z");
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
            decode_cipher(raw, &key, &HashMap::new(), &HashMap::new()).unwrap().0.state
        };

        assert_eq!(state(cipher(Value::Null, Value::Null)), ItemState::Active);
        assert_eq!(state(cipher(Value::Null, json!("2026-02-02"))), ItemState::Archived);
        assert_eq!(state(cipher(json!("2026-02-02"), json!("2026-02-02"))), ItemState::Deleted);
        let (_, stored) = decode_cipher(
            cipher(Value::Null, Value::Null),
            &key,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(stored.revision_date.as_deref(), Some("2026-01-01T00:00:00.000Z"));
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
        assert_eq!(
            cipher_path("0b6f-AB12").unwrap(),
            "/api/ciphers/0b6f-AB12"
        );
        assert!(cipher_path("../sync").is_err());
        assert!(cipher_path("").is_err());
    }

    fn editable_login(key: &[u8]) -> StoredCipher {
        let enc = |value: &str| encrypt_string(value, key);
        let history = (0..5)
            .map(|idx| json!({"password": enc(&format!("old-{idx}")), "lastUsedDate": "2025-01-01"}))
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
                "fido2Credentials": [{"credentialId": enc("passkey")}],
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
        let dec = |value: &Value| decrypt_string(value.as_str().unwrap(), &key).unwrap().unwrap();

        // Untouched data goes back byte for byte.
        assert_eq!(body["name"], raw["name"]);
        assert_eq!(body["favorite"], raw["favorite"]);
        assert_eq!(body["reprompt"], raw["reprompt"]);
        assert_eq!(body["login"]["username"], raw["login"]["username"]);
        assert_eq!(body["login"]["fido2Credentials"], raw["login"]["fido2Credentials"]);
        assert_eq!(body["login"]["uris"][0], raw["login"]["uris"][0]);
        assert!(body.get("data").is_none());
        // Edited values are re-encrypted, keeping their extra settings.
        assert_eq!(dec(&body["login"]["password"]), "new-password");
        assert_eq!(body["login"]["passwordRevisionDate"], "2026-09-30T10:00:00.000Z");
        assert_eq!(dec(&body["login"]["uris"][1]["uri"]), "https://three.example");
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
            name: "Throwaway".into(),
            notes: String::new(),
            login: Some(LoginDraft {
                username: "tester".into(),
                password: "pw".into(),
                totp: String::new(),
                uris: vec![DraftUri { uri: "https://t.example".into(), original_index: None }],
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
            name: "Note".into(),
            notes: "text".into(),
            ..ItemDraft::default()
        };

        let body = build_create_request(&draft, &key).unwrap();

        assert_eq!(body["type"], 2);
        assert_eq!(body["secureNote"]["type"], 0);
        assert!(body["login"].is_null());
        assert_eq!(decrypt_string(body["notes"].as_str().unwrap(), &key).unwrap().as_deref(), Some("text"));
        assert!(build_create_request(&ItemDraft::default(), &key).is_err(), "name is required");
    }
}
