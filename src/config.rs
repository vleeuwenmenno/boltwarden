use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use zeroize::Zeroizing;

const APP_DIR: &str = "boltwarden";
/// The directory name before the app was renamed from bw-quick-access.
const LEGACY_APP_DIR: &str = "bw-quick-access";
const DEVICE_ID_FILE: &str = "device-id";
const VAULT_CACHE_FILE: &str = "vault-cache.json";
const SESSION_FILE: &str = "session.json";
const SETTINGS_FILE: &str = "settings.json";
const RECENT_ITEM_FILE: &str = "recent-item.json";
const ITEM_USAGE_FILE: &str = "item-usage.json";
/// How many recently opened items the "Recently used" start list remembers.
pub const ITEM_USAGE_LIMIT: usize = 20;

/// What an empty search shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartList {
    #[default]
    None,
    RecentlyUsed,
    RecentlyEdited,
    RecentlyCreated,
}

impl StartList {
    pub fn next(self) -> Self {
        match self {
            Self::None => Self::RecentlyUsed,
            Self::RecentlyUsed => Self::RecentlyEdited,
            Self::RecentlyEdited => Self::RecentlyCreated,
            Self::RecentlyCreated => Self::None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::RecentlyUsed => "Recently used",
            Self::RecentlyEdited => "Recently edited",
            Self::RecentlyCreated => "Recently created",
        }
    }
}

/// Master-password verification policy for browser passkey operations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyVerification {
    #[default]
    Always,
    WhenRequired,
    VaultUnlock,
}

impl PasskeyVerification {
    pub fn next(self) -> Self {
        match self {
            Self::Always => Self::WhenRequired,
            Self::WhenRequired => Self::VaultUnlock,
            Self::VaultUnlock => Self::Always,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Always => "Always ask",
            Self::WhenRequired => "Only when required",
            Self::VaultUnlock => "Use vault unlock",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AppSettings {
    /// Browser access is opt-in and always uses a separate paired connection.
    #[serde(default)]
    pub browser_integration_enabled: bool,
    #[serde(default)]
    pub default_uri_match: crate::uri_match::UriMatchType,
    #[serde(default)]
    pub passkey_verification: PasskeyVerification,
    #[serde(default = "default_true")]
    pub keep_offline_copy: bool,
    #[serde(default = "default_true")]
    pub show_keyboard_shortcuts: bool,
    #[serde(default = "default_true")]
    pub close_after_copy: bool,
    #[serde(default = "default_true")]
    pub restore_recent_item: bool,
    #[serde(default)]
    pub ssh_agent_enabled: bool,
    #[serde(default = "default_ssh_agent_socket_path")]
    pub ssh_agent_socket_path: String,
    #[serde(default = "default_true")]
    pub lock_on_system_lock: bool,
    #[serde(default = "default_true")]
    pub lock_after_idle_timeout: bool,
    #[serde(default = "default_idle_lock_timeout_minutes")]
    pub idle_lock_timeout_minutes: u64,
    /// Fetch website icons from the vault server's icon service (cached on disk).
    #[serde(default = "default_true")]
    pub show_website_icons: bool,
    /// Ask Hyprland to obscure this popup in screenshots and screen sharing.
    #[serde(default = "default_true")]
    pub obscure_screen_capture: bool,
    #[serde(default)]
    pub start_list: StartList,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            keep_offline_copy: true,
            browser_integration_enabled: false,
            default_uri_match: crate::uri_match::UriMatchType::Host,
            passkey_verification: PasskeyVerification::Always,
            show_keyboard_shortcuts: true,
            close_after_copy: true,
            restore_recent_item: true,
            ssh_agent_enabled: false,
            ssh_agent_socket_path: default_ssh_agent_socket_path(),
            lock_on_system_lock: true,
            lock_after_idle_timeout: true,
            idle_lock_timeout_minutes: default_idle_lock_timeout_minutes(),
            show_website_icons: true,
            obscure_screen_capture: true,
            start_list: StartList::None,
        }
    }
}

/// Local browser registrations, independent of vault and daemon preferences.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct BrowserSetupPreferences {
    pub configured: bool,
    pub custom: Vec<crate::browser::install::BrowserRegistration>,
}

pub fn load_browser_setup() -> io::Result<BrowserSetupPreferences> {
    let path = config_path("browser-setup.json").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Configuration directory unavailable",
        )
    })?;
    match fs::read(path) {
        Ok(data) => {
            serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Default::default()),
        Err(error) => Err(error),
    }
}

pub fn save_browser_setup(preferences: &BrowserSetupPreferences) -> io::Result<()> {
    let data = serde_json::to_vec(preferences).map_err(io::Error::other)?;
    write_private("browser-setup.json", &data)
}

/// The vault window owns this preference independently of popup settings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListOrder {
    #[default]
    Name,
    Modified,
    Created,
}

pub fn load_window_order() -> ListOrder {
    config_path("window-order.json")
        .and_then(|path| fs::read(path).ok())
        .and_then(|data| serde_json::from_slice(&data).ok())
        .unwrap_or_default()
}

pub fn save_window_order(order: ListOrder) -> io::Result<()> {
    let data = serde_json::to_vec(&order)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write_private("window-order.json", &data)
}

fn default_true() -> bool {
    true
}

pub fn default_ssh_agent_socket_path() -> String {
    "$HOME/.bitwarden-ssh.sock".to_string()
}

pub fn default_idle_lock_timeout_minutes() -> u64 {
    60
}

pub fn expand_ssh_agent_socket_path(path: &str) -> Result<PathBuf, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("SSH agent path cannot be empty".into());
    }

    let expanded = if trimmed == "~" {
        home_dir().ok_or_else(|| "HOME is not set".to_string())?
    } else if let Some(rest) = trimmed.strip_prefix("~/") {
        home_dir()
            .ok_or_else(|| "HOME is not set".to_string())?
            .join(rest)
    } else if let Some(rest) = trimmed.strip_prefix("$HOME/") {
        home_dir()
            .ok_or_else(|| "HOME is not set".to_string())?
            .join(rest)
    } else if trimmed == "$HOME" {
        home_dir().ok_or_else(|| "HOME is not set".to_string())?
    } else {
        PathBuf::from(trimmed)
    };

    if !expanded.is_absolute() {
        return Err("SSH agent path must be absolute".into());
    }
    if expanded.is_dir() {
        return Err("SSH agent path must point to a socket file, not a directory".into());
    }
    Ok(expanded)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SavedSession {
    pub server_url: String,
    pub email: String,
    // Read old sessions only. Never serialize a plaintext token again.
    #[serde(default, skip_serializing)]
    pub refresh_token: String,
    #[serde(default)]
    pub encrypted_refresh_token: Option<String>,
    pub master_key_encrypted_user_key: String,
    pub salt: String,
    pub kdf: SavedKdf,
}

impl Drop for SavedSession {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.refresh_token);
    }
}

impl std::fmt::Debug for SavedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SavedSession")
            .field("server_url", &self.server_url)
            .field("email", &self.email)
            .field("refresh_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecentItem {
    pub id: String,
    pub saved_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SavedKdf {
    pub kdf_type: u32,
    pub iterations: u32,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
}

pub fn load_or_create_device_identifier() -> String {
    let Some(path) = device_identifier_path() else {
        return uuid::Uuid::new_v4().to_string();
    };

    if let Ok(value) = fs::read_to_string(&path) {
        let trimmed = value.trim();
        if uuid::Uuid::parse_str(trimmed).is_ok() {
            return trimmed.to_string();
        }
    }

    let identifier = uuid::Uuid::new_v4().to_string();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, format!("{identifier}\n"));
    identifier
}

fn device_identifier_path() -> Option<PathBuf> {
    config_path(DEVICE_ID_FILE)
}

pub fn load_saved_session() -> Option<SavedSession> {
    let path = config_path(SESSION_FILE)?;
    let data = Zeroizing::new(fs::read_to_string(path).ok()?);
    serde_json::from_str(&data).ok()
}

pub fn save_session(session: &SavedSession) -> io::Result<()> {
    if !session.refresh_token.is_empty() || session.encrypted_refresh_token.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Session token must be encrypted before saving",
        ));
    }
    let data = Zeroizing::new(
        serde_json::to_vec_pretty(session)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
    );
    write_private(SESSION_FILE, &data)
}

pub fn clear_saved_session() -> io::Result<()> {
    let cache_result = clear_vault_cache();
    let Some(path) = config_path(SESSION_FILE) else {
        return cache_result;
    };
    let session_result = match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    };
    session_result.and(cache_result)
}

pub fn load_vault_cache() -> Option<String> {
    fs::read_to_string(config_path(VAULT_CACHE_FILE)?).ok()
}

pub fn save_vault_cache(data: &[u8]) -> io::Result<()> {
    write_private(VAULT_CACHE_FILE, data)
}

pub fn clear_vault_cache() -> io::Result<()> {
    let Some(path) = config_path(VAULT_CACHE_FILE) else {
        return Ok(());
    };
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

pub fn load_settings() -> AppSettings {
    let Some(path) = config_path(SETTINGS_FILE) else {
        return AppSettings::default();
    };
    let Ok(data) = fs::read_to_string(path) else {
        return AppSettings::default();
    };
    serde_json::from_str(&data).unwrap_or_default()
}

pub fn save_settings(settings: &AppSettings) -> io::Result<()> {
    let path = config_path(SETTINGS_FILE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "config directory unavailable"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(settings)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(path, data)
}

pub fn load_recent_item() -> Option<RecentItem> {
    let path = config_path(RECENT_ITEM_FILE)?;
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

pub fn save_recent_item(id: &str) -> io::Result<()> {
    let data = serde_json::to_vec_pretty(&RecentItem {
        id: id.to_string(),
        saved_at_unix_ms: unix_millis_now(),
    })
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_private(RECENT_ITEM_FILE, &data)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ItemUse {
    id: String,
    used_at_unix_ms: u64,
}

/// Ids of recently opened items, most recent first. Only item ids are stored.
pub fn load_item_usage() -> Vec<String> {
    read_item_usage()
        .into_iter()
        .map(|entry| entry.id)
        .collect()
}

fn read_item_usage() -> Vec<ItemUse> {
    config_path(ITEM_USAGE_FILE)
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default()
}

pub fn record_item_use(id: &str) -> io::Result<()> {
    let mut entries = read_item_usage();
    entries.retain(|entry| entry.id != id);
    entries.insert(
        0,
        ItemUse {
            id: id.to_string(),
            used_at_unix_ms: unix_millis_now(),
        },
    );
    entries.truncate(ITEM_USAGE_LIMIT);
    let data = serde_json::to_vec_pretty(&entries)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_private(ITEM_USAGE_FILE, &data)
}

pub fn clear_item_usage() -> io::Result<()> {
    let Some(path) = config_path(ITEM_USAGE_FILE) else {
        return Ok(());
    };
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Writes a config file readable only by the current user.
pub(crate) fn write_private(file_name: &str, data: &[u8]) -> io::Result<()> {
    let path = config_path(file_name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "config directory unavailable"))?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("config directory unavailable"))?;
    fs::create_dir_all(parent)?;
    // A private, newly created inode avoids following symlinks or modifying hard links.
    // Rename preserves the previous session if serialization or writing fails.
    let temporary = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let mut file = options.open(&temporary)?;
        std::io::Write::write_all(&mut file, data)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub fn clear_recent_item() -> io::Result<()> {
    let Some(path) = config_path(RECENT_ITEM_FILE) else {
        return Ok(());
    };
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn recent_item_is_fresh(item: &RecentItem, ttl: std::time::Duration) -> bool {
    let now = unix_millis_now();
    let Some(age) = now.checked_sub(item.saved_at_unix_ms) else {
        return false;
    };
    age <= ttl.as_millis().min(u128::from(u64::MAX)) as u64
}

fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub(crate) fn config_path(file_name: &str) -> Option<PathBuf> {
    Some(config_base()?.join(APP_DIR).join(file_name))
}

fn config_base() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
}

/// `$XDG_CACHE_HOME/boltwarden`, or `~/.cache/boltwarden`.
pub fn cache_dir() -> Option<PathBuf> {
    Some(cache_base()?.join(APP_DIR))
}

fn cache_base() -> Option<PathBuf> {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
}

/// Moves the config (saved session, settings, device id) and cache directories from
/// the old bw-quick-access name, once. Nothing moves when the new directory exists.
pub fn migrate_legacy_dirs() {
    for base in [config_base(), cache_base()].into_iter().flatten() {
        let _ = migrate_dir(&base.join(LEGACY_APP_DIR), &base.join(APP_DIR));
    }
}

fn migrate_dir(old: &std::path::Path, new: &std::path::Path) -> io::Result<()> {
    if !old.is_dir() || new.exists() {
        return Ok(());
    }
    fs::rename(old, new)
}

#[cfg(test)]
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn with_test_config(test: impl FnOnce(&std::path::Path)) {
    let _guard = ENV_LOCK.lock().unwrap();
    struct Restore {
        previous: Option<std::ffi::OsString>,
        dir: PathBuf,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                    None => std::env::remove_var("XDG_CONFIG_HOME"),
                }
            }
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
    let restore = Restore {
        previous: std::env::var_os("XDG_CONFIG_HOME"),
        dir: std::env::temp_dir().join(format!("boltwarden-offline-test-{}", uuid::Uuid::new_v4())),
    };
    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", &restore.dir);
    }
    test(&restore.dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passkey_verification_defaults_safely_and_persists_all_choices() {
        let migrated: AppSettings =
            serde_json::from_str(r#"{"browser_integration_enabled":true}"#).unwrap();
        assert_eq!(migrated.passkey_verification, PasskeyVerification::Always);
        assert_eq!(PasskeyVerification::Always.label(), "Always ask");
        assert_eq!(
            PasskeyVerification::WhenRequired.label(),
            "Only when required"
        );
        assert_eq!(PasskeyVerification::VaultUnlock.label(), "Use vault unlock");
        with_test_config(|_| {
            for (choice, serialized) in [
                (PasskeyVerification::WhenRequired, "when_required"),
                (PasskeyVerification::VaultUnlock, "vault_unlock"),
                (PasskeyVerification::Always, "always"),
            ] {
                let settings = AppSettings {
                    passkey_verification: choice,
                    ..Default::default()
                };
                save_settings(&settings).unwrap();
                assert_eq!(load_settings().passkey_verification, choice);
                let raw: serde_json::Value =
                    serde_json::from_slice(&fs::read(config_path(SETTINGS_FILE).unwrap()).unwrap())
                        .unwrap();
                assert_eq!(raw["passkey_verification"], serialized);
            }
        });
    }

    #[test]
    fn offline_cache_storage_is_private_and_forgotten_with_session() {
        with_test_config(|root| {
            assert!(load_settings().keep_offline_copy);
            assert!(
                serde_json::from_str::<AppSettings>("{}")
                    .unwrap()
                    .keep_offline_copy
            );
            assert!(load_vault_cache().is_none());
            save_vault_cache(b"encrypted").unwrap();
            assert_eq!(load_vault_cache().as_deref(), Some("encrypted"));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(root.join(APP_DIR).join(VAULT_CACHE_FILE))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
            clear_saved_session().unwrap();
            assert!(load_vault_cache().is_none());
            clear_vault_cache().unwrap();
        });
    }

    #[test]
    fn migrates_the_legacy_directory_once() {
        let temp =
            std::env::temp_dir().join(format!("boltwarden-migrate-{}", uuid::Uuid::new_v4()));
        let (old, new) = (temp.join(LEGACY_APP_DIR), temp.join(APP_DIR));
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join(SESSION_FILE), "saved").unwrap();

        migrate_dir(&old, &new).unwrap();
        assert_eq!(fs::read_to_string(new.join(SESSION_FILE)).unwrap(), "saved");
        assert!(!old.exists());

        // A newer directory is never overwritten by an old one.
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join(SESSION_FILE), "stale").unwrap();
        migrate_dir(&old, &new).unwrap();
        assert_eq!(fs::read_to_string(new.join(SESSION_FILE)).unwrap(), "saved");
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn reuses_existing_device_identifier_from_xdg_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp =
            std::env::temp_dir().join(format!("boltwarden-config-test-{}", uuid::Uuid::new_v4()));
        let config_dir = temp.join("config");
        let app_dir = config_dir.join(APP_DIR);
        fs::create_dir_all(&app_dir).unwrap();
        let expected = uuid::Uuid::new_v4().to_string();
        fs::write(app_dir.join(DEVICE_ID_FILE), format!("{expected}\n")).unwrap();
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        }

        let actual = load_or_create_device_identifier();

        restore_var("XDG_CONFIG_HOME", previous_config_home);
        let _ = fs::remove_dir_all(temp);
        assert_eq!(actual, expected);
    }

    #[test]
    fn creates_device_identifier_in_xdg_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp =
            std::env::temp_dir().join(format!("boltwarden-config-test-{}", uuid::Uuid::new_v4()));
        let config_dir = temp.join("config");
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        }

        let first = load_or_create_device_identifier();
        let second = load_or_create_device_identifier();

        restore_var("XDG_CONFIG_HOME", previous_config_home);
        let _ = fs::remove_dir_all(temp);
        assert!(uuid::Uuid::parse_str(&first).is_ok());
        assert_eq!(first, second);
    }

    #[test]
    fn saves_and_loads_session_from_xdg_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp =
            std::env::temp_dir().join(format!("boltwarden-config-test-{}", uuid::Uuid::new_v4()));
        let config_dir = temp.join("config");
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        }

        let expected = SavedSession {
            server_url: "https://vault.example.test".into(),
            email: "me@example.test".into(),
            refresh_token: String::new(),
            encrypted_refresh_token: Some("2.encrypted-fixture".into()),
            master_key_encrypted_user_key: "2.iv|data|mac".into(),
            salt: "custom-salt".into(),
            kdf: SavedKdf {
                kdf_type: 0,
                iterations: 600_000,
                memory: None,
                parallelism: None,
            },
        };

        save_session(&expected).unwrap();
        let actual = load_saved_session().unwrap();

        restore_var("XDG_CONFIG_HOME", previous_config_home);
        let _ = fs::remove_dir_all(temp);
        assert_eq!(actual.server_url, expected.server_url);
        assert_eq!(actual.email, expected.email);
        assert_eq!(
            actual.encrypted_refresh_token,
            expected.encrypted_refresh_token
        );
        assert!(actual.refresh_token.is_empty());
        assert_eq!(
            actual.master_key_encrypted_user_key,
            expected.master_key_encrypted_user_key
        );
        assert_eq!(actual.salt, expected.salt);
        assert_eq!(actual.kdf, expected.kdf);
    }

    #[test]
    fn clears_saved_session_from_xdg_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp =
            std::env::temp_dir().join(format!("boltwarden-config-test-{}", uuid::Uuid::new_v4()));
        let config_dir = temp.join("config");
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        }

        let session = SavedSession {
            server_url: "https://vault.example.test".into(),
            email: "me@example.test".into(),
            refresh_token: String::new(),
            encrypted_refresh_token: Some("2.encrypted-fixture".into()),
            master_key_encrypted_user_key: "2.iv|data|mac".into(),
            salt: "custom-salt".into(),
            kdf: SavedKdf {
                kdf_type: 0,
                iterations: 600_000,
                memory: None,
                parallelism: None,
            },
        };

        save_session(&session).unwrap();
        clear_saved_session().unwrap();
        assert!(load_saved_session().is_none());

        restore_var("XDG_CONFIG_HOME", previous_config_home);
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn missing_settings_defaults_enabled_features() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp =
            std::env::temp_dir().join(format!("boltwarden-config-test-{}", uuid::Uuid::new_v4()));
        let config_dir = temp.join("config");
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        }

        let actual = load_settings();

        restore_var("XDG_CONFIG_HOME", previous_config_home);
        let _ = fs::remove_dir_all(temp);
        assert!(actual.show_keyboard_shortcuts);
        assert!(actual.close_after_copy);
        assert!(actual.restore_recent_item);
        assert!(!actual.ssh_agent_enabled);
        assert_eq!(
            actual.ssh_agent_socket_path,
            default_ssh_agent_socket_path()
        );
        assert!(actual.obscure_screen_capture);
        assert!(actual.lock_on_system_lock);
        assert!(actual.lock_after_idle_timeout);
        assert_eq!(actual.idle_lock_timeout_minutes, 60);
    }

    #[test]
    fn saves_and_loads_app_settings() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp =
            std::env::temp_dir().join(format!("boltwarden-config-test-{}", uuid::Uuid::new_v4()));
        let config_dir = temp.join("config");
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        }

        save_settings(&AppSettings {
            keep_offline_copy: true,
            show_keyboard_shortcuts: false,
            close_after_copy: false,
            restore_recent_item: false,
            ssh_agent_enabled: true,
            ssh_agent_socket_path: "$HOME/custom-agent.sock".into(),
            lock_on_system_lock: false,
            lock_after_idle_timeout: false,
            idle_lock_timeout_minutes: 15,
            show_website_icons: true,
            obscure_screen_capture: false,
            start_list: StartList::None,
            ..Default::default()
        })
        .unwrap();
        let actual = load_settings();
        assert!(!actual.obscure_screen_capture);
        assert!(!actual.show_keyboard_shortcuts);
        assert!(!actual.close_after_copy);
        assert!(!actual.restore_recent_item);
        assert!(actual.ssh_agent_enabled);
        assert_eq!(actual.ssh_agent_socket_path, "$HOME/custom-agent.sock");
        assert!(!actual.lock_on_system_lock);
        assert!(!actual.lock_after_idle_timeout);
        assert_eq!(actual.idle_lock_timeout_minutes, 15);

        save_settings(&AppSettings {
            keep_offline_copy: true,
            show_keyboard_shortcuts: true,
            close_after_copy: true,
            restore_recent_item: true,
            ssh_agent_enabled: false,
            ssh_agent_socket_path: "$HOME/.bitwarden-ssh.sock".into(),
            lock_on_system_lock: true,
            lock_after_idle_timeout: true,
            idle_lock_timeout_minutes: 60,
            show_website_icons: true,
            obscure_screen_capture: true,
            start_list: StartList::None,
            ..Default::default()
        })
        .unwrap();
        let actual = load_settings();
        assert!(actual.show_keyboard_shortcuts);
        assert!(actual.close_after_copy);
        assert!(actual.restore_recent_item);
        assert!(!actual.ssh_agent_enabled);
        assert_eq!(
            actual.ssh_agent_socket_path,
            default_ssh_agent_socket_path()
        );
        assert!(actual.obscure_screen_capture);
        assert!(actual.lock_on_system_lock);
        assert!(actual.lock_after_idle_timeout);
        assert_eq!(actual.idle_lock_timeout_minutes, 60);

        restore_var("XDG_CONFIG_HOME", previous_config_home);
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn window_sort_survives_reload_and_popup_settings_updates() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp =
            std::env::temp_dir().join(format!("boltwarden-order-test-{}", uuid::Uuid::new_v4()));
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &temp);
        }
        assert_eq!(load_window_order(), ListOrder::Name);
        for order in [ListOrder::Modified, ListOrder::Created, ListOrder::Name] {
            save_window_order(order).unwrap();
            save_settings(&AppSettings::default()).unwrap();
            assert_eq!(load_window_order(), order);
        }
        fs::write(temp.join(APP_DIR).join("window-order.json"), "invalid").unwrap();
        assert_eq!(load_window_order(), ListOrder::Name);
        restore_var("XDG_CONFIG_HOME", previous);
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn loading_old_settings_file_defaults_new_settings_to_enabled() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp =
            std::env::temp_dir().join(format!("boltwarden-config-test-{}", uuid::Uuid::new_v4()));
        let config_dir = temp.join("config");
        let app_dir = config_dir.join(APP_DIR);
        fs::create_dir_all(&app_dir).unwrap();
        fs::write(
            app_dir.join(SETTINGS_FILE),
            r#"{
  "show_keyboard_shortcuts": false
}"#,
        )
        .unwrap();
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        }

        let actual = load_settings();

        restore_var("XDG_CONFIG_HOME", previous_config_home);
        let _ = fs::remove_dir_all(temp);
        assert!(!actual.show_keyboard_shortcuts);
        assert!(actual.close_after_copy);
        assert!(actual.restore_recent_item);
        assert!(!actual.ssh_agent_enabled);
        assert_eq!(
            actual.ssh_agent_socket_path,
            default_ssh_agent_socket_path()
        );
        assert!(actual.obscure_screen_capture);
        assert!(actual.lock_on_system_lock);
        assert!(actual.lock_after_idle_timeout);
        assert_eq!(actual.idle_lock_timeout_minutes, 60);
    }

    #[test]
    fn expands_and_validates_ssh_agent_socket_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", "/tmp/boltwarden-home");
        }

        assert_eq!(
            expand_ssh_agent_socket_path("$HOME/.bitwarden-ssh.sock").unwrap(),
            PathBuf::from("/tmp/boltwarden-home/.bitwarden-ssh.sock")
        );
        assert_eq!(
            expand_ssh_agent_socket_path("~/.bitwarden-ssh.sock").unwrap(),
            PathBuf::from("/tmp/boltwarden-home/.bitwarden-ssh.sock")
        );
        assert!(expand_ssh_agent_socket_path("").is_err());
        assert!(expand_ssh_agent_socket_path("relative.sock").is_err());
        assert!(expand_ssh_agent_socket_path("/tmp").is_err());

        restore_var("HOME", previous_home);
    }

    #[test]
    fn records_recent_item_usage_newest_first_without_duplicates() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp =
            std::env::temp_dir().join(format!("boltwarden-config-test-{}", uuid::Uuid::new_v4()));
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", temp.join("config"));
        }

        assert!(load_item_usage().is_empty());
        for id in ["a", "b", "a", "c"] {
            record_item_use(id).unwrap();
        }
        assert_eq!(load_item_usage(), ["c", "a", "b"]);
        for idx in 0..(ITEM_USAGE_LIMIT + 5) {
            record_item_use(&format!("item-{idx}")).unwrap();
        }
        assert_eq!(load_item_usage().len(), ITEM_USAGE_LIMIT);

        clear_item_usage().unwrap();
        assert!(load_item_usage().is_empty());

        restore_var("XDG_CONFIG_HOME", previous_config_home);
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn saves_loads_and_clears_recent_item() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp =
            std::env::temp_dir().join(format!("boltwarden-config-test-{}", uuid::Uuid::new_v4()));
        let config_dir = temp.join("config");
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        }

        assert!(load_recent_item().is_none());
        save_recent_item("item-123").unwrap();
        let actual = load_recent_item().unwrap();
        assert_eq!(actual.id, "item-123");
        assert!(recent_item_is_fresh(
            &actual,
            std::time::Duration::from_secs(30)
        ));

        clear_recent_item().unwrap();
        assert!(load_recent_item().is_none());

        restore_var("XDG_CONFIG_HOME", previous_config_home);
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn recent_item_freshness_respects_ttl() {
        let fresh = RecentItem {
            id: "item-123".into(),
            saved_at_unix_ms: unix_millis_now().saturating_sub(10_000),
        };
        let stale = RecentItem {
            id: "item-123".into(),
            saved_at_unix_ms: unix_millis_now().saturating_sub(31_000),
        };
        let future = RecentItem {
            id: "item-123".into(),
            saved_at_unix_ms: unix_millis_now().saturating_add(1_000),
        };

        assert!(recent_item_is_fresh(
            &fresh,
            std::time::Duration::from_secs(30)
        ));
        assert!(!recent_item_is_fresh(
            &stale,
            std::time::Duration::from_secs(30)
        ));
        assert!(!recent_item_is_fresh(
            &future,
            std::time::Duration::from_secs(30)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn private_writes_replace_links_without_touching_the_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let _guard = ENV_LOCK.lock().unwrap();
        let temp =
            std::env::temp_dir().join(format!("boltwarden-private-{}", uuid::Uuid::new_v4()));
        let app_dir = temp.join(APP_DIR);
        fs::create_dir_all(&app_dir).unwrap();
        let target = temp.join("unrelated");
        fs::write(&target, b"unchanged").unwrap();
        let path = app_dir.join(SESSION_FILE);
        symlink(&target, &path).unwrap();
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &temp);
        }
        write_private(SESSION_FILE, b"private").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
        assert_eq!(fs::read(&path).unwrap(), b"private");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_private(SESSION_FILE, b"replacement").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        restore_var("XDG_CONFIG_HOME", previous);
        fs::remove_dir_all(temp).unwrap();
    }

    fn restore_var(key: &str, value: Option<std::ffi::OsString>) {
        match value {
            Some(value) => unsafe {
                std::env::set_var(key, value);
            },
            None => unsafe {
                std::env::remove_var(key);
            },
        }
    }
}
