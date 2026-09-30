use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

const APP_DIR: &str = "bw-quick-access";
const DEVICE_ID_FILE: &str = "device-id";
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AppSettings {
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
    #[serde(default)]
    pub start_list: StartList,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            show_keyboard_shortcuts: true,
            close_after_copy: true,
            restore_recent_item: true,
            ssh_agent_enabled: false,
            ssh_agent_socket_path: default_ssh_agent_socket_path(),
            lock_on_system_lock: true,
            lock_after_idle_timeout: true,
            idle_lock_timeout_minutes: default_idle_lock_timeout_minutes(),
            show_website_icons: true,
            start_list: StartList::None,
        }
    }
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SavedSession {
    pub server_url: String,
    pub email: String,
    pub refresh_token: String,
    pub master_key_encrypted_user_key: String,
    pub salt: String,
    pub kdf: SavedKdf,
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
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

pub fn save_session(session: &SavedSession) -> io::Result<()> {
    let path = config_path(SESSION_FILE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "config directory unavailable"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(session)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    #[cfg(unix)]
    {
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(true).write(true).mode(0o600);
        std::io::Write::write_all(&mut options.open(path)?, &data)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
    }
    Ok(())
}

pub fn clear_saved_session() -> io::Result<()> {
    let Some(path) = config_path(SESSION_FILE) else {
        return Ok(());
    };
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
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
    let path = config_path(RECENT_ITEM_FILE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "config directory unavailable"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(&RecentItem {
        id: id.to_string(),
        saved_at_unix_ms: unix_millis_now(),
    })
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    #[cfg(unix)]
    {
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(true).write(true).mode(0o600);
        std::io::Write::write_all(&mut options.open(path)?, &data)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ItemUse {
    id: String,
    used_at_unix_ms: u64,
}

/// Ids of recently opened items, most recent first. Only item ids are stored.
pub fn load_item_usage() -> Vec<String> {
    read_item_usage().into_iter().map(|entry| entry.id).collect()
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
fn write_private(file_name: &str, data: &[u8]) -> io::Result<()> {
    let path = config_path(file_name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "config directory unavailable"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(true).write(true).mode(0o600);
        std::io::Write::write_all(&mut options.open(path)?, data)
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)
    }
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

fn config_path(file_name: &str) -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join(APP_DIR).join(file_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn reuses_existing_device_identifier_from_xdg_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp = std::env::temp_dir().join(format!(
            "bw-quick-access-config-test-{}",
            uuid::Uuid::new_v4()
        ));
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
        let temp = std::env::temp_dir().join(format!(
            "bw-quick-access-config-test-{}",
            uuid::Uuid::new_v4()
        ));
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
        let temp = std::env::temp_dir().join(format!(
            "bw-quick-access-config-test-{}",
            uuid::Uuid::new_v4()
        ));
        let config_dir = temp.join("config");
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        }

        let expected = SavedSession {
            server_url: "https://vault.example.test".into(),
            email: "me@example.test".into(),
            refresh_token: "refresh".into(),
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
        assert_eq!(actual.refresh_token, expected.refresh_token);
        assert_eq!(actual.master_key_encrypted_user_key, expected.master_key_encrypted_user_key);
        assert_eq!(actual.salt, expected.salt);
        assert_eq!(actual.kdf, expected.kdf);
    }

    #[test]
    fn clears_saved_session_from_xdg_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp = std::env::temp_dir().join(format!(
            "bw-quick-access-config-test-{}",
            uuid::Uuid::new_v4()
        ));
        let config_dir = temp.join("config");
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        }

        let session = SavedSession {
            server_url: "https://vault.example.test".into(),
            email: "me@example.test".into(),
            refresh_token: "refresh".into(),
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
        let temp = std::env::temp_dir().join(format!(
            "bw-quick-access-config-test-{}",
            uuid::Uuid::new_v4()
        ));
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
        assert_eq!(actual.ssh_agent_socket_path, default_ssh_agent_socket_path());
        assert!(actual.lock_on_system_lock);
        assert!(actual.lock_after_idle_timeout);
        assert_eq!(actual.idle_lock_timeout_minutes, 60);
    }

    #[test]
    fn saves_and_loads_app_settings() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp = std::env::temp_dir().join(format!(
            "bw-quick-access-config-test-{}",
            uuid::Uuid::new_v4()
        ));
        let config_dir = temp.join("config");
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        }

        save_settings(&AppSettings {
            show_keyboard_shortcuts: false,
            close_after_copy: false,
            restore_recent_item: false,
            ssh_agent_enabled: true,
            ssh_agent_socket_path: "$HOME/custom-agent.sock".into(),
            lock_on_system_lock: false,
            lock_after_idle_timeout: false,
            idle_lock_timeout_minutes: 15,
            show_website_icons: true,
            start_list: StartList::None,
        })
        .unwrap();
        let actual = load_settings();
        assert!(!actual.show_keyboard_shortcuts);
        assert!(!actual.close_after_copy);
        assert!(!actual.restore_recent_item);
        assert!(actual.ssh_agent_enabled);
        assert_eq!(actual.ssh_agent_socket_path, "$HOME/custom-agent.sock");
        assert!(!actual.lock_on_system_lock);
        assert!(!actual.lock_after_idle_timeout);
        assert_eq!(actual.idle_lock_timeout_minutes, 15);

        save_settings(&AppSettings {
            show_keyboard_shortcuts: true,
            close_after_copy: true,
            restore_recent_item: true,
            ssh_agent_enabled: false,
            ssh_agent_socket_path: "$HOME/.bitwarden-ssh.sock".into(),
            lock_on_system_lock: true,
            lock_after_idle_timeout: true,
            idle_lock_timeout_minutes: 60,
            show_website_icons: true,
            start_list: StartList::None,
        })
        .unwrap();
        let actual = load_settings();
        assert!(actual.show_keyboard_shortcuts);
        assert!(actual.close_after_copy);
        assert!(actual.restore_recent_item);
        assert!(!actual.ssh_agent_enabled);
        assert_eq!(actual.ssh_agent_socket_path, default_ssh_agent_socket_path());
        assert!(actual.lock_on_system_lock);
        assert!(actual.lock_after_idle_timeout);
        assert_eq!(actual.idle_lock_timeout_minutes, 60);

        restore_var("XDG_CONFIG_HOME", previous_config_home);
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn loading_old_settings_file_defaults_new_settings_to_enabled() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp = std::env::temp_dir().join(format!(
            "bw-quick-access-config-test-{}",
            uuid::Uuid::new_v4()
        ));
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
        assert_eq!(actual.ssh_agent_socket_path, default_ssh_agent_socket_path());
        assert!(actual.lock_on_system_lock);
        assert!(actual.lock_after_idle_timeout);
        assert_eq!(actual.idle_lock_timeout_minutes, 60);
    }

    #[test]
    fn expands_and_validates_ssh_agent_socket_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", "/tmp/bwqa-home");
        }

        assert_eq!(
            expand_ssh_agent_socket_path("$HOME/.bitwarden-ssh.sock").unwrap(),
            PathBuf::from("/tmp/bwqa-home/.bitwarden-ssh.sock")
        );
        assert_eq!(
            expand_ssh_agent_socket_path("~/.bitwarden-ssh.sock").unwrap(),
            PathBuf::from("/tmp/bwqa-home/.bitwarden-ssh.sock")
        );
        assert!(expand_ssh_agent_socket_path("").is_err());
        assert!(expand_ssh_agent_socket_path("relative.sock").is_err());
        assert!(expand_ssh_agent_socket_path("/tmp").is_err());

        restore_var("HOME", previous_home);
    }

    #[test]
    fn records_recent_item_usage_newest_first_without_duplicates() {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp = std::env::temp_dir().join(format!(
            "bw-quick-access-config-test-{}",
            uuid::Uuid::new_v4()
        ));
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
        let temp = std::env::temp_dir().join(format!(
            "bw-quick-access-config-test-{}",
            uuid::Uuid::new_v4()
        ));
        let config_dir = temp.join("config");
        let previous_config_home = std::env::var_os("XDG_CONFIG_HOME");

        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        }

        assert!(load_recent_item().is_none());
        save_recent_item("item-123").unwrap();
        let actual = load_recent_item().unwrap();
        assert_eq!(actual.id, "item-123");
        assert!(recent_item_is_fresh(&actual, std::time::Duration::from_secs(30)));

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
