use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

const APP_DIR: &str = "bw-quick-access";
const DEVICE_ID_FILE: &str = "device-id";
const SESSION_FILE: &str = "session.json";

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
