//! Start at login through an XDG autostart entry, which desktop environments and
//! systemd-managed sessions (such as uwsm) run at graphical login. The entry starts the
//! daemon in the background; quitting stops it until the next login.
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const FILE_NAME: &str = "boltwarden.desktop";
/// Marks entries we wrote; any other file at the path is left alone.
const MARKER: &str = "X-Boltwarden-Autostart=true";

fn entry_path(config_home: &Path) -> PathBuf {
    config_home.join("autostart").join(FILE_NAME)
}

/// `$XDG_CONFIG_HOME`, or `~/.config` when it is unset or relative, as the spec requires.
fn config_home() -> io::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
    {
        return Ok(dir);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .map(|home| home.join(".config"))
        .ok_or_else(|| io::Error::other("HOME must be an absolute path"))
}

/// Escapes a desktop entry string value, where a backslash starts an escape sequence.
fn escape_value(text: &str) -> String {
    text.replace('\\', "\\\\")
}

/// Quotes the executable for the Exec key: reserved characters inside double quotes get a
/// backslash, `%` is doubled because it starts a field code, and the result is then
/// escaped as a string value.
fn exec_argument(executable: &str) -> String {
    let mut quoted = String::from("\"");
    for character in executable.chars() {
        match character {
            '"' | '`' | '$' | '\\' => {
                quoted.push('\\');
                quoted.push(character);
            }
            '%' => quoted.push_str("%%"),
            _ => quoted.push(character),
        }
    }
    quoted.push('"');
    escape_value(&quoted)
}

fn entry(executable: &Path) -> io::Result<String> {
    let executable = executable
        .to_str()
        .filter(|path| !path.contains(['\n', '\r']))
        .ok_or_else(|| {
            io::Error::other("the executable path cannot be written to an autostart entry")
        })?;
    Ok(format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Boltwarden\n\
         Comment=Start Boltwarden in the background\n\
         Exec={} --daemon\n\
         TryExec={}\n\
         Icon=boltwarden\n\
         Terminal=false\n\
         NoDisplay=true\n\
         {MARKER}\n",
        exec_argument(executable),
        escape_value(executable),
    ))
}

fn is_ours(contents: &str) -> bool {
    contents.lines().any(|line| line.trim() == MARKER)
}

/// The running executable. After a package upgrade replaces the binary, Linux reports the
/// old path with a " (deleted)" suffix; the new binary sits at the same path.
fn executable() -> io::Result<PathBuf> {
    let path = std::env::current_exe()?;
    Ok(
        match path
            .to_str()
            .and_then(|text| text.strip_suffix(" (deleted)"))
        {
            Some(original) => PathBuf::from(original),
            None => path,
        },
    )
}

/// Creates, updates, or removes the entry so it matches `enabled` and starts the running
/// executable. A moved binary rewrites the path on its next start.
pub fn apply(enabled: bool) -> io::Result<()> {
    apply_at(&entry_path(&config_home()?), &executable()?, enabled)
}

fn apply_at(path: &Path, executable: &Path, enabled: bool) -> io::Result<()> {
    let existing = match fs::read_to_string(path) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if existing
        .as_deref()
        .is_some_and(|contents| !is_ours(contents))
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} was not created by Boltwarden", path.display()),
        ));
    }
    if !enabled {
        if existing.is_some() {
            fs::remove_file(path)?;
        }
        return Ok(());
    }
    let wanted = entry(executable)?;
    if existing.as_deref() == Some(wanted.as_str()) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("desktop.tmp");
    fs::write(&temporary, wanted)?;
    fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = crate::test_temp_dir().join(format!("boltwarden-login-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn enabling_writes_an_entry_for_the_executable_and_disabling_removes_it() {
        let config = scratch();
        let path = entry_path(&config);
        apply_at(&path, Path::new("/usr/bin/boltwarden"), true).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("[Desktop Entry]\n"));
        assert!(contents.contains("\nExec=\"/usr/bin/boltwarden\" --daemon\n"));
        assert!(contents.contains("\nTryExec=/usr/bin/boltwarden\n"));
        assert!(is_ours(&contents));

        let moved = Path::new("/opt/boltwarden/bin/boltwarden");
        apply_at(&path, moved, true).unwrap();
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("Exec=\"/opt/boltwarden/bin/boltwarden\" --daemon")
        );

        apply_at(&path, moved, false).unwrap();
        assert!(!path.exists());
        apply_at(&path, moved, false).unwrap();
        fs::remove_dir_all(config).unwrap();
    }

    #[test]
    fn exec_quotes_reserved_characters_and_field_codes() {
        assert_eq!(
            exec_argument("/home/me/Bolt $dir/100%/a\"b\\c"),
            "\"/home/me/Bolt \\\\$dir/100%%/a\\\\\"b\\\\\\\\c\""
        );
        assert!(entry(Path::new("/tmp/bolt\nwarden")).is_err());
    }

    #[test]
    fn another_apps_file_is_never_replaced_or_removed() {
        let config = scratch();
        let path = entry_path(&config);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "[Desktop Entry]\nExec=boltwarden --daemon\n").unwrap();
        let executable = Path::new("/usr/bin/boltwarden");
        assert!(apply_at(&path, executable, true).is_err());
        assert!(apply_at(&path, executable, false).is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "[Desktop Entry]\nExec=boltwarden --daemon\n"
        );
        fs::remove_dir_all(config).unwrap();
    }
}
