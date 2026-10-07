//! Start at login through a per-user LaunchAgent, which works without a signed app. The
//! agent starts the daemon in the menu bar; quitting stops it until the next login.
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const LABEL: &str = "nl.mvl.boltwarden";

fn agent_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn plist(executable: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{}</string>
		<string>--daemon</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
"#,
        escape(&executable.display().to_string())
    )
}

/// Our agents carry our label; any other file at the path is left alone.
fn is_ours(contents: &str) -> bool {
    contents.contains(&format!("<string>{LABEL}</string>"))
}

/// Creates, updates, or removes the agent so it matches `enabled` and starts the running
/// executable. A moved app rewrites the path on its next start.
pub fn apply(enabled: bool) -> io::Result<()> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .ok_or_else(|| io::Error::other("HOME must be an absolute path"))?;
    apply_at(&agent_path(&home), &std::env::current_exe()?, enabled)
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
            format!("{} belongs to another app", path.display()),
        ));
    }
    if !enabled {
        if existing.is_some() {
            fs::remove_file(path)?;
        }
        return Ok(());
    }
    let wanted = plist(executable);
    if existing.as_deref() == Some(wanted.as_str()) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("plist.tmp");
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
    fn enabling_writes_an_agent_for_the_executable_and_disabling_removes_it() {
        let home = scratch();
        let path = agent_path(&home);
        let executable = Path::new("/Applications/Boltwarden & Co.app/Contents/MacOS/boltwarden");
        apply_at(&path, executable, true).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("<string>nl.mvl.boltwarden</string>"));
        assert!(contents.contains(
            "<string>/Applications/Boltwarden &amp; Co.app/Contents/MacOS/boltwarden</string>"
        ));
        assert!(contents.contains("<string>--daemon</string>"));
        assert!(contents.contains("<key>RunAtLoad</key>\n\t<true/>"));

        let moved = Path::new("/Users/me/Applications/Boltwarden.app/Contents/MacOS/boltwarden");
        apply_at(&path, moved, true).unwrap();
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains(&moved.display().to_string())
        );

        apply_at(&path, moved, false).unwrap();
        assert!(!path.exists());
        apply_at(&path, moved, false).unwrap();
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn another_apps_file_is_never_replaced_or_removed() {
        let home = scratch();
        let path = agent_path(&home);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "<plist><dict><key>Label</key><string>other</string></dict></plist>",
        )
        .unwrap();
        let executable = Path::new("/Applications/Boltwarden.app/Contents/MacOS/boltwarden");
        assert!(apply_at(&path, executable, true).is_err());
        assert!(apply_at(&path, executable, false).is_err());
        assert!(fs::read_to_string(&path).unwrap().contains("other"));
        fs::remove_dir_all(home).unwrap();
    }
}
