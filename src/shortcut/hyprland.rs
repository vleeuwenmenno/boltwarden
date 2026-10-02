use super::Shortcut;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
const MARKER: &str = "Boltwarden quick access - managed file; edit the shortcut in Boltwarden";
#[derive(Clone, Copy, Debug, PartialEq)]
enum Format {
    Lua,
    Conf,
}
struct Paths {
    main: PathBuf,
    owned: PathBuf,
    format: Format,
}
pub struct Runtime;
impl Runtime {
    pub fn new(_: mpsc::Sender<()>) -> Self {
        Self
    }
    pub fn supported(&self) -> bool {
        std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_some() && paths().is_ok()
    }
    pub fn unavailable_message(&self) -> String {
        "Automatic setup requires a running Hyprland session and its standard user config. Use Copy binding for manual setup.".into()
    }
    pub fn active(&self, selected: &Shortcut) -> Result<bool, String> {
        let command = shell_command(&std::env::current_exe().map_err(|e| e.to_string())?)?;
        let bindings: serde_json::Value =
            serde_json::from_str(&run(&["-j", "binds"])?).map_err(|e| e.to_string())?;
        let list = bindings
            .as_array()
            .ok_or("Hyprland returned an invalid bindings list")?;
        let matching: Vec<_> = list
            .iter()
            .filter(|binding| matches_key(binding, selected))
            .collect();
        Ok(matching.len() == 1 && owns_command(matching[0], &command))
    }
    pub fn apply(
        &mut self,
        previous: Option<&Shortcut>,
        next: Option<&Shortcut>,
    ) -> Result<(), String> {
        if !self.supported() {
            return Err(self.unavailable_message());
        }
        let paths = paths()?;
        // Refuse custom --config sessions rather than editing an unused default file.
        let instances: serde_json::Value =
            serde_json::from_str(&run(&["-j", "instances"])?).map_err(|e| e.to_string())?;
        let signature = std::env::var("HYPRLAND_INSTANCE_SIGNATURE").unwrap_or_default();
        if let Some(instance) = instances.as_array().and_then(|list| {
            list.iter()
                .find(|entry| entry["instance"].as_str() == Some(&signature))
        }) {
            if let Some(pid) = instance["pid"].as_u64() {
                let bytes = fs::read(format!("/proc/{pid}/cmdline")).map_err(|e| e.to_string())?;
                if bytes
                    .split(|byte| *byte == 0)
                    .any(|arg| arg == b"-c" || arg.starts_with(b"--config"))
                {
                    return Err(
                        "Hyprland uses a custom config path. Use Copy binding for manual setup."
                            .into(),
                    );
                }
            }
        }
        let errors = run(&["configerrors"])?;
        if !errors.trim().is_empty() {
            return Err(
                "Fix existing Hyprland configuration errors before applying a shortcut".into(),
            );
        }
        let executable = std::env::current_exe().map_err(|e| e.to_string())?;
        let command = shell_command(&executable)?;
        let binds: serde_json::Value =
            serde_json::from_str(&run(&["-j", "binds"])?).map_err(|e| e.to_string())?;
        let owned = read_optional(&paths.owned)?;
        if let Some(next) = next {
            let already_owned =
                owned.as_deref() == Some(render(paths.format, Some(next), &command).as_str());
            check_conflict(&binds, next, &command, already_owned)?;
        }
        if let Some(existing) = &owned {
            if existing != &render(paths.format, previous, &command)
                && existing != &render(paths.format, next, &command)
            {
                return Err(
                    "The managed shortcut file was changed outside Boltwarden; use manual setup"
                        .into(),
                );
            }
        }
        if next.is_some()
            && owned.as_deref() == Some(render(paths.format, next, &command).as_str())
            && binds.as_array().is_some_and(|list| {
                list.iter()
                    .any(|bind| matches_key(bind, next.unwrap()) && owns_command(bind, &command))
            })
        {
            return Ok(());
        }
        install(&paths, next, &command, || {
            run(&["reload"])?;
            let errors = run(&["configerrors"])?;
            if !errors.trim().is_empty() { return Err(format!("Hyprland rejected the shortcut: {}", errors.trim())); }
            let bindings: serde_json::Value = serde_json::from_str(&run(&["-j", "binds"])?).map_err(|e| e.to_string())?;
            let bindings = bindings.as_array().ok_or("Hyprland returned an invalid bindings list")?;
            if let Some(next) = next {
                let matching: Vec<_> = bindings.iter().filter(|bind| matches_key(bind, next)).collect();
                if matching.len() != 1 || !owns_command(matching[0], &command) {
                    return Err("Hyprland did not activate exactly one binding; use manual setup for custom includes".into());
                }
            } else if previous.is_some_and(|previous| bindings.iter().any(|bind| matches_key(bind, previous) && owns_command(bind, &command))) {
                return Err("Hyprland did not remove the managed shortcut".into());
            }
            Ok(())
        }).inspect_err(|_| { let _ = run(&["reload"]); })
    }
}
fn paths() -> Result<Paths, String> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or("User config directory unavailable")?
        .join("hypr");
    let format = if base.join("hyprland.lua").is_file() {
        Format::Lua
    } else {
        Format::Conf
    };
    let extension = if format == Format::Lua { "lua" } else { "conf" };
    let main = base.join(format!("hyprland.{extension}"));
    if !main.is_file() {
        return Err("Hyprland user configuration was not found".into());
    }
    Ok(Paths {
        main,
        owned: base.join(format!("boltwarden-shortcut.{extension}")),
        format,
    })
}
pub fn copy_binding(shortcut: &Shortcut) -> Result<String, String> {
    let format = paths().map(|p| p.format).unwrap_or(Format::Lua);
    Ok(render(
        format,
        Some(shortcut),
        &shell_command(&std::env::current_exe().map_err(|e| e.to_string())?)?,
    ))
}
fn shell_command(executable: &Path) -> Result<String, String> {
    let path = executable
        .to_str()
        .ok_or("Executable path is not valid UTF-8")?;
    if path.chars().any(char::is_control) || path.contains('#') || path.contains('$') {
        return Err("Executable path cannot be safely used in a Hyprland binding".into());
    }
    Ok(format!("'{}' toggle", path.replace('\'', "'\\''")))
}
fn render(format: Format, shortcut: Option<&Shortcut>, command: &str) -> String {
    let comment = if format == Format::Lua { "--" } else { "#" };
    let mut body = format!("{comment} {MARKER}\n");
    if let Some(shortcut) = shortcut {
        let mut modifiers = Vec::new();
        if shortcut.ctrl {
            modifiers.push("CTRL");
        }
        if shortcut.alt {
            modifiers.push("ALT");
        }
        if shortcut.shift {
            modifiers.push("SHIFT");
        }
        if shortcut.super_key {
            modifiers.push("SUPER");
        }
        let key = if shortcut.key == "Space" {
            "space"
        } else {
            &shortcut.key
        };
        match format {
            Format::Lua => {
                modifiers.push(key);
                body.push_str(&format!(
                    "hl.bind({}, hl.dsp.exec_cmd({}))\n",
                    quote(&modifiers.join(" + ")),
                    quote(command)
                ));
            }
            Format::Conf => body.push_str(&format!(
                "bind = {}, {}, exec, {}\n",
                modifiers.join(" "),
                key,
                command
            )),
        }
    }
    body
}
fn quote(value: &str) -> String {
    serde_json::to_string(value).unwrap()
}
fn matches_key(binding: &serde_json::Value, key: &Shortcut) -> bool {
    let mask = if key.shift { 1 } else { 0 }
        | if key.ctrl { 4 } else { 0 }
        | if key.alt { 8 } else { 0 }
        | if key.super_key { 64 } else { 0 };
    binding["modmask"]
        .as_u64()
        .is_some_and(|value| value & !18 == mask)
        && (binding["key"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(&key.key))
            || binding["keycode"].as_u64().is_some_and(|code| code != 0))
}
fn owns_command(binding: &serde_json::Value, command: &str) -> bool {
    matches!(binding["dispatcher"].as_str(), Some("exec" | "exec_cmd"))
        && binding["arg"].as_str() == Some(command)
        && binding["submap"].as_str().unwrap_or("").is_empty()
}
fn check_conflict(
    bindings: &serde_json::Value,
    key: &Shortcut,
    command: &str,
    already_owned: bool,
) -> Result<(), String> {
    let list = bindings
        .as_array()
        .ok_or("Hyprland returned an invalid bindings list")?;
    let matches: Vec<_> = list
        .iter()
        .filter(|binding| matches_key(binding, key))
        .collect();
    if matches.is_empty()
        || (already_owned && matches.len() == 1 && owns_command(matches[0], command))
    {
        return Ok(());
    }
    Err("Already in use by a Hyprland binding. Choose another shortcut or remove the existing binding yourself.".into())
}
fn read_optional(path: &Path) -> Result<Option<String>, String> {
    reject_symlinks(path)?;
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}
fn reject_symlinks(path: &Path) -> Result<(), String> {
    for part in path.ancestors() {
        if fs::symlink_metadata(part).is_ok_and(|info| info.file_type().is_symlink()) {
            return Err("Symlinked Hyprland configurations require manual setup".into());
        }
    }
    Ok(())
}
fn write(path: &Path, contents: &str) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    reject_symlinks(path)?;
    let temporary = path.with_extension(format!("boltwarden-{}", uuid::Uuid::new_v4()));
    let mode = fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777)
        .unwrap_or(0o600);
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    let _ = fs::remove_file(&temporary);
    result.map_err(|error: std::io::Error| error.to_string())
}
fn install(
    paths: &Paths,
    next: Option<&Shortcut>,
    command: &str,
    reload: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let original = read_optional(&paths.main)?.ok_or("Hyprland config is missing")?;
    let previous = read_optional(&paths.owned)?;
    if previous.as_ref().is_some_and(|text| {
        !text
            .lines()
            .next()
            .is_some_and(|line| line.ends_with(MARKER))
    }) {
        return Err("The shortcut file belongs to something else; refusing to replace it".into());
    }
    let filename = paths
        .owned
        .to_str()
        .ok_or("Configuration path is not valid UTF-8")?;
    if filename.chars().any(char::is_control) || filename.contains(['#', '$']) {
        return Err("Configuration path requires manual setup".into());
    }
    let include = match paths.format {
        Format::Lua => format!(
            "-- Boltwarden quick access include\ndofile({})\n",
            quote(filename)
        ),
        Format::Conf => format!("# Boltwarden quick access include\nsource = {filename}\n"),
    };
    let changed_main = !original.contains(&include);
    if changed_main && original.contains("Boltwarden quick access include") {
        return Err("The Boltwarden include was edited; use manual setup".into());
    }
    if changed_main {
        let backup = paths
            .main
            .with_extension(format!("boltwarden-backup-{}", uuid::Uuid::new_v4()));
        write(&backup, &original)?;
    }
    write(&paths.owned, &render(paths.format, next, command))?;
    let apply = (|| {
        if changed_main {
            write(&paths.main, &format!("{original}\n{include}"))?;
        }
        reload()
    })();
    if let Err(error) = apply {
        let restore_main = if changed_main {
            write(&paths.main, &original)
        } else {
            Ok(())
        };
        let restore_owned = match previous {
            Some(text) => write(&paths.owned, &text),
            None => fs::remove_file(&paths.owned).map_err(|e| e.to_string()),
        };
        restore_main
            .and(restore_owned)
            .map_err(|rollback| format!("{error}; restoring config failed: {rollback}"))?;
        return Err(error);
    }
    Ok(())
}
fn run(args: &[&str]) -> Result<String, String> {
    let mut child = Command::new("hyprctl")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let output = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = String::new();
        let result = output
            .take(2 * 1024 * 1024)
            .read_to_string(&mut bytes)
            .map(|_| bytes);
        let _ = tx.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => {
                if !status.success() {
                    return Err("Hyprland command failed".into());
                }
                return rx
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|_| "Hyprland response timed out")?
                    .map_err(|e| e.to_string());
            }
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Hyprland command timed out".into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> Shortcut {
        Shortcut {
            ctrl: true,
            alt: true,
            key: "B".into(),
            ..Default::default()
        }
    }
    fn fixture(format: Format, test: impl FnOnce(&Paths)) {
        let root =
            std::env::temp_dir().join(format!("boltwarden-shortcut-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let paths = Paths {
            main: root.join("hyprland.config"),
            owned: root.join("shortcut.config"),
            format,
        };
        fs::write(&paths.main, "# existing user configuration\n").unwrap();
        test(&paths);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn installs_rebinds_and_clears_only_managed_content_in_both_formats() {
        for format in [Format::Lua, Format::Conf] {
            fixture(format, |paths| {
                let original = fs::read_to_string(&paths.main).unwrap();
                install(paths, Some(&key()), "'boltwarden' toggle", || Ok(())).unwrap();
                let installed = fs::read_to_string(&paths.main).unwrap();
                assert!(installed.starts_with(&original));
                let new = Shortcut {
                    key: "C".into(),
                    ..key()
                };
                install(paths, Some(&new), "'boltwarden' toggle", || Ok(())).unwrap();
                assert_eq!(fs::read_to_string(&paths.main).unwrap(), installed);
                install(paths, None, "'boltwarden' toggle", || Ok(())).unwrap();
                assert_eq!(fs::read_to_string(&paths.owned).unwrap().lines().count(), 1);
                assert_eq!(fs::read_to_string(&paths.main).unwrap(), installed);
            });
        }
    }
    #[test]
    fn failed_reload_restores_files_and_foreign_files_are_not_overwritten() {
        fixture(Format::Lua, |paths| {
            let original = fs::read_to_string(&paths.main).unwrap();
            assert!(
                install(paths, Some(&key()), "'boltwarden' toggle", || Err(
                    "bad config".into()
                ))
                .is_err()
            );
            assert_eq!(fs::read_to_string(&paths.main).unwrap(), original);
            assert!(!paths.owned.exists());
            fs::write(&paths.owned, "user content").unwrap();
            assert!(install(paths, Some(&key()), "'boltwarden' toggle", || Ok(())).is_err());
            assert_eq!(fs::read_to_string(&paths.owned).unwrap(), "user content");
        });
    }
    #[test]
    fn conflicts_include_other_submaps_and_allow_only_exact_owned_binding() {
        let binding = serde_json::json!([{"modmask":12,"key":"B","dispatcher":"exec","arg":"other app","submap":"special"}]);
        assert!(check_conflict(&binding, &key(), "'boltwarden' toggle", true).is_err());
        let binding = serde_json::json!([{"modmask":12,"key":"b","dispatcher":"exec","arg":"'boltwarden' toggle"}]);
        assert!(check_conflict(&binding, &key(), "'boltwarden' toggle", false).is_err());
        assert!(check_conflict(&binding, &key(), "'boltwarden' toggle", true).is_ok());
        let binding = serde_json::json!([{"modmask":12,"key":"b","dispatcher":"exec","arg":"'boltwarden' toggle","submap":"special"}]);
        assert!(check_conflict(&binding, &key(), "'boltwarden' toggle", true).is_err());
    }
    #[test]
    fn shell_paths_are_quoted_and_configuration_injection_is_rejected() {
        assert_eq!(
            shell_command(Path::new("/tmp/it's here/boltwarden")).unwrap(),
            "'/tmp/it'\\''s here/boltwarden' toggle"
        );
        for path in ["/tmp/a\nb", "/tmp/$HOME/boltwarden", "/tmp/a#b"] {
            assert!(shell_command(Path::new(path)).is_err());
        }
    }
}
