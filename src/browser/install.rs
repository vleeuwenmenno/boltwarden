//! Native-host registration for per-user, unsandboxed browsers on Linux.
//!
//! Discovery reads executable metadata only; it does not launch browsers or inspect profiles.
//! Custom Chromium profiles need their user-data directory's `NativeMessagingHosts` directory,
//! not an individual profile directory. Registration controls native-host discovery, while the
//! daemon's signed pairing protocol continues to authorize each browser connection.
use super::protocol::identities;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const LAUNCHER_PREFIX: &str = "#!/bin/sh\n# Installed by Boltwarden browser integration.\nexec ";
const LAUNCHER_SUFFIX: &str = " native-host \"$@\"\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFamily {
    Firefox,
    Chromium,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserRegistration {
    pub id: String,
    pub label: String,
    pub executable: PathBuf,
    pub family: BrowserFamily,
    pub native_host_dir: PathBuf,
    pub registered: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Browser {
    Firefox,
    Chrome,
    Chromium,
    Vivaldi,
    VivaldiSnapshot,
    Brave,
    BraveOrigin,
    Edge,
    Zen,
    LibreWolf,
    FirefoxDeveloper,
    Helium,
    Opera,
    OperaGx,
    OperaBeta,
    OperaDeveloper,
    ChromeBeta,
    ChromeDev,
    BraveBeta,
    BraveNightly,
    EdgeBeta,
    EdgeDev,
    UngoogledChromium,
    All,
}

struct KnownBrowser {
    browser: Browser,
    id: &'static str,
    label: &'static str,
    executables: &'static [&'static str],
    family: BrowserFamily,
    config_dir: &'static str,
}

const KNOWN_BROWSERS: &[KnownBrowser] = &[
    KnownBrowser {
        browser: Browser::Firefox,
        id: "firefox",
        label: "Firefox",
        executables: &["firefox", "firefox-esr"],
        family: BrowserFamily::Firefox,
        config_dir: ".mozilla/native-messaging-hosts",
    },
    KnownBrowser {
        browser: Browser::Chrome,
        id: "chrome",
        label: "Google Chrome",
        executables: &["google-chrome-stable", "google-chrome"],
        family: BrowserFamily::Chromium,
        config_dir: "google-chrome/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::Chromium,
        id: "chromium",
        label: "Chromium",
        executables: &["chromium", "chromium-browser"],
        family: BrowserFamily::Chromium,
        config_dir: "chromium/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::Vivaldi,
        id: "vivaldi",
        label: "Vivaldi",
        executables: &["vivaldi", "vivaldi-stable"],
        family: BrowserFamily::Chromium,
        config_dir: "vivaldi/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::VivaldiSnapshot,
        id: "vivaldi-snapshot",
        label: "Vivaldi Snapshot",
        executables: &["vivaldi-snapshot"],
        family: BrowserFamily::Chromium,
        config_dir: "vivaldi-snapshot/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::Brave,
        id: "brave",
        label: "Brave",
        executables: &["brave-browser", "brave-browser-stable", "brave"],
        family: BrowserFamily::Chromium,
        config_dir: "BraveSoftware/Brave-Browser/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::BraveOrigin,
        id: "brave-origin",
        label: "Brave Origin",
        executables: &["brave-origin", "brave-origin-browser"],
        family: BrowserFamily::Chromium,
        config_dir: "BraveSoftware/Brave-Origin/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::Edge,
        id: "edge",
        label: "Microsoft Edge",
        executables: &["microsoft-edge-stable", "microsoft-edge"],
        family: BrowserFamily::Chromium,
        config_dir: "microsoft-edge/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::Zen,
        id: "zen",
        label: "Zen",
        executables: &["zen", "zen-browser", "zen-bin"],
        family: BrowserFamily::Firefox,
        config_dir: ".mozilla/native-messaging-hosts",
    },
    KnownBrowser {
        browser: Browser::LibreWolf,
        id: "librewolf",
        label: "LibreWolf",
        executables: &["librewolf"],
        family: BrowserFamily::Firefox,
        config_dir: ".librewolf/native-messaging-hosts",
    },
    KnownBrowser {
        browser: Browser::FirefoxDeveloper,
        id: "firefox-developer",
        label: "Firefox Developer Edition",
        executables: &["firefox-developer-edition"],
        family: BrowserFamily::Firefox,
        config_dir: ".mozilla/native-messaging-hosts",
    },
    KnownBrowser {
        browser: Browser::Helium,
        id: "helium",
        label: "Helium",
        executables: &["helium", "helium-browser"],
        family: BrowserFamily::Chromium,
        config_dir: "net.imput.helium/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::Opera,
        id: "opera",
        label: "Opera",
        executables: &["opera", "opera-stable"],
        family: BrowserFamily::Chromium,
        config_dir: "opera/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::OperaGx,
        id: "opera-gx",
        label: "Opera GX",
        executables: &["opera-gx"],
        family: BrowserFamily::Chromium,
        config_dir: "opera-gx/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::OperaBeta,
        id: "opera-beta",
        label: "Opera Beta",
        executables: &["opera-beta"],
        family: BrowserFamily::Chromium,
        config_dir: "opera-beta/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::OperaDeveloper,
        id: "opera-developer",
        label: "Opera Developer",
        executables: &["opera-developer"],
        family: BrowserFamily::Chromium,
        config_dir: "opera-developer/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::ChromeBeta,
        id: "chrome-beta",
        label: "Google Chrome Beta",
        executables: &["google-chrome-beta"],
        family: BrowserFamily::Chromium,
        config_dir: "google-chrome-beta/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::ChromeDev,
        id: "chrome-dev",
        label: "Google Chrome Dev",
        executables: &["google-chrome-unstable"],
        family: BrowserFamily::Chromium,
        config_dir: "google-chrome-unstable/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::BraveBeta,
        id: "brave-beta",
        label: "Brave Beta",
        executables: &["brave-browser-beta", "brave-beta"],
        family: BrowserFamily::Chromium,
        config_dir: "BraveSoftware/Brave-Browser-Beta/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::BraveNightly,
        id: "brave-nightly",
        label: "Brave Nightly",
        executables: &["brave-browser-nightly", "brave-nightly"],
        family: BrowserFamily::Chromium,
        config_dir: "BraveSoftware/Brave-Browser-Nightly/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::EdgeBeta,
        id: "edge-beta",
        label: "Microsoft Edge Beta",
        executables: &["microsoft-edge-beta"],
        family: BrowserFamily::Chromium,
        config_dir: "microsoft-edge-beta/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::EdgeDev,
        id: "edge-dev",
        label: "Microsoft Edge Dev",
        executables: &["microsoft-edge-dev"],
        family: BrowserFamily::Chromium,
        config_dir: "microsoft-edge-dev/NativeMessagingHosts",
    },
    KnownBrowser {
        browser: Browser::UngoogledChromium,
        id: "ungoogled-chromium",
        label: "Ungoogled Chromium",
        executables: &["ungoogled-chromium"],
        family: BrowserFamily::Chromium,
        config_dir: "chromium/NativeMessagingHosts",
    },
];

struct Paths {
    home: PathBuf,
    config: PathBuf,
}

impl Paths {
    fn from_env() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .context("HOME must be absolute")?;
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        Ok(Self { home, config })
    }

    fn launcher(&self) -> PathBuf {
        self.home.join(".local/libexec/boltwarden-native-host")
    }

    fn native_host_dir(&self, browser: &KnownBrowser) -> PathBuf {
        match browser.family {
            BrowserFamily::Firefox => self.home.join(browser.config_dir),
            BrowserFamily::Chromium => self.config.join(browser.config_dir),
        }
    }
}

/// Discover known browsers on the absolute entries of PATH. Symlink aliases are deduplicated.
/// Saved custom registrations belong to the caller and are not inferred from browser profiles.
pub fn discover() -> Result<Vec<BrowserRegistration>> {
    discover_at(&Paths::from_env()?, &search_paths())
}

fn discover_at(paths: &Paths, search: &[PathBuf]) -> Result<Vec<BrowserRegistration>> {
    let mut seen = HashSet::new();
    let mut registrations: Vec<BrowserRegistration> = Vec::new();
    for browser in KNOWN_BROWSERS {
        let Some(executable) = browser
            .executables
            .iter()
            .find_map(|name| find_executable(search, name))
        else {
            continue;
        };
        let canonical = fs::canonicalize(&executable)?;
        if !seen.insert(canonical) {
            continue;
        }
        let native_host_dir = normalize_native_host_dir(&paths.native_host_dir(browser))?;
        if let Some(shared) = registrations
            .iter_mut()
            .find(|row| row.native_host_dir == native_host_dir)
        {
            // Shared manifests cannot be independently enabled or disabled.
            shared.label.push_str(" / ");
            shared.label.push_str(browser.label);
            continue;
        }
        registrations.push(BrowserRegistration {
            id: browser.id.into(),
            label: browser.label.into(),
            executable,
            family: browser.family,
            registered: is_registered_at(&native_host_dir, &paths.launcher())?,
            native_host_dir,
        });
    }
    Ok(registrations)
}

/// Default native-host directory for Firefox or Chromium. Vendor-specific Chromium browsers
/// use the paths returned by `discover`; custom user-data directories must be supplied explicitly.
pub fn default_native_host_dir(family: BrowserFamily) -> Result<PathBuf> {
    let paths = Paths::from_env()?;
    Ok(default_native_host_dir_at(&paths, family))
}

/// Suggest the vendor directory for a known executable without launching it.
pub fn suggested_registration(executable: &Path) -> Option<(BrowserFamily, PathBuf)> {
    let name = executable.file_name()?.to_str()?;
    let browser = KNOWN_BROWSERS
        .iter()
        .find(|browser| browser.executables.contains(&name))?;
    Some((
        browser.family,
        Paths::from_env().ok()?.native_host_dir(browser),
    ))
}

fn default_native_host_dir_at(paths: &Paths, family: BrowserFamily) -> PathBuf {
    match family {
        BrowserFamily::Firefox => paths.home.join(".mozilla/native-messaging-hosts"),
        BrowserFamily::Chromium => paths.config.join("chromium/NativeMessagingHosts"),
    }
}

/// Register a browser without executing it. `executable` identifies the browser, never the native
/// host: the shared launcher invokes the installed Boltwarden binary with `native-host`.
pub fn register(
    executable: PathBuf,
    family: BrowserFamily,
    native_host_dir: PathBuf,
) -> Result<()> {
    validate_executable(&executable).context("Invalid browser executable")?;
    install_at(&Paths::from_env()?, &[(native_host_dir, family)], None)
}

/// Remove only this installation's manifest. The shared launcher is retained because other
/// registered browsers, including custom user-data directories, can still depend on it.
/// Existing authenticated connections are ended by revoking their pairing, not by this operation.
pub fn unregister(native_host_dir: PathBuf) -> Result<()> {
    let native_host_dir = normalize_native_host_dir(&native_host_dir)?;
    remove_owned_manifest(
        &manifest_path(&native_host_dir),
        &Paths::from_env()?.launcher(),
    )?;
    Ok(())
}

/// A registration is usable only when its exact extension identity and owned launcher are intact.
/// Missing, foreign, malformed, or symlinked integration files are reported as unregistered.
pub fn is_registered(native_host_dir: &Path) -> Result<bool> {
    let native_host_dir = normalize_native_host_dir(native_host_dir)?;
    is_registered_at(&native_host_dir, &Paths::from_env()?.launcher())
}

/// Resolve existing directory symlinks and remove redundant components without creating folders.
/// A symlink followed by `..` resolves relative to its real target, as filesystem traversal does.
/// Missing suffixes are normalized lexically so callers can compare planned registrations too.
pub fn normalize_native_host_dir(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("Native-host directory must be absolute");
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(name) => {
                normalized.push(name);
                match fs::metadata(&normalized) {
                    Ok(metadata) if metadata.is_dir() => {
                        normalized = fs::canonicalize(&normalized)?;
                    }
                    Ok(_) => bail!("Native-host path must be a directory"),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        // A dangling existing symlink is not a directory we can safely create.
                        if fs::symlink_metadata(&normalized)
                            .is_ok_and(|metadata| metadata.is_symlink())
                        {
                            bail!("Native-host directory contains a dangling symlink");
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Component::Prefix(_) => bail!("Unsupported native-host directory prefix"),
        }
    }
    Ok(normalized)
}

fn is_registered_at(native_host_dir: &Path, launcher: &Path) -> Result<bool> {
    let owned = match read_owned(&manifest_path(native_host_dir)) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&owned) else {
        return Ok(false);
    };
    if !is_our_manifest(&value, launcher) {
        return Ok(false);
    }
    let owned = match read_owned(launcher) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let Some(binary) = launcher_binary(&owned) else {
        return Ok(false);
    };
    Ok(validate_executable(&binary).is_ok() && executable_file(launcher))
}

/// Rewrite the shared launcher when a registered browser would otherwise be left pointing at a
/// missing Boltwarden binary, for example after a move from `/usr/local/bin` to a package install.
/// Does nothing unless one of our manifests exists, so integration stays opt-in. Returns whether
/// the launcher was rewritten.
pub fn repair_launcher() -> Result<bool> {
    let binary = std::env::current_exe()
        .ok()
        .filter(|path| validate_executable(path).is_ok())
        .or_else(find_binary);
    repair_launcher_at(&Paths::from_env()?, binary)
}

fn repair_launcher_at(paths: &Paths, binary: Option<PathBuf>) -> Result<bool> {
    let launcher = paths.launcher();
    if let Some(bytes) = read_owned(&launcher)? {
        match launcher_binary(&bytes) {
            Some(existing) if validate_executable(&existing).is_ok() => return Ok(false),
            Some(_) => {}
            None => return Ok(false),
        }
    }
    let registered = destinations(paths, Browser::All)
        .iter()
        .any(|(directory, _)| {
            matches!(
                check_managed_manifest(&manifest_path(directory), &launcher),
                Ok(true)
            )
        });
    let Some(binary) = binary.filter(|_| registered) else {
        return Ok(false);
    };
    validate_executable(&binary)?;
    let script = format!(
        "{LAUNCHER_PREFIX}{}{LAUNCHER_SUFFIX}",
        shell_quote(binary.to_str().context("Binary path must be valid UTF-8")?)
    );
    write_atomic(&launcher, script.as_bytes(), 0o700)?;
    Ok(true)
}

struct Options {
    browser: Browser,
    uninstall: bool,
    detected: bool,
    binary: Option<PathBuf>,
}

pub fn run(args: impl IntoIterator<Item = String>) -> Result<(), String> {
    let options = parse(args)?;
    let paths = Paths::from_env().map_err(|error| error.to_string())?;
    if options.detected {
        if options.uninstall {
            return Err("--detected cannot be combined with --uninstall".into());
        }
        let found = discover_at(&paths, &search_paths()).map_err(|error| error.to_string())?;
        if found.is_empty() {
            println!("No supported browsers found in PATH.");
            return Ok(());
        }
        let targets: Vec<_> = found
            .iter()
            .map(|row| (row.native_host_dir.clone(), row.family))
            .collect();
        install_at(&paths, &targets, options.binary).map_err(|error| error.to_string())?;
        for row in &found {
            println!("Registered {}", row.label);
        }
        return Ok(());
    }
    let destinations = destinations(&paths, options.browser);
    if options.uninstall {
        for (directory, _) in destinations {
            let directory =
                normalize_native_host_dir(&directory).map_err(|error| error.to_string())?;
            remove_owned_manifest(&manifest_path(&directory), &paths.launcher())
                .map_err(|error| error.to_string())?;
        }
        return Ok(());
    }
    install_at(&paths, &destinations, options.binary).map_err(|error| error.to_string())
}

fn install_at(
    paths: &Paths,
    destinations: &[(PathBuf, BrowserFamily)],
    binary_override: Option<PathBuf>,
) -> Result<()> {
    let launcher = paths.launcher();
    let destinations: Vec<_> = destinations
        .iter()
        .map(|(directory, family)| Ok((normalize_native_host_dir(directory)?, *family)))
        .collect::<Result<_>>()?;
    // Check every destination before replacing the shared launcher or any existing manifest.
    for (directory, _) in &destinations {
        check_managed_manifest(&manifest_path(directory), &launcher)?;
    }
    let existing_binary = match read_owned(&launcher)? {
        Some(bytes) => Some(
            launcher_binary(&bytes)
                .context("Refusing to replace a launcher not installed by Boltwarden")?,
        ),
        None => None,
    };
    let binary = binary_override
        .or_else(|| existing_binary.filter(|binary| validate_executable(binary).is_ok()))
        .or_else(find_binary)
        .context(
            "boltwarden was not found in PATH; install it or pass --path /absolute/path/boltwarden",
        )?;
    validate_executable(&binary).context("Invalid Boltwarden executable")?;
    let script = format!(
        "{LAUNCHER_PREFIX}{}{LAUNCHER_SUFFIX}",
        shell_quote(binary.to_str().context("Binary path must be valid UTF-8")?)
    );
    write_atomic(&launcher, script.as_bytes(), 0o700)?;
    for (directory, family) in &destinations {
        write_atomic(
            &manifest_path(directory),
            &serde_json::to_vec_pretty(&manifest(&launcher, *family))?,
            0o600,
        )?;
    }
    Ok(())
}

fn parse(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut result = Options {
        browser: Browser::All,
        uninstall: false,
        detected: false,
        binary: None,
    };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--browser" => {
                result.browser = match args.next().as_deref() {
                    Some("all") => Browser::All,
                    Some(name) => KNOWN_BROWSERS
                        .iter()
                        .find(|browser| browser.id == name)
                        .map(|browser| browser.browser)
                        .ok_or_else(|| {
                            format!(
                                "--browser must be {} or all",
                                KNOWN_BROWSERS
                                    .iter()
                                    .map(|browser| browser.id)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        })?,
                    None => return Err("--browser requires a browser name".into()),
                }
            }
            "--uninstall" => result.uninstall = true,
            "--detected" => result.detected = true,
            "--path" => {
                result.binary = Some(PathBuf::from(
                    args.next().ok_or("--path requires a binary path")?,
                ))
            }
            _ => return Err(format!("Unknown install-browser argument: {arg}")),
        }
    }
    Ok(result)
}

fn destinations(paths: &Paths, browser: Browser) -> Vec<(PathBuf, BrowserFamily)> {
    let mut seen = HashSet::new();
    KNOWN_BROWSERS
        .iter()
        .filter(|known| browser == Browser::All || known.browser == browser)
        .map(|known| (paths.native_host_dir(known), known.family))
        .filter(|(path, _)| seen.insert(path.clone()))
        .collect()
}

fn manifest_path(directory: &Path) -> PathBuf {
    directory.join(format!("{}.json", identities().host_name))
}

fn manifest(launcher: &Path, family: BrowserFamily) -> serde_json::Value {
    let ids = identities();
    let mut value = serde_json::json!({"name": ids.host_name, "description": "Boltwarden browser integration", "path": launcher, "type": "stdio"});
    match family {
        BrowserFamily::Firefox => {
            value["allowed_extensions"] = serde_json::json!([ids.firefox_id]);
        }
        BrowserFamily::Chromium => {
            value["allowed_origins"] =
                serde_json::json!([format!("chrome-extension://{}/", ids.chrome_id)]);
        }
    }
    value
}

fn is_our_manifest(value: &serde_json::Value, launcher: &Path) -> bool {
    *value == manifest(launcher, BrowserFamily::Firefox)
        || *value == manifest(launcher, BrowserFamily::Chromium)
}

fn check_managed_manifest(path: &Path, launcher: &Path) -> io::Result<bool> {
    let Some(bytes) = read_owned(path)? else {
        return Ok(false);
    };
    let value = serde_json::from_slice::<serde_json::Value>(&bytes)
        .map_err(|_| permission_denied("Refusing to replace or remove an invalid manifest"))?;
    if !is_our_manifest(&value, launcher) {
        return Err(permission_denied(
            "Manifest belongs to another installation",
        ));
    }
    Ok(true)
}

fn validate_executable(path: &Path) -> Result<()> {
    if !executable_file(path) {
        bail!("Path must name an absolute executable file");
    }
    let text = path.to_str().context("Binary path must be valid UTF-8")?;
    if text.contains(['\n', '\r']) {
        bail!("Binary path contains a line break");
    }
    Ok(())
}

fn executable_file(path: &Path) -> bool {
    path.is_absolute()
        && fs::metadata(path)
            .is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
}

fn search_paths() -> Vec<PathBuf> {
    std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path)
                .filter(|directory| directory.is_absolute())
                .collect()
        })
        .unwrap_or_default()
}

fn find_executable(search: &[PathBuf], name: &str) -> Option<PathBuf> {
    search
        .iter()
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(name))
        .find(|path| executable_file(path))
}

fn find_binary() -> Option<PathBuf> {
    let installed = PathBuf::from("/usr/local/bin/boltwarden");
    if executable_file(&installed) {
        Some(installed)
    } else {
        find_executable(&search_paths(), "boltwarden")
    }
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

// Only recognize the exact script format we write. This is not a general shell parser.
fn launcher_binary(bytes: &[u8]) -> Option<PathBuf> {
    let script = std::str::from_utf8(bytes).ok()?;
    let quoted = script
        .strip_prefix(LAUNCHER_PREFIX)?
        .strip_suffix(LAUNCHER_SUFFIX)?;
    let binary = quoted
        .strip_prefix('\'')?
        .strip_suffix('\'')?
        .replace("'\\''", "'");
    if binary.contains(['\n', '\r']) || shell_quote(&binary) != quoted {
        return None;
    }
    let path = PathBuf::from(binary);
    path.is_absolute().then_some(path)
}

fn permission_denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn owned_regular(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_file() || metadata.uid() != crate::unix_socket::current_uid() {
        return Err(permission_denied(
            "Refusing to use a non-owned or nonregular integration file",
        ));
    }
    Ok(())
}

fn read_owned(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => owned_regular(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    owned_regular(&file.metadata()?)?;
    let mut bytes = Vec::new();
    file.take(65_537).read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        return Err(permission_denied(
            "Integration file exceeds the expected size",
        ));
    }
    Ok(Some(bytes))
}

fn write_atomic(path: &Path, body: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("Missing parent directory"))?;
    fs::create_dir_all(parent)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => owned_regular(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let temporary = parent.join(format!(".boltwarden.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(body)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn remove_owned_manifest(path: &Path, launcher: &Path) -> io::Result<()> {
    if check_managed_manifest(path, launcher)? {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Fixture {
        root: PathBuf,
        paths: Paths,
        binaries: PathBuf,
        boltwarden: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root =
                crate::test_temp_dir().join(format!("boltwarden-install-{}", uuid::Uuid::new_v4()));
            let binaries = root.join("bin");
            fs::create_dir_all(&binaries).unwrap();
            let boltwarden = binaries.join("boltwarden");
            executable(&boltwarden);
            Self {
                paths: Paths {
                    home: root.join("home"),
                    config: root.join("config"),
                },
                root,
                binaries,
                boltwarden,
            }
        }

        fn install(&self, directory: &Path, family: BrowserFamily) -> Result<()> {
            install_at(
                &self.paths,
                &[(directory.into(), family)],
                Some(self.boltwarden.clone()),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn executable(path: &Path) {
        fs::write(path, "#!/bin/sh\nexit 89\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn repair_rewrites_stale_or_missing_launcher_only_when_registered() {
        let fixture = Fixture::new();
        let directory = fixture.paths.home.join(".mozilla/native-messaging-hosts");
        let launcher = fixture.paths.launcher();
        let current = Some(fixture.boltwarden.clone());

        // Not registered: stay opt-in.
        assert!(!repair_launcher_at(&fixture.paths, current.clone()).unwrap());
        assert!(!launcher.exists());

        let gone = fixture.binaries.join("gone");
        executable(&gone);
        install_at(
            &fixture.paths,
            &[(directory.clone(), BrowserFamily::Firefox)],
            Some(gone.clone()),
        )
        .unwrap();
        assert!(!repair_launcher_at(&fixture.paths, current.clone()).unwrap());

        fs::remove_file(&gone).unwrap();
        assert!(repair_launcher_at(&fixture.paths, current.clone()).unwrap());
        assert_eq!(
            launcher_binary(&fs::read(&launcher).unwrap()),
            Some(fixture.boltwarden.clone())
        );
        assert!(
            is_registered_at(&normalize_native_host_dir(&directory).unwrap(), &launcher).unwrap()
        );

        fs::remove_file(&launcher).unwrap();
        assert!(repair_launcher_at(&fixture.paths, current).unwrap());
        assert!(launcher.exists());
    }

    #[test]
    fn manifests_use_launcher_and_exact_extension_ids() {
        let path = Path::new("/home/user/.local/libexec/boltwarden-native-host");
        assert_eq!(
            manifest(path, BrowserFamily::Firefox)["allowed_extensions"],
            serde_json::json!([identities().firefox_id])
        );
        assert_eq!(
            manifest(path, BrowserFamily::Chromium)["allowed_origins"],
            serde_json::json!([format!("chrome-extension://{}/", identities().chrome_id)])
        );
        assert_eq!(
            manifest(path, BrowserFamily::Chromium)["path"],
            path.to_str().unwrap()
        );
        assert_eq!(shell_quote("/path/with 'quote"), "'/path/with '\\''quote'");
    }

    #[test]
    fn installer_rejects_arbitrary_ids_and_accepts_vendor_names() {
        assert!(parse(["--dev-extension-id".into(), "anything".into()]).is_err());
        assert!(parse(["--browser".into(), "anything".into()]).is_err());
        assert_eq!(
            parse(["--browser".into(), "vivaldi".into()])
                .unwrap()
                .browser,
            Browser::Vivaldi
        );
        assert_eq!(
            parse(["--browser".into(), "vivaldi-snapshot".into()])
                .unwrap()
                .browser,
            Browser::VivaldiSnapshot
        );
    }

    #[test]
    fn vendor_destinations_respect_config_home_and_vivaldi_is_in_all() {
        let fixture = Fixture::new();
        let all = destinations(&fixture.paths, Browser::All);
        for directory in [
            "vivaldi/NativeMessagingHosts",
            "vivaldi-snapshot/NativeMessagingHosts",
            "BraveSoftware/Brave-Browser/NativeMessagingHosts",
            "BraveSoftware/Brave-Origin/NativeMessagingHosts",
            "microsoft-edge/NativeMessagingHosts",
        ] {
            assert!(all.contains(&(
                fixture.paths.config.join(directory),
                BrowserFamily::Chromium
            )));
        }
        assert_eq!(
            destinations(&fixture.paths, Browser::Vivaldi),
            vec![(
                fixture.paths.config.join("vivaldi/NativeMessagingHosts"),
                BrowserFamily::Chromium
            )]
        );
        assert_eq!(
            default_native_host_dir_at(&fixture.paths, BrowserFamily::Firefox),
            fixture.paths.home.join(".mozilla/native-messaging-hosts")
        );
        assert_eq!(
            default_native_host_dir_at(&fixture.paths, BrowserFamily::Chromium),
            fixture.paths.config.join("chromium/NativeMessagingHosts")
        );
    }

    #[test]
    fn every_catalog_entry_discovers_parses_and_registers_its_own_family() {
        for browser in KNOWN_BROWSERS {
            let fixture = Fixture::new();
            executable(&fixture.binaries.join(browser.executables[0]));
            let rows = discover_at(&fixture.paths, &[fixture.binaries.clone()]).unwrap();
            assert_eq!(rows.len(), 1, "{}", browser.id);
            let row = &rows[0];
            assert_eq!(row.id, browser.id);
            assert_eq!(row.family, browser.family);
            assert_eq!(row.native_host_dir, fixture.paths.native_host_dir(browser));
            assert_eq!(
                parse(["--browser".into(), browser.id.into()])
                    .unwrap()
                    .browser,
                browser.browser
            );
            fixture.install(&row.native_host_dir, row.family).unwrap();
            assert!(is_registered_at(&row.native_host_dir, &fixture.paths.launcher()).unwrap());
        }
    }

    #[test]
    fn firefox_and_zen_share_one_visible_registration() {
        let fixture = Fixture::new();
        executable(&fixture.binaries.join("firefox"));
        executable(&fixture.binaries.join("zen"));
        let rows = discover_at(&fixture.paths, &[fixture.binaries.clone()]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "Firefox / Zen");
        assert_eq!(
            rows[0].native_host_dir,
            fixture.paths.home.join(".mozilla/native-messaging-hosts")
        );
        let all = destinations(&fixture.paths, Browser::All);
        assert_eq!(
            all.iter()
                .map(|(path, _)| path)
                .collect::<HashSet<_>>()
                .len(),
            all.len()
        );
    }

    #[test]
    fn brave_origin_is_discovered_separately_from_brave_and_chromium() {
        let fixture = Fixture::new();
        for name in ["brave", "brave-origin", "chromium"] {
            executable(&fixture.binaries.join(name));
        }
        let rows = discover_at(&fixture.paths, &[fixture.binaries.clone()]).unwrap();
        assert_eq!(rows.len(), 3);
        let origin = rows.iter().find(|row| row.id == "brave-origin").unwrap();
        assert_eq!(
            origin.native_host_dir,
            fixture
                .paths
                .config
                .join("BraveSoftware/Brave-Origin/NativeMessagingHosts")
        );
        assert_eq!(
            parse(["--browser".into(), "brave-origin".into()])
                .unwrap()
                .browser,
            Browser::BraveOrigin
        );
        let (_, suggested) = suggested_registration(Path::new("/usr/bin/brave-origin")).unwrap();
        assert!(suggested.ends_with("BraveSoftware/Brave-Origin/NativeMessagingHosts"));
    }

    #[test]
    fn discovery_ignores_missing_nonexecutables_and_relative_search_and_deduplicates_aliases() {
        let fixture = Fixture::new();
        executable(&fixture.binaries.join("vivaldi-stable"));
        symlink("vivaldi-stable", fixture.binaries.join("vivaldi")).unwrap();
        symlink("vivaldi-stable", fixture.binaries.join("brave")).unwrap();
        fs::write(fixture.binaries.join("firefox"), "not executable").unwrap();
        let registrations = discover_at(
            &fixture.paths,
            &[PathBuf::from("relative"), fixture.binaries.clone()],
        )
        .unwrap();
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].id, "vivaldi");
        assert_eq!(
            registrations[0].native_host_dir,
            fixture.paths.config.join("vivaldi/NativeMessagingHosts")
        );
        assert!(!registrations[0].registered);
    }

    #[test]
    fn discovery_deduplicates_browsers_sharing_the_same_native_host_directory() {
        let fixture = Fixture::new();
        executable(&fixture.binaries.join("google-chrome"));
        executable(&fixture.binaries.join("vivaldi"));
        let shared = fixture
            .paths
            .config
            .join("google-chrome/NativeMessagingHosts");
        fs::create_dir_all(&shared).unwrap();
        let vivaldi = fixture.paths.config.join("vivaldi/NativeMessagingHosts");
        fs::create_dir_all(vivaldi.parent().unwrap()).unwrap();
        symlink(&shared, &vivaldi).unwrap();
        let registrations = discover_at(&fixture.paths, &[fixture.binaries.clone()]).unwrap();
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].native_host_dir, shared);
        assert!(!registrations[0].registered);
    }

    #[test]
    fn custom_directory_round_trip_keeps_shared_launcher_and_other_registrations() {
        let fixture = Fixture::new();
        let custom = fixture.root.join("custom user data/NativeMessagingHosts");
        let firefox = default_native_host_dir_at(&fixture.paths, BrowserFamily::Firefox);
        assert!(!is_registered_at(&custom, &fixture.paths.launcher()).unwrap());
        fixture.install(&custom, BrowserFamily::Chromium).unwrap();
        fixture.install(&firefox, BrowserFamily::Firefox).unwrap();
        assert!(is_registered_at(&custom, &fixture.paths.launcher()).unwrap());
        assert!(is_registered_at(&firefox, &fixture.paths.launcher()).unwrap());
        assert_eq!(
            launcher_binary(&fs::read(fixture.paths.launcher()).unwrap()),
            Some(fixture.boltwarden.clone())
        );
        assert_eq!(
            fs::metadata(fixture.paths.launcher()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(manifest_path(&custom)).unwrap().mode() & 0o777,
            0o600
        );
        remove_owned_manifest(&manifest_path(&custom), &fixture.paths.launcher()).unwrap();
        remove_owned_manifest(&manifest_path(&custom), &fixture.paths.launcher()).unwrap();
        assert!(!is_registered_at(&custom, &fixture.paths.launcher()).unwrap());
        assert!(is_registered_at(&firefox, &fixture.paths.launcher()).unwrap());
    }

    #[test]
    fn existing_owned_custom_launcher_is_preserved_without_executing_it() {
        let fixture = Fixture::new();
        let binary = fixture.binaries.join("custom 'boltwarden");
        executable(&binary);
        let directory = fixture.root.join("native-hosts");
        install_at(
            &fixture.paths,
            &[(directory.clone(), BrowserFamily::Firefox)],
            Some(binary.clone()),
        )
        .unwrap();
        install_at(
            &fixture.paths,
            &[(directory.clone(), BrowserFamily::Firefox)],
            None,
        )
        .unwrap();
        assert_eq!(
            launcher_binary(&fs::read(fixture.paths.launcher()).unwrap()),
            Some(binary)
        );
        assert!(is_registered_at(&directory, &fixture.paths.launcher()).unwrap());
        fs::remove_file(fixture.paths.launcher()).unwrap();
        assert!(!is_registered_at(&directory, &fixture.paths.launcher()).unwrap());
    }

    #[test]
    fn foreign_manifest_is_not_overwritten_or_removed_and_launcher_is_not_created() {
        let fixture = Fixture::new();
        let directory = fixture.root.join("native-hosts");
        fs::create_dir_all(&directory).unwrap();
        let foreign = serde_json::json!({"name": identities().host_name, "path": "/someone/elses/host", "type": "stdio"});
        let original = serde_json::to_vec(&foreign).unwrap();
        fs::write(manifest_path(&directory), &original).unwrap();
        assert!(
            fixture
                .install(&directory, BrowserFamily::Chromium)
                .is_err()
        );
        assert!(
            remove_owned_manifest(&manifest_path(&directory), &fixture.paths.launcher()).is_err()
        );
        assert_eq!(fs::read(manifest_path(&directory)).unwrap(), original);
        assert!(!fixture.paths.launcher().exists());
        assert!(!is_registered_at(&directory, &fixture.paths.launcher()).unwrap());
    }

    #[test]
    fn broadening_allowed_origins_is_not_considered_an_owned_registration() {
        let fixture = Fixture::new();
        let directory = fixture.root.join("native-hosts");
        fixture
            .install(&directory, BrowserFamily::Chromium)
            .unwrap();
        let mut changed = manifest(&fixture.paths.launcher(), BrowserFamily::Chromium);
        changed["allowed_origins"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("chrome-extension://other/"));
        fs::write(
            manifest_path(&directory),
            serde_json::to_vec(&changed).unwrap(),
        )
        .unwrap();
        assert!(!is_registered_at(&directory, &fixture.paths.launcher()).unwrap());
        assert!(
            fixture
                .install(&directory, BrowserFamily::Chromium)
                .is_err()
        );
        assert!(
            remove_owned_manifest(&manifest_path(&directory), &fixture.paths.launcher()).is_err()
        );
    }

    #[test]
    fn foreign_or_symlinked_launcher_is_not_replaced() {
        let fixture = Fixture::new();
        let launcher = fixture.paths.launcher();
        fs::create_dir_all(launcher.parent().unwrap()).unwrap();
        fs::write(&launcher, "#!/bin/sh\necho foreign\n").unwrap();
        let directory = fixture.root.join("native-hosts");
        assert!(fixture.install(&directory, BrowserFamily::Firefox).is_err());
        assert_eq!(
            fs::read_to_string(&launcher).unwrap(),
            "#!/bin/sh\necho foreign\n"
        );
        fs::remove_file(&launcher).unwrap();
        symlink(&fixture.boltwarden, &launcher).unwrap();
        assert!(fixture.install(&directory, BrowserFamily::Firefox).is_err());
        assert!(fs::symlink_metadata(launcher).unwrap().is_symlink());
        assert!(!manifest_path(&directory).exists());
    }

    #[test]
    fn symlinked_manifest_and_nonregular_files_are_never_replaced_or_removed() {
        let fixture = Fixture::new();
        let directory = fixture.root.join("native-hosts");
        fs::create_dir_all(&directory).unwrap();
        let outside = fixture.root.join("outside.json");
        fs::write(
            &outside,
            serde_json::to_vec(&manifest(&fixture.paths.launcher(), BrowserFamily::Firefox))
                .unwrap(),
        )
        .unwrap();
        symlink(&outside, manifest_path(&directory)).unwrap();
        assert!(fixture.install(&directory, BrowserFamily::Firefox).is_err());
        assert!(
            remove_owned_manifest(&manifest_path(&directory), &fixture.paths.launcher()).is_err()
        );
        assert!(outside.exists());
        assert!(!is_registered_at(&directory, &fixture.paths.launcher()).unwrap());
        fs::remove_file(manifest_path(&directory)).unwrap();
        fs::create_dir(manifest_path(&directory)).unwrap();
        assert!(fixture.install(&directory, BrowserFamily::Firefox).is_err());
    }

    #[test]
    fn invalid_executables_and_relative_directories_fail_before_writes() {
        let fixture = Fixture::new();
        assert!(validate_executable(Path::new("relative/browser")).is_err());
        assert!(validate_executable(&fixture.root.join("missing")).is_err());
        assert!(validate_executable(&fixture.binaries).is_err());
        assert!(normalize_native_host_dir(Path::new("relative/native-hosts")).is_err());
        assert!(
            fixture
                .install(Path::new("relative/native-hosts"), BrowserFamily::Firefox)
                .is_err()
        );
        assert!(!fixture.paths.launcher().exists());
        assert!(launcher_binary(b"#!/bin/sh\n# Installed by Boltwarden browser integration.\nexec '/binary'; touch /tmp/injected native-host \"$@\"\n").is_none());
    }

    #[test]
    fn integration_files_owned_by_another_uid_are_rejected() {
        // This machine-independent fixture is read-only. Root owns /etc/passwd on Unix systems.
        let path = Path::new("/etc/passwd");
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if metadata.uid() != crate::unix_socket::current_uid() {
            assert_eq!(
                read_owned(path).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn normalized_directories_deduplicate_aliases_without_losing_symlink_parent_semantics() {
        let fixture = Fixture::new();
        let parent = fixture.root.join("actual");
        let target = parent.join("profile-data");
        fs::create_dir_all(&target).unwrap();
        let alias = fixture.root.join("browser-link");
        symlink(&target, &alias).unwrap();
        assert_eq!(
            normalize_native_host_dir(&alias.join("./NativeMessagingHosts")).unwrap(),
            normalize_native_host_dir(&target.join("NativeMessagingHosts")).unwrap()
        );
        assert_eq!(
            normalize_native_host_dir(&alias.join("../NativeMessagingHosts")).unwrap(),
            parent.join("NativeMessagingHosts")
        );
        assert!(!parent.join("NativeMessagingHosts").exists());
        assert!(!target.join("NativeMessagingHosts").exists());
    }

    #[test]
    fn normalization_handles_missing_suffixes_and_refuses_files_and_dangling_links() {
        let fixture = Fixture::new();
        let path = fixture
            .root
            .join("missing/./child/../../NativeMessagingHosts");
        assert_eq!(
            normalize_native_host_dir(&path).unwrap(),
            fixture.root.join("NativeMessagingHosts")
        );
        assert!(!fixture.root.join("missing").exists());
        assert!(normalize_native_host_dir(&fixture.boltwarden.join("..")).is_err());
        let dangling = fixture.root.join("dangling");
        symlink(fixture.root.join("nonexistent"), &dangling).unwrap();
        assert!(normalize_native_host_dir(&dangling.join("NativeMessagingHosts")).is_err());
    }
}
