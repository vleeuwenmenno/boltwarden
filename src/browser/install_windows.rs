//! Per-user Windows native messaging registration. No browser is launched or
//! profile inspected. Registry entries authorize discovery, never vault access.
use super::protocol::identities;
use crate::platform::windows::*;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{Foundation::*, System::Registry::*};

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
struct Browser {
    id: &'static str,
    label: &'static str,
    executable: &'static str,
    vendor: &'static str,
    family: BrowserFamily,
    directory: &'static str,
}
const BROWSERS: &[Browser] = &[
    Browser {
        id: "chrome",
        label: "Google Chrome",
        executable: "chrome.exe",
        vendor: r"Google\Chrome",
        family: BrowserFamily::Chromium,
        directory: r"Google\Chrome\Application",
    },
    Browser {
        id: "edge",
        label: "Microsoft Edge",
        executable: "msedge.exe",
        vendor: r"Microsoft\Edge",
        family: BrowserFamily::Chromium,
        directory: r"Microsoft\Edge\Application",
    },
    Browser {
        id: "firefox",
        label: "Mozilla Firefox",
        executable: "firefox.exe",
        vendor: "Mozilla",
        family: BrowserFamily::Firefox,
        directory: "Mozilla Firefox",
    },
];
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn reg_path(browser: &Browser) -> String {
    format!(
        r"Software\{}\NativeMessagingHosts\{}",
        browser.vendor,
        identities().host_name
    )
}
fn directory(browser: &Browser) -> Result<PathBuf> {
    Ok(data_dir()?.join("NativeMessagingHosts").join(browser.id))
}
fn browser_for(directory_path: &Path) -> Result<&'static Browser> {
    BROWSERS
        .iter()
        .find(|browser| directory(browser).is_ok_and(|p| p == directory_path))
        .context(
            "Choose Chrome, Edge, or Firefox; custom Windows registration paths are unsupported",
        )
}
fn registry_value(root: HKEY, path: &str, view: u32) -> io::Result<Option<String>> {
    let mut key = null_mut();
    let result = unsafe { RegOpenKeyExW(root, wide(path).as_ptr(), 0, KEY_READ | view, &mut key) };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let key = Key(key);
    let mut kind = 0;
    let mut bytes = 0;
    let result =
        unsafe { RegQueryValueExW(key.0, null(), null(), &mut kind, null_mut(), &mut bytes) };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    if kind != REG_SZ || bytes > 65536 || bytes % 2 != 0 {
        return Err(io::Error::other("Invalid native messaging registry value"));
    }
    let mut value = vec![0u16; bytes as usize / 2];
    let result = unsafe {
        RegQueryValueExW(
            key.0,
            null(),
            null(),
            &mut kind,
            value.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    while value.last() == Some(&0) {
        value.pop();
    }
    String::from_utf16(&value)
        .map(Some)
        .map_err(io::Error::other)
}
fn manifest_path(browser: &Browser) -> Result<PathBuf> {
    Ok(directory(browser)?.join(format!("{}.json", identities().host_name)))
}
fn helper(binary: Option<PathBuf>) -> Result<PathBuf> {
    let binary = binary.unwrap_or(std::env::current_exe()?);
    if !binary.is_absolute() || !binary.is_file() {
        bail!("Boltwarden path must be an absolute executable file");
    }
    let path = binary
        .parent()
        .context("Missing executable directory")?
        .join("boltwarden-native-host.exe");
    if !path.is_file() {
        bail!("boltwarden-native-host.exe must be beside boltwarden.exe");
    }
    reject_reparse(&path)?;
    Ok(path)
}
fn manifest(browser: &Browser, host: &Path) -> serde_json::Value {
    let ids = identities();
    let mut value = serde_json::json!({"name":ids.host_name, "description":"Boltwarden browser integration", "path":host, "type":"stdio"});
    match browser.family {
        BrowserFamily::Firefox => value["allowed_extensions"] = serde_json::json!([ids.firefox_id]),
        BrowserFamily::Chromium => {
            value["allowed_origins"] =
                serde_json::json!([format!("chrome-extension://{}/", ids.chrome_id)])
        }
    }
    value
}
fn check_existing(browser: &Browser, host: &Path) -> Result<bool> {
    let path = manifest_path(browser)?;
    if !path.exists() {
        return Ok(false);
    }
    verify_private(&path)?;
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() || metadata.len() > 65536 {
        bail!("Invalid native host manifest");
    }
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    if value != manifest(browser, host) {
        bail!("Native host manifest belongs to another installation; unregister it there first");
    }
    Ok(true)
}
fn check_registry(browser: &Browser) -> Result<bool> {
    let expected = manifest_path(browser)?;
    let mut found = false;
    for view in [KEY_WOW64_32KEY, KEY_WOW64_64KEY] {
        if let Some(value) = registry_value(HKEY_CURRENT_USER, &reg_path(browser), view)? {
            if Path::new(&value) != expected {
                bail!(
                    "{} registry entry belongs to another installation",
                    browser.label
                );
            }
            found = true;
        }
    }
    Ok(found)
}
fn install(browser: &Browser, host: &Path) -> Result<()> {
    check_existing(browser, host)?;
    check_registry(browser)?;
    let path = manifest_path(browser)?;
    write_private(&path, &serde_json::to_vec_pretty(&manifest(browser, host))?)?;
    let mut key = null_mut();
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            wide(reg_path(browser)).as_ptr(),
            0,
            null(),
            0,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            null(),
            &mut key,
            null_mut(),
        )
    };
    if result != 0 {
        bail!(
            "Cannot register native host: {}",
            io::Error::from_raw_os_error(result as i32)
        );
    }
    let key = Key(key);
    let value = wide(&path);
    let result = unsafe {
        RegSetValueExW(
            key.0,
            null(),
            0,
            REG_SZ,
            value.as_ptr().cast(),
            (value.len() * 2) as u32,
        )
    };
    if result != 0 {
        bail!("Cannot write native host registry value: {result}");
    }
    Ok(())
}
pub fn discover() -> Result<Vec<BrowserRegistration>> {
    BROWSERS
        .iter()
        .map(|browser| {
            let mut executable = None;
            for root in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
                let app = format!(
                    r"Software\Microsoft\Windows\CurrentVersion\App Paths\{}",
                    browser.executable
                );
                if let Some(path) = registry_value(root, &app, KEY_WOW64_64KEY)? {
                    let path = PathBuf::from(path.trim_matches('"'));
                    if path.is_file() {
                        executable = Some(path);
                        break;
                    }
                }
            }
            if executable.is_none() {
                for base in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
                    if let Some(base) = std::env::var_os(base) {
                        let path = PathBuf::from(base)
                            .join(browser.directory)
                            .join(browser.executable);
                        if path.is_file() {
                            executable = Some(path);
                            break;
                        }
                    }
                }
            }
            // Show a registration row even before a browser is installed. Registration
            // itself needs no browser executable and also supports managed installs.
            Ok(BrowserRegistration {
                id: browser.id.into(),
                label: browser.label.into(),
                executable: executable.unwrap_or_else(|| PathBuf::from(browser.executable)),
                family: browser.family,
                native_host_dir: directory(browser)?,
                registered: is_registered(&directory(browser)?)?,
            })
        })
        .collect()
}
pub fn normalize_native_host_dir(path: &Path) -> Result<PathBuf> {
    directory(browser_for(path)?)
}
pub fn default_native_host_dir(family: BrowserFamily) -> Result<PathBuf> {
    directory(if family == BrowserFamily::Firefox {
        &BROWSERS[2]
    } else {
        &BROWSERS[0]
    })
}
pub fn suggested_registration(executable: &Path) -> Option<(BrowserFamily, PathBuf)> {
    let name = executable.file_name()?.to_str()?;
    let browser = BROWSERS
        .iter()
        .find(|b| b.executable.eq_ignore_ascii_case(name))?;
    Some((browser.family, directory(browser).ok()?))
}
pub fn register(_: PathBuf, family: BrowserFamily, dir: PathBuf) -> Result<()> {
    let browser = browser_for(&dir)?;
    if family != browser.family {
        bail!("Browser family does not match registration");
    }
    install(browser, &helper(None)?)
}
pub fn unregister(dir: PathBuf) -> Result<()> {
    uninstall(browser_for(&dir)?, &helper(None)?)
}
fn uninstall(browser: &Browser, host: &Path) -> Result<()> {
    if !check_existing(browser, host)? {
        if check_registry(browser)? {
            bail!("Registered manifest is missing; refusing unverified cleanup");
        }
        return Ok(());
    }
    check_registry(browser)?;
    for view in [KEY_WOW64_32KEY, KEY_WOW64_64KEY] {
        // Recheck before deletion, and delete only our default value. Other values
        // or subkeys remain untouched.
        if registry_value(HKEY_CURRENT_USER, &reg_path(browser), view)?.is_none() {
            continue;
        }
        let mut key = null_mut();
        let result = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                wide(reg_path(browser)).as_ptr(),
                0,
                KEY_SET_VALUE | view,
                &mut key,
            )
        };
        if result != 0 {
            bail!("Cannot remove native host registration: {result}");
        }
        let key = Key(key);
        let result = unsafe { RegDeleteValueW(key.0, null()) };
        if result != 0 && result != ERROR_FILE_NOT_FOUND {
            bail!("Cannot remove native host registration: {result}");
        }
    }
    fs::remove_file(manifest_path(browser)?)?;
    Ok(())
}
pub fn is_registered(dir: &Path) -> Result<bool> {
    let browser = browser_for(dir)?;
    let host = match helper(None) {
        Ok(host) => host,
        Err(_) => return Ok(false),
    };
    Ok(check_existing(browser, &host)? && check_registry(browser)?)
}
pub fn run(args: impl IntoIterator<Item = String>) -> Result<(), String> {
    let execute = || -> Result<()> {
        let mut args = args.into_iter();
        let mut selected = "all".to_string();
        let mut remove = false;
        let mut binary = None;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--browser" => selected = args.next().context("Missing browser")?,
                "--path" => binary = Some(PathBuf::from(args.next().context("Missing path")?)),
                "--uninstall" => remove = true,
                _ => bail!("Unknown option: {arg}"),
            }
        }
        let choices: Vec<_> = BROWSERS
            .iter()
            .filter(|b| selected == "all" || selected == b.id)
            .collect();
        if choices.is_empty() {
            bail!("Choose all, chrome, edge, or firefox");
        }
        let host = helper(binary)?;
        for browser in choices {
            if remove {
                uninstall(browser, &host)?;
            } else {
                install(browser, &host)?;
            }
        }
        Ok(())
    };
    execute().map_err(|e| format!("{e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_is_idempotent_and_foreign_manifests_are_never_removed() {
        crate::config::with_test_config(|root| {
            let id = uuid::Uuid::new_v4().to_string();
            let vendor = format!(r"Boltwarden\Tests\{id}");
            let browser = Browser {
                id: "test",
                label: "Fixture",
                executable: "fixture.exe",
                vendor: Box::leak(vendor.clone().into_boxed_str()),
                family: BrowserFamily::Chromium,
                directory: "fixture",
            };
            let host = root.join("native-host.exe");
            install(&browser, &host).unwrap();
            install(&browser, &host).unwrap();
            assert!(check_registry(&browser).unwrap());
            assert!(check_existing(&browser, &host).unwrap());
            let mut foreign = manifest(&browser, &host);
            foreign["path"] = serde_json::json!(root.join("other-host.exe"));
            write_private(
                &manifest_path(&browser).unwrap(),
                &serde_json::to_vec(&foreign).unwrap(),
            )
            .unwrap();
            assert!(uninstall(&browser, &host).is_err());
            assert!(check_registry(&browser).unwrap());
            write_private(
                &manifest_path(&browser).unwrap(),
                &serde_json::to_vec(&manifest(&browser, &host)).unwrap(),
            )
            .unwrap();
            uninstall(&browser, &host).unwrap();
            uninstall(&browser, &host).unwrap();
            assert!(!check_registry(&browser).unwrap());
            unsafe {
                RegDeleteTreeW(
                    HKEY_CURRENT_USER,
                    wide(format!(r"Software\{vendor}")).as_ptr(),
                );
            }
        });
    }
    #[test]
    fn manifests_keep_exact_extension_allowlists_and_executable_paths() {
        let host = Path::new(r"C:\Users\Test User\Boltwarden\boltwarden-native-host.exe");
        let chrome = manifest(&BROWSERS[0], host);
        let edge = manifest(&BROWSERS[1], host);
        assert_eq!(chrome, edge);
        assert_eq!(chrome["path"], serde_json::json!(host));
        assert_eq!(
            chrome["allowed_origins"],
            serde_json::json!([format!("chrome-extension://{}/", identities().chrome_id)])
        );
        assert_eq!(
            manifest(&BROWSERS[2], host)["allowed_extensions"],
            serde_json::json!([identities().firefox_id])
        );
    }
}
