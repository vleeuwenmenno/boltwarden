//! Small Win32 primitives with explicit ownership and private security descriptors.
use std::ffi::{OsStr, c_void};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
#[cfg(not(test))]
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::{
    Foundation::*, Security::Authorization::*, Security::*, Storage::FileSystem::*,
    System::Threading::*,
};

pub fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
/// Hands an http(s) address to the default browser.
pub fn open_url(url: &str) -> io::Result<()> {
    let operation = wide("open");
    let url = wide(url);
    let result = unsafe {
        windows_sys::Win32::UI::Shell::ShellExecuteW(
            null_mut(),
            operation.as_ptr(),
            url.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW reports success with a value above 32.
    if result as usize > 32 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Could not open the browser (error {})",
            result as usize
        )))
    }
}
pub fn handle(raw: HANDLE) -> io::Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }
}
pub fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle()
}
pub fn check(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub struct LocalMemory(pub *mut c_void);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub fn process_identity(pid: u32) -> io::Result<(String, u32)> {
    let process = handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;
    let mut token = null_mut();
    check(unsafe { OpenProcessToken(raw(&process), TOKEN_QUERY, &mut token) })?;
    let token = handle(token)?;
    let mut length = 0;
    unsafe {
        GetTokenInformation(raw(&token), TokenUser, null_mut(), 0, &mut length);
    }
    // usize storage gives TOKEN_USER its required pointer alignment.
    let mut buffer = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    check(unsafe {
        GetTokenInformation(
            raw(&token),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    })?;
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let sid = sid_string(user.User.Sid)?;
    let mut session = 0u32;
    check(unsafe {
        GetTokenInformation(
            raw(&token),
            TokenSessionId,
            (&mut session as *mut u32).cast(),
            4,
            &mut length,
        )
    })?;
    Ok((sid, session))
}
fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text = null_mut();
    check(unsafe { ConvertSidToStringSidW(sid, &mut text) })?;
    let _memory = LocalMemory(text.cast());
    let mut length = 0;
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
    }
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(text, length)
    }))
}
pub fn identity() -> io::Result<(String, u32)> {
    process_identity(std::process::id())
}

pub struct PrivateSecurity(LocalMemory);
impl PrivateSecurity {
    pub fn new() -> io::Result<Self> {
        let (sid, _) = identity()?;
        let text = wide(format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)"));
        let mut descriptor = null_mut();
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        })?;
        Ok(Self(LocalMemory(descriptor)))
    }
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: 0,
        }
    }
}
#[cfg(test)]
pub fn data_dir() -> io::Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("boltwarden-unit-{}", std::process::id()))
        });
    Ok(base.join("boltwarden"))
}

#[cfg(not(test))]
pub fn data_dir() -> io::Result<PathBuf> {
    let mut path = null_mut();
    let result = unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, null_mut(), &mut path) };
    if result < 0 {
        return Err(io::Error::other(format!(
            "Local AppData unavailable: {result:#x}"
        )));
    }
    let mut length = 0;
    unsafe {
        while *path.add(length) != 0 {
            length += 1;
        }
    }
    let base = PathBuf::from(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(path, length)
    }));
    unsafe {
        windows_sys::Win32::System::Com::CoTaskMemFree(path.cast());
    }
    Ok(base.join("Boltwarden"))
}
pub fn reject_reparse(path: &Path) -> io::Result<()> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Reparse-point storage path refused",
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
/// Verify user ownership and a user/LocalSystem-only DACL; NULL is never private.
pub fn verify_private(path: &Path) -> io::Result<()> {
    reject_reparse(path)?;
    let path = wide(path);
    let mut owner = null_mut();
    let mut acl = null_mut();
    let mut descriptor = null_mut();
    let result = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let _memory = LocalMemory(descriptor);
    let (sid, _) = identity()?;
    if owner.is_null() || acl.is_null() || sid_string(owner)? != sid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Storage is not owned privately by this user",
        ));
    }
    for i in 0..unsafe { (*acl).AceCount } {
        let mut ace = null_mut();
        check(unsafe { GetAce(acl, i as u32, &mut ace) })?;
        let kind = unsafe { (*ace.cast::<ACE_HEADER>()).AceType };
        if kind == 0
        /* ACCESS_ALLOWED_ACE_TYPE */
        {
            let entry = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let grantee = sid_string((&entry.SidStart as *const u32).cast_mut().cast())?;
            // LocalSystem is the trusted OS, equivalent to root on Linux. No
            // other user/group may read or modify persisted vault state.
            if grantee != sid && grantee != "S-1-5-18" {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Storage grants access to another account: {} (mask {:#x})",
                        sid_string((&entry.SidStart as *const u32).cast_mut().cast())?,
                        entry.Mask
                    ),
                ));
            }
        } else if kind != 1
        /* ACCESS_DENIED_ACE_TYPE */
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Unsupported storage access rule",
            ));
        }
    }
    Ok(())
}
pub fn private_dir(path: &Path) -> io::Result<()> {
    reject_reparse(path)?;
    if path.exists() {
        return verify_private(path);
    }
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            private_dir(parent)?;
        }
    }
    let security = PrivateSecurity::new()?;
    let attrs = security.attributes();
    let name = wide(path);
    if unsafe { CreateDirectoryW(name.as_ptr(), &attrs) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(error);
        }
    }
    verify_private(path)
}
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("Missing storage directory"))?;
    private_dir(parent)?;
    if path.exists() {
        verify_private(path)?;
    }
    reject_reparse(path)?;
    let temp = parent.join(format!(".boltwarden-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let security = PrivateSecurity::new()?;
        let attrs = security.attributes();
        let name = wide(&temp);
        let handle = handle(unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                &attrs,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        })?;
        let mut file = std::fs::File::from(handle);
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        let target = wide(path);
        check(unsafe {
            MoveFileExW(
                name.as_ptr(),
                target.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Display-only process evidence. Pairing proofs, not executable names, authorize access.
pub fn browser_description(host_pid: u32) -> String {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    let snapshot = match handle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) {
        Ok(snapshot) => snapshot,
        Err(_) => return format!("Native host PID: {host_pid}"),
    };
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of_val(&entry) as u32;
    let mut entries = Vec::new();
    let mut found = unsafe { Process32FirstW(raw(&snapshot), &mut entry) };
    while found != 0 {
        entries.push((entry.th32ProcessID, entry.th32ParentProcessID));
        found = unsafe { Process32NextW(raw(&snapshot), &mut entry) };
    }
    let mut pid = host_pid;
    for _ in 0..6 {
        let Some((_, parent)) = entries.iter().find(|(id, _)| *id == pid) else {
            break;
        };
        if *parent == 0 || *parent == pid {
            break;
        }
        pid = *parent;
        if let Ok(process) =
            handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })
        {
            let mut path = vec![0u16; 32768];
            let mut length = path.len() as u32;
            if unsafe {
                QueryFullProcessImageNameW(raw(&process), 0, path.as_mut_ptr(), &mut length)
            } != 0
            {
                let path = String::from_utf16_lossy(&path[..length as usize]);
                let name = Path::new(&path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_ascii_lowercase();
                if matches!(name.as_str(), "chrome.exe" | "msedge.exe" | "firefox.exe") {
                    return format!("Browser process: {path} (PID {pid})");
                }
            }
        }
    }
    format!("Native host PID: {host_pid}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_writes_replace_atomically_and_keep_acl_private() {
        let directory =
            std::env::temp_dir().join(format!("boltwarden-private-{}", uuid::Uuid::new_v4()));
        let path = directory.join("test.json");
        write_private(&path, b"first").unwrap();
        verify_private(&directory).unwrap();
        verify_private(&path).unwrap();
        write_private(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        verify_private(&path).unwrap();
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn refuses_files_with_inherited_non_private_permissions() {
        let directory =
            std::env::temp_dir().join(format!("boltwarden-public-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("existing");
        std::fs::write(&path, b"untouched").unwrap();
        // Make this explicit rather than relying on the runner's default ACL.
        let output = std::process::Command::new("icacls.exe")
            .arg(&path)
            .args(["/grant", "*S-1-1-0:R"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(verify_private(&path).is_err());
        assert!(write_private(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"untouched");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
