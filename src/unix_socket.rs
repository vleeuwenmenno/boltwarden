//! Helpers for the daemon's private Unix sockets (activation and vault RPC).
//!
//! The sockets live in `$XDG_RUNTIME_DIR` when available. Without it we fall back to a
//! per-user directory in the system temp dir, which another local user could pre-create,
//! so every directory is checked to be owned by us and closed to group and others.

use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// Directory that holds the daemon sockets. Created with mode 0700 when missing.
pub fn runtime_dir() -> io::Result<PathBuf> {
    let dir = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(runtime_dir) => PathBuf::from(runtime_dir),
        None => {
            let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
            std::env::temp_dir().join(format!("bw-quick-access-{user}"))
        }
    };
    ensure_private_dir(&dir)?;
    Ok(dir)
}

fn ensure_private_dir(path: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    // symlink_metadata so a symlink planted in /tmp is rejected rather than followed.
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(permission_error(path, "is not a directory"));
    }
    if metadata.uid() != current_uid() {
        return Err(permission_error(path, "is not owned by the current user"));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(permission_error(
            path,
            &format!("must not be accessible by group or others (mode {:04o})", metadata.mode() & 0o777),
        ));
    }
    Ok(())
}

/// Binds a listener at `path` that only the current user can connect to. A leftover
/// socket from a previous run is removed first, but only if it is ours and really a socket.
pub fn bind_private(path: &Path) -> io::Result<UnixListener> {
    remove_stale_socket(path)?;
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub fn remove_stale_socket(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if metadata.uid() != current_uid() {
        return Err(permission_error(path, "is not owned by the current user"));
    }
    if !metadata.file_type().is_socket() {
        return Err(permission_error(path, "already exists and is not a socket"));
    }
    fs::remove_file(path)
}

/// Uid of the process on the other end of `stream`, as reported by the kernel.
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(credentials.uid)
}

pub fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn permission_error(path: &Path, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{} {reason}", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "bw-quick-access-socket-test-{}-{name}",
            uuid::Uuid::new_v4()
        ))
    }

    #[test]
    fn creates_private_dir() {
        let dir = temp_path("create");
        ensure_private_dir(&dir).unwrap();

        let mode = fs::metadata(&dir).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o700);
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn rejects_dir_open_to_others() {
        let dir = temp_path("open");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        let error = ensure_private_dir(&dir).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn rejects_symlinked_dir() {
        let target = temp_path("target");
        let link = temp_path("link");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(ensure_private_dir(&link).is_err());
        fs::remove_file(&link).unwrap();
        fs::remove_dir(&target).unwrap();
    }

    #[test]
    fn binds_socket_with_owner_only_mode_and_replaces_stale_one() {
        let dir = temp_path("bind");
        ensure_private_dir(&dir).unwrap();
        let path = dir.join("test.sock");

        drop(bind_private(&path).unwrap());
        let listener = bind_private(&path).unwrap();

        let mode = fs::symlink_metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let client = UnixStream::connect(&path).unwrap();
        assert_eq!(peer_uid(&client).unwrap(), current_uid());
        drop(listener);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_to_remove_regular_file() {
        let dir = temp_path("file");
        ensure_private_dir(&dir).unwrap();
        let path = dir.join("not-a-socket");
        fs::write(&path, b"keep me").unwrap();

        assert!(bind_private(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"keep me");
        fs::remove_dir_all(&dir).unwrap();
    }
}
