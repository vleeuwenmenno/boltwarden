//! Public pairing identities. The user's account and browser profile remain trusted.
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRecord {
    pub id: String,
    pub label: String,
    pub public_key_spki: String,
    pub fingerprint: String,
    pub created_at: u64,
    pub last_seen_at: u64,
}

#[derive(Debug, Clone)]
pub struct PairingRequest {
    pub pairing_id: String,
    pub label: String,
    pub public_key_spki: String,
    pub fingerprint: String,
}

pub struct PairingStore {
    path: PathBuf,
    records: Vec<PairingRecord>,
}

impl PairingStore {
    pub fn load() -> io::Result<Self> {
        let path = crate::config::config_path("browsers.json").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Config directory unavailable")
        })?;
        Self::load_at(path)
    }
    pub(super) fn load_at(path: PathBuf) -> io::Result<Self> {
        let records = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                #[cfg(windows)]
                crate::platform::windows::verify_private(&path)?;
                #[cfg(unix)]
                if !metadata.is_file()
                    || metadata.uid() != crate::unix_socket::current_uid()
                    || metadata.mode() & 0o077 != 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Pairing store must be an owner-only regular file",
                    ));
                }
                if metadata.len() > 64 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Pairing store is too large",
                    ));
                }
                let records: Vec<PairingRecord> =
                    serde_json::from_slice(&fs::read(&path)?).map_err(io::Error::other)?;
                if records.len() > 32
                    || records.iter().any(|r| {
                        uuid::Uuid::parse_str(&r.id).is_err()
                            || r.public_key_spki.len() > 512
                            || r.label.len() > 100
                    })
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Pairing store contains invalid records",
                    ));
                }
                records
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(Self { path, records })
    }
    pub fn list(&self) -> Vec<PairingRecord> {
        self.records.clone()
    }
    pub fn get(&self, id: &str) -> Option<PairingRecord> {
        self.records.iter().find(|p| p.id == id).cloned()
    }
    pub fn insert(&mut self, pending: &PairingRequest) -> io::Result<()> {
        if self.records.len() >= 32 {
            return Err(io::Error::other("At most 32 browsers can be paired"));
        }
        if self.get(&pending.pairing_id).is_some() {
            return Err(io::Error::other("Pairing already exists"));
        }
        let mut next = self.records.clone();
        let now = unix_seconds();
        next.push(PairingRecord {
            id: pending.pairing_id.clone(),
            label: pending.label.clone(),
            public_key_spki: pending.public_key_spki.clone(),
            fingerprint: pending.fingerprint.clone(),
            created_at: now,
            last_seen_at: now,
        });
        self.persist(&next)?;
        self.records = next;
        Ok(())
    }
    pub fn revoke(&mut self, id: &str) -> io::Result<()> {
        let mut next = self.records.clone();
        next.retain(|r| r.id != id);
        self.persist(&next)?;
        self.records = next;
        Ok(())
    }
    /// The last successful authenticated connection, not a continuous activity timestamp.
    pub(super) fn record_authenticated(&mut self, id: &str) -> io::Result<()> {
        self.record_authenticated_at(id, unix_seconds())
    }
    fn record_authenticated_at(&mut self, id: &str, at: u64) -> io::Result<()> {
        let mut next = self.records.clone();
        let record = next
            .iter_mut()
            .find(|record| record.id == id)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "Pairing is unknown or revoked")
            })?;
        if at <= record.last_seen_at {
            return Ok(());
        }
        record.last_seen_at = at;
        self.persist(&next)?;
        self.records = next;
        Ok(())
    }
    fn persist(&self, records: &[PairingRecord]) -> io::Result<()> {
        write_private(
            &self.path,
            &serde_json::to_vec_pretty(records).map_err(io::Error::other)?,
        )
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn fingerprint(spki: &str) -> Result<String, String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let der = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(spki)
        .map_err(|_| "Invalid public key encoding")?;
    let digest = Sha256::digest(der);
    Ok(digest
        .as_slice()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| format!("{:02X}{:02X}", bytes[0], bytes[1]))
        .collect::<Vec<_>>()
        .join(":"))
}

#[cfg(windows)]
fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    crate::platform::windows::write_private(path, data)
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("Missing config directory"))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let temp = parent.join(format!(".browsers.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn records_are_private_durable_and_revocable() {
        let dir = std::env::temp_dir().join(format!("boltwarden-pairing-{}", uuid::Uuid::new_v4()));
        let path = dir.join("browsers.json");
        let mut store = PairingStore::load_at(path.clone()).unwrap();
        let pending = PairingRequest {
            pairing_id: uuid::Uuid::new_v4().to_string(),
            label: "Firefox".into(),
            public_key_spki: "key".into(),
            fingerprint: "fingerprint".into(),
        };
        store.insert(&pending).unwrap();
        #[cfg(unix)]
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        #[cfg(windows)]
        crate::platform::windows::verify_private(&path).unwrap();
        assert_eq!(PairingStore::load_at(path.clone()).unwrap().list().len(), 1);
        store.revoke(&pending.pairing_id).unwrap();
        assert!(PairingStore::load_at(path).unwrap().list().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    #[cfg(unix)]
    fn refuses_symlink_trust_store() {
        let dir = std::env::temp_dir().join(format!("boltwarden-pairing-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("browsers.json");
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert!(PairingStore::load_at(path).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn authentication_timestamp_is_durable_monotonic_and_cannot_restore_revoked_trust() {
        let dir = std::env::temp_dir().join(format!("boltwarden-pairing-{}", uuid::Uuid::new_v4()));
        let path = dir.join("browsers.json");
        let mut store = PairingStore::load_at(path.clone()).unwrap();
        let pending = PairingRequest {
            pairing_id: uuid::Uuid::new_v4().to_string(),
            label: "Firefox".into(),
            public_key_spki: "key".into(),
            fingerprint: "fingerprint".into(),
        };
        store.insert(&pending).unwrap();
        let first = store.list()[0].last_seen_at;
        store
            .record_authenticated_at(&pending.pairing_id, first + 60)
            .unwrap();
        store
            .record_authenticated_at(&pending.pairing_id, first + 30)
            .unwrap();
        assert_eq!(store.list()[0].last_seen_at, first + 60);
        assert_eq!(
            PairingStore::load_at(path.clone()).unwrap().list()[0].last_seen_at,
            first + 60
        );
        store.revoke(&pending.pairing_id).unwrap();
        assert!(
            store
                .record_authenticated_at(&pending.pairing_id, first + 90)
                .is_err()
        );
        assert!(PairingStore::load_at(path).unwrap().list().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_persistence_never_reports_success_or_changes_the_in_memory_record() {
        let dir = std::env::temp_dir().join(format!("boltwarden-pairing-{}", uuid::Uuid::new_v4()));
        let path = dir.join("browsers.json");
        let mut store = PairingStore::load_at(path.clone()).unwrap();
        let pending = PairingRequest {
            pairing_id: uuid::Uuid::new_v4().to_string(),
            label: "Firefox".into(),
            public_key_spki: "key".into(),
            fingerprint: "fingerprint".into(),
        };
        store.insert(&pending).unwrap();
        let first = store.list()[0].last_seen_at;
        let blocking = dir.join("not-a-directory");
        fs::write(&blocking, b"test").unwrap();
        store.path = blocking.join("browsers.json");
        assert!(
            store
                .record_authenticated_at(&pending.pairing_id, first + 60)
                .is_err()
        );
        assert!(store.revoke(&pending.pairing_id).is_err());
        assert_eq!(store.list()[0].last_seen_at, first);
        assert_eq!(PairingStore::load_at(path).unwrap().list().len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
