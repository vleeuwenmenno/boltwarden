//! Account-bound encrypted snapshots. Only the format version is stored in plaintext.
use crate::bw::{BwError, decrypt_bytes, encrypt_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use zeroize::Zeroizing;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub synced_at_unix: u64,
    pub profile: Option<Value>,
    pub folders: Vec<Value>,
    pub ciphers: Vec<Value>,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u32,
    data: String,
}

fn storage_key(user_key: &[u8], server: &str, email: &str) -> Result<Zeroizing<[u8; 64]>, BwError> {
    let context = serde_json::to_vec(&(server, email)).map_err(parse_error)?;
    let kdf = hkdf::Hkdf::<Sha256>::new(Some(b"boltwarden/vault-cache/v1"), user_key);
    let mut key = Zeroizing::new([0; 64]);
    kdf.expand(&context, key.as_mut())
        .map_err(|_| BwError::Parse("Cache key derivation failed".into()))?;
    Ok(key)
}

fn parse_error(error: serde_json::Error) -> BwError {
    BwError::Parse(error.to_string())
}

pub(crate) fn encode(
    snapshot: &Snapshot,
    user_key: &[u8],
    server: &str,
    email: &str,
) -> Result<Vec<u8>, BwError> {
    let key = storage_key(user_key, server, email)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(snapshot).map_err(parse_error)?);
    let envelope = Envelope {
        version: 1,
        data: encrypt_bytes(&plaintext, key.as_ref())?,
    };
    serde_json::to_vec(&envelope).map_err(parse_error)
}

pub(crate) fn decode(
    data: &str,
    user_key: &[u8],
    server: &str,
    email: &str,
) -> Result<Snapshot, BwError> {
    let envelope: Envelope = serde_json::from_str(data).map_err(parse_error)?;
    // Reject unauthenticated encryption types even if the generic vault decoder supports them.
    if envelope.version != 1 || !envelope.data.starts_with("2.") {
        return Err(BwError::Parse("Unsupported offline cache format".into()));
    }
    let key = storage_key(user_key, server, email)?;
    let plaintext = Zeroizing::new(decrypt_bytes(&envelope.data, key.as_ref())?);
    serde_json::from_slice(&plaintext).map_err(parse_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn snapshot_is_authenticated_and_account_bound() {
        let snapshot = Snapshot {
            synced_at_unix: 123,
            profile: Some(json!({"organizations": []})),
            folders: vec![],
            ciphers: vec![json!({"unknown": "preserved"})],
        };
        let bytes = encode(&snapshot, &[7; 64], "https://vault.test", "user@test").unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("preserved"));
        let decoded = decode(&text, &[7; 64], "https://vault.test", "user@test").unwrap();
        assert_eq!(decoded.ciphers, snapshot.ciphers);
        assert_eq!(decoded.synced_at_unix, 123);
        assert!(decode(&text, &[8; 64], "https://vault.test", "user@test").is_err());
        assert!(decode(&text, &[7; 64], "https://other.test", "user@test").is_err());
        assert!(decode(&text, &[7; 64], "https://vault.test", "other@test").is_err());
        let mut envelope: Envelope = serde_json::from_str(&text).unwrap();
        envelope.data.replace_range(
            2..3,
            if &envelope.data[2..3] == "A" {
                "B"
            } else {
                "A"
            },
        );
        assert!(
            decode(
                &serde_json::to_string(&envelope).unwrap(),
                &[7; 64],
                "https://vault.test",
                "user@test"
            )
            .is_err()
        );
        envelope.version = 2;
        assert!(
            decode(
                &serde_json::to_string(&envelope).unwrap(),
                &[7; 64],
                "https://vault.test",
                "user@test"
            )
            .is_err()
        );
    }
}
