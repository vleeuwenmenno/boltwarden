//! WebAuthn encoding for the supported top-level HTTPS, ES256 credential profile.
//!
//! Callers must obtain explicit desktop consent and any required verification before calling
//! the cryptographic operations, and persist a new credential/counter before
//! releasing its response. Private keys never appear in wire response types.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDescriptor {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub transports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetOptions {
    pub challenge: String,
    #[serde(default)]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub allow_credentials: Vec<CredentialDescriptor>,
    pub user_verification: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpEntity {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialParameter {
    #[serde(rename = "type")]
    pub kind: String,
    pub alg: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOptions {
    pub challenge: String,
    pub rp: RpEntity,
    pub user: UserEntity,
    pub pub_key_cred_params: Vec<CredentialParameter>,
    #[serde(default)]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    pub resident_key: String,
    pub user_verification: String,
    #[serde(default)]
    pub cred_props: bool,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PasskeyResult {
    pub kind: String,
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_object: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_algorithm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    pub document_id: String,
    pub epoch: u64,
}

#[derive(Debug, Clone)]
pub struct ValidatedRequest {
    pub requires_user_verification: bool,
    pub origin: String,
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct PasskeyError {
    pub name: &'static str,
    pub message: &'static str,
}

impl std::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for PasskeyError {}

const INVALID: PasskeyError = PasskeyError {
    name: "DataError",
    message: "Invalid passkey request.",
};
const SECURITY: PasskeyError = PasskeyError {
    name: "SecurityError",
    message: "This page cannot use that passkey relying party.",
};
const UNSUPPORTED: PasskeyError = PasskeyError {
    name: "NotSupportedError",
    message: "This passkey format is not supported by Boltwarden.",
};
const CRYPTO: PasskeyError = PasskeyError {
    name: "OperationError",
    message: "The passkey cryptographic operation failed.",
};

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Wire and Bitwarden key encodings are canonical, unpadded base64url.
pub fn decode(text: &str, max: usize) -> Result<Vec<u8>, PasskeyError> {
    if text.len() > max.saturating_mul(4).div_ceil(3) {
        return Err(INVALID);
    }
    let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| INVALID)?;
    if bytes.len() > max || encode(&bytes) != text {
        return Err(INVALID);
    }
    Ok(bytes)
}

/// Bitwarden's UUID is network-order UUID bytes, not Microsoft GUID byte order.
pub fn credential_id(value: &str) -> Result<Vec<u8>, PasskeyError> {
    let bytes = if let Some(value) = value.strip_prefix("b64.") {
        decode(value, 1023)?
    } else {
        let id = uuid::Uuid::parse_str(value).map_err(|_| UNSUPPORTED)?;
        if id.hyphenated().to_string() != value.to_ascii_lowercase() {
            return Err(UNSUPPORTED);
        }
        id.as_bytes().to_vec()
    };
    if bytes.is_empty() {
        return Err(UNSUPPORTED);
    }
    Ok(bytes)
}

fn validate_context(
    top: &str,
    frame: &str,
    rp: Option<&str>,
    challenge: &str,
    timeout_ms: u64,
    requires_user_verification: bool,
) -> Result<ValidatedRequest, PasskeyError> {
    let top = crate::uri_match::page_url(top).ok_or(SECURITY)?;
    let frame = crate::uri_match::page_url(frame).ok_or(SECURITY)?;
    // The extension also enforces frameId == 0 with browser-owned metadata.
    if top != frame || frame.scheme() != "https" {
        return Err(SECURITY);
    }
    let url::Host::Domain(host) = frame.host().ok_or(SECURITY)? else {
        return Err(SECURITY);
    };
    if host.ends_with('.') {
        return Err(SECURITY);
    }
    let rp = rp.unwrap_or(host);
    if rp.is_empty()
        || rp.len() > 253
        || !rp.is_ascii()
        || rp.ends_with('.')
        || rp.starts_with('.')
        || rp.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(SECURITY);
    }
    // Do not silently alter an explicit RP ID: its exact bytes are hashed.
    if rp.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(SECURITY);
    }
    let rp = rp.to_owned();
    if host != rp && !host.ends_with(&format!(".{rp}")) {
        return Err(SECURITY);
    }
    if rp != "localhost" && psl::domain_str(&rp).is_none() {
        return Err(SECURITY);
    }
    let challenge = decode(challenge, 1024)?;
    if challenge.is_empty() || !(1..=60_000).contains(&timeout_ms) {
        return Err(INVALID);
    }
    Ok(ValidatedRequest {
        requires_user_verification,
        origin: frame.origin().ascii_serialization(),
        rp_id: rp,
        challenge,
        timeout_ms,
    })
}

fn validate_verification(value: &str) -> Result<(), PasskeyError> {
    if matches!(value, "required" | "preferred" | "discouraged") {
        Ok(())
    } else {
        Err(INVALID)
    }
}

fn validate_descriptors(items: &[CredentialDescriptor]) -> Result<(), PasskeyError> {
    if items.len() > 64 {
        return Err(INVALID);
    }
    for item in items {
        if item.kind != "public-key"
            || decode(&item.id, 1023)?.is_empty()
            || item.transports.len() > 16
            || item.transports.iter().any(|s| s.len() > 64)
        {
            return Err(INVALID);
        }
    }
    Ok(())
}

pub fn validate_get(
    top: &str,
    frame: &str,
    options: &GetOptions,
) -> Result<ValidatedRequest, PasskeyError> {
    validate_verification(&options.user_verification)?;
    validate_descriptors(&options.allow_credentials)?;
    validate_context(
        top,
        frame,
        options.rp_id.as_deref(),
        &options.challenge,
        options.timeout_ms,
        options.user_verification == "required",
    )
}

pub fn validate_create(
    top: &str,
    frame: &str,
    options: &CreateOptions,
) -> Result<ValidatedRequest, PasskeyError> {
    validate_verification(&options.user_verification)?;
    validate_descriptors(&options.exclude_credentials)?;
    if !matches!(
        options.resident_key.as_str(),
        "required" | "preferred" | "discouraged"
    ) {
        return Err(INVALID);
    }
    if options.pub_key_cred_params.is_empty()
        || options.pub_key_cred_params.len() > 32
        || options
            .pub_key_cred_params
            .iter()
            .any(|p| p.kind != "public-key")
    {
        return Err(INVALID);
    }
    if !options.pub_key_cred_params.iter().any(|p| p.alg == -7) {
        return Err(UNSUPPORTED);
    }
    for value in [
        &options.rp.name,
        &options.user.name,
        &options.user.display_name,
    ] {
        if value.len() > 256 || value.chars().any(char::is_control) {
            return Err(INVALID);
        }
    }
    if decode(&options.user.id, 64)?.is_empty() {
        return Err(INVALID);
    }
    validate_context(
        top,
        frame,
        options.rp.id.as_deref(),
        &options.challenge,
        options.timeout_ms,
        options.user_verification == "required",
    )
}

fn client_data(request: &ValidatedRequest, kind: &str) -> Result<Vec<u8>, PasskeyError> {
    #[derive(Serialize)]
    struct ClientData<'a> {
        #[serde(rename = "type")]
        kind: &'a str,
        challenge: String,
        origin: &'a str,
        #[serde(rename = "crossOrigin")]
        cross_origin: bool,
    }
    serde_json::to_vec(&ClientData {
        kind,
        challenge: encode(&request.challenge),
        origin: &request.origin,
        cross_origin: false,
    })
    .map_err(|_| CRYPTO)
}

fn authenticator_data(rp: &str, counter: u32, attested: bool, user_verified: bool) -> Vec<u8> {
    let mut bytes = Sha256::digest(rp.as_bytes()).to_vec();
    // Explicit consent establishes UP. The daemon supplies UV from a fresh password
    // or an explicitly permitted verified vault unlock. Syncable keys retain BE=BS=1.
    bytes.push(0x19 | if user_verified { 0x04 } else { 0 } | if attested { 0x40 } else { 0 });
    bytes.extend_from_slice(&counter.to_be_bytes());
    bytes
}

pub fn sign_assertion(
    request: &ValidatedRequest,
    id: &[u8],
    user_handle: Option<&[u8]>,
    pkcs8_der: &[u8],
    counter: u32,
    user_verified: bool,
) -> Result<PasskeyResult, PasskeyError> {
    if id.is_empty() || id.len() > 1023 || user_handle.is_some_and(|u| u.is_empty() || u.len() > 64)
    {
        return Err(INVALID);
    }
    if request.requires_user_verification && !user_verified {
        return Err(PasskeyError {
            name: "NotAllowedError",
            message: "User verification is required.",
        });
    }
    let key = SigningKey::from_pkcs8_der(pkcs8_der).map_err(|_| UNSUPPORTED)?;
    let client = client_data(request, "webauthn.get")?;
    let auth = authenticator_data(&request.rp_id, counter, false, user_verified);
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(&client));
    let signature: Signature = key.try_sign(&signed).map_err(|_| CRYPTO)?;
    Ok(PasskeyResult {
        kind: "get".into(),
        credential_id: encode(id),
        client_data_json: encode(&client),
        authenticator_data: encode(&auth),
        signature: Some(encode(signature.to_der().as_bytes())),
        user_handle: user_handle.map(encode),
        ..Default::default()
    })
}

pub struct GeneratedCredential {
    pub credential_id: Vec<u8>,
    pub pkcs8_der: Zeroizing<Vec<u8>>,
    pub response: PasskeyResult,
}

pub fn generate_credential(
    request: &ValidatedRequest,
    options: &CreateOptions,
    user_verified: bool,
) -> Result<GeneratedCredential, PasskeyError> {
    if (request.requires_user_verification || options.user_verification == "required")
        && !user_verified
    {
        return Err(PasskeyError {
            name: "NotAllowedError",
            message: "User verification is required.",
        });
    }
    let key = loop {
        let random = Zeroizing::new(crate::random::random_bytes::<32>().map_err(|_| CRYPTO)?);
        if let Ok(key) = SigningKey::from_slice(random.as_ref()) {
            break key;
        }
    };
    let pkcs8_der = Zeroizing::new(key.to_pkcs8_der().map_err(|_| CRYPTO)?.as_bytes().to_vec());
    let id = uuid::Uuid::new_v4().as_bytes().to_vec();
    let point = key.verifying_key().to_sec1_point(false);
    let client = client_data(request, "webauthn.create")?;
    let mut auth = authenticator_data(&request.rp_id, 0, true, user_verified);
    auth.extend_from_slice(&[0; 16]); // Privacy-preserving AAGUID for none attestation.
    auth.extend_from_slice(&(id.len() as u16).to_be_bytes());
    auth.extend_from_slice(&id);
    // COSE EC2 key: {1:2, 3:-7, -1:1, -2:x, -3:y}, RFC 9053 ES256/P-256.
    auth.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]);
    cbor_bytes(&mut auth, point.x().ok_or(CRYPTO)?);
    auth.push(0x22);
    cbor_bytes(&mut auth, point.y().ok_or(CRYPTO)?);
    let mut attestation = vec![0xa3];
    cbor_text(&mut attestation, "fmt");
    cbor_text(&mut attestation, "none");
    cbor_text(&mut attestation, "attStmt");
    attestation.push(0xa0);
    cbor_text(&mut attestation, "authData");
    cbor_bytes(&mut attestation, &auth);
    let response = PasskeyResult {
        kind: "create".into(),
        credential_id: encode(&id),
        client_data_json: encode(&client),
        authenticator_data: encode(&auth),
        attestation_object: Some(encode(&attestation)),
        public_key: Some(encode(
            key.verifying_key()
                .to_public_key_der()
                .map_err(|_| CRYPTO)?
                .as_bytes(),
        )),
        public_key_algorithm: Some(-7),
        transports: Some(vec!["internal".into()]),
        cred_props: options.cred_props.then_some(true),
        ..Default::default()
    };
    Ok(GeneratedCredential {
        credential_id: id,
        pkcs8_der,
        response,
    })
}

fn cbor_head(out: &mut Vec<u8>, major: u8, n: usize) {
    if n < 24 {
        out.push(major | n as u8);
    } else if n <= 255 {
        out.extend_from_slice(&[major | 24, n as u8]);
    } else {
        out.push(major | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    }
}
fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_head(out, 0x40, bytes.len());
    out.extend_from_slice(bytes);
}
fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_head(out, 0x60, text.len());
    out.extend_from_slice(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{VerifyingKey, signature::Verifier};
    use p256::pkcs8::DecodePublicKey;

    fn get(rp: Option<&str>) -> GetOptions {
        GetOptions {
            challenge: encode(b"synthetic challenge"),
            rp_id: rp.map(str::to_owned),
            allow_credentials: vec![],
            user_verification: "required".into(),
            timeout_ms: 60_000,
        }
    }

    #[test]
    fn relying_party_is_bound_to_https_top_level_domain() {
        for (url, rp) in [
            ("https://login.example.com:8443/a", "example.com"),
            ("https://example.com", "example.com"),
            ("https://localhost:9443", "localhost"),
            ("https://xn--bcher-kva.de", "xn--bcher-kva.de"),
            ("https://alice.github.io", "alice.github.io"),
        ] {
            let validated = validate_get(url, url, &get(Some(rp))).unwrap();
            assert_eq!(validated.rp_id, rp);
        }
        for (url, rp) in [
            ("https://evil-example.com", "example.com"),
            ("https://example.com.evil.test", "example.com"),
            ("https://example.com", "com"),
            ("https://alice.github.io", "github.io"),
            ("https://login.example.com", "EXAMPLE.COM"),
            ("https://example.com", "example.com."),
            ("https://example.com.", "example.com"),
            ("https://127.0.0.1", "127.0.0.1"),
            ("http://localhost", "localhost"),
            ("https://example.com", "unrelated.test"),
        ] {
            assert!(
                validate_get(url, url, &get(Some(rp))).is_err(),
                "{url} / {rp}"
            );
        }
        assert!(
            validate_get("https://example.com/a", "https://example.com/b", &get(None)).is_err()
        );
        let request = validate_get(
            "https://example.com:8443/path",
            "https://example.com:8443/path",
            &get(None),
        )
        .unwrap();
        assert_eq!(request.origin, "https://example.com:8443");
    }

    #[test]
    fn canonical_identifiers_and_bounded_requests() {
        assert_eq!(
            credential_id("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            (0..16).map(|i| i * 17).collect::<Vec<u8>>()
        );
        assert_eq!(credential_id("b64.AQID").unwrap(), [1, 2, 3]);
        for id in ["b64.", "b64.AQ==", "00112233445566778899aabbccddeeff"] {
            assert!(credential_id(id).is_err());
        }
        assert!(decode("AR", 1).is_err()); // Non-zero discarded padding bits.
        let url = "https://example.com";
        let mut options = get(None);
        for challenge in ["".into(), "AQ==".into(), encode(&[0; 1025])] {
            options.challenge = challenge;
            assert!(validate_get(url, url, &options).is_err());
        }
        options = get(None);
        options.timeout_ms = 60_001;
        assert!(validate_get(url, url, &options).is_err());
        options = get(None);
        options.allow_credentials = vec![
            CredentialDescriptor {
                kind: "public-key".into(),
                id: "AQ".into(),
                transports: vec![]
            };
            65
        ];
        assert!(validate_get(url, url, &options).is_err());
        assert!(serde_json::from_value::<GetOptions>(serde_json::json!({"challenge":"AQ","user_verification":"required","timeout_ms":1000,"origin":"https://evil.test"})).is_err());
    }

    #[test]
    fn generated_credential_registers_and_signs_with_verifiable_public_key() {
        let options = CreateOptions {
            challenge: encode(b"registration challenge"),
            rp: RpEntity {
                id: Some("example.com".into()),
                name: "Example".into(),
            },
            user: UserEntity {
                id: encode(b"account id"),
                name: "alice".into(),
                display_name: "Alice".into(),
            },
            pub_key_cred_params: vec![CredentialParameter {
                kind: "public-key".into(),
                alg: -7,
            }],
            exclude_credentials: vec![],
            resident_key: "required".into(),
            user_verification: "required".into(),
            cred_props: true,
            timeout_ms: 60_000,
        };
        let request =
            validate_create("https://example.com", "https://example.com", &options).unwrap();
        let generated = generate_credential(&request, &options, true).unwrap();
        let response = &generated.response;
        let auth = decode(&response.authenticator_data, 1024).unwrap();
        assert_eq!(&auth[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(auth[32], 0x5d);
        assert_eq!(&auth[33..37], &[0; 4]);
        assert_eq!(&auth[37..53], &[0; 16]);
        assert_eq!(&auth[53..55], &[0, 16]);
        assert_eq!(&auth[55..71], generated.credential_id);
        assert_eq!(response.cred_props, Some(true));
        let assertion = sign_assertion(
            &request,
            &generated.credential_id,
            Some(b"account id"),
            &generated.pkcs8_der,
            0,
            true,
        )
        .unwrap();
        let public = decode(response.public_key.as_ref().unwrap(), 1024).unwrap();
        let verifying = VerifyingKey::from_public_key_der(&public).unwrap();
        let client = decode(&assertion.client_data_json, 1024).unwrap();
        let client_json: serde_json::Value = serde_json::from_slice(&client).unwrap();
        assert_eq!(
            client_json,
            serde_json::json!({"type":"webauthn.get", "challenge":options.challenge,"origin":"https://example.com", "crossOrigin":false})
        );
        let mut signed = decode(&assertion.authenticator_data, 1024).unwrap();
        assert_eq!(signed[32], 0x1d);
        signed.extend_from_slice(&Sha256::digest(&client));
        let signature =
            Signature::from_der(&decode(assertion.signature.as_ref().unwrap(), 1024).unwrap())
                .unwrap();
        verifying.verify(&signed, &signature).unwrap();
        signed[0] ^= 1;
        assert!(verifying.verify(&signed, &signature).is_err());
        // Optional synthetic artifact for the independent Node/OpenSSL verifier.
        if let Some(path) = std::env::var_os("BOLTWARDEN_PASSKEY_TEST_OUTPUT") {
            let mut approval_options = options.clone();
            approval_options.user_verification = "preferred".into();
            let approval_request = validate_create(
                "https://example.com",
                "https://example.com",
                &approval_options,
            )
            .unwrap();
            let approval_only =
                generate_credential(&approval_request, &approval_options, false).unwrap();
            let approval_assertion = sign_assertion(
                &approval_request,
                &approval_only.credential_id,
                Some(b"account id"),
                &approval_only.pkcs8_der,
                0,
                false,
            )
            .unwrap();
            std::fs::write(
                path,
                serde_json::to_vec(&serde_json::json!({
                    "synthetic_test_fixture": true,
                    "registration": response,
                    "assertion": assertion,
                    "approval_only_registration": approval_only.response,
                    "approval_only_assertion": approval_assertion,
                    // Fresh random test key; never read from a vault or wire response.
                    "pkcs8_der": encode(&generated.pkcs8_der),
                }))
                .unwrap(),
            )
            .unwrap();
        }
    }
    #[test]
    fn approval_only_assertions_sign_uv_false_and_required_verification_cannot_be_skipped() {
        let mut options: CreateOptions = serde_json::from_value(serde_json::json!({
            "challenge": encode(b"approval-only challenge"),
            "rp": {"id":"example.com", "name":"Example"},
            "user": {"id":encode(b"account id"), "name":"alice", "display_name":"Alice"},
            "pub_key_cred_params":[{"type":"public-key", "alg":-7}],
            "exclude_credentials":[], "resident_key":"required", "user_verification":"preferred",
            "cred_props":true, "timeout_ms":60000
        }))
        .unwrap();
        for preference in ["preferred", "discouraged"] {
            options.user_verification = preference.into();
            let request =
                validate_create("https://example.com", "https://example.com", &options).unwrap();
            let generated = generate_credential(&request, &options, false).unwrap();
            let auth = decode(&generated.response.authenticator_data, 1024).unwrap();
            assert_eq!(
                auth[32], 0x59,
                "UP, BE, BS and AT are retained, UV is not asserted"
            );
            let assertion = sign_assertion(
                &request,
                &generated.credential_id,
                Some(b"account id"),
                &generated.pkcs8_der,
                0,
                false,
            )
            .unwrap();
            let public = VerifyingKey::from_public_key_der(
                &decode(generated.response.public_key.as_ref().unwrap(), 1024).unwrap(),
            )
            .unwrap();
            let mut signed = decode(&assertion.authenticator_data, 1024).unwrap();
            assert_eq!(signed[32], 0x19);
            signed.extend_from_slice(&Sha256::digest(
                decode(&assertion.client_data_json, 4096).unwrap(),
            ));
            let signature =
                Signature::from_der(&decode(assertion.signature.as_ref().unwrap(), 1024).unwrap())
                    .unwrap();
            public.verify(&signed, &signature).unwrap();
            signed[32] |= 0x04;
            assert!(
                public.verify(&signed, &signature).is_err(),
                "UV cannot be added to an approval-only assertion"
            );
            let required =
                validate_get("https://example.com", "https://example.com", &get(None)).unwrap();
            assert_eq!(
                sign_assertion(
                    &required,
                    &generated.credential_id,
                    None,
                    &generated.pkcs8_der,
                    0,
                    false
                )
                .unwrap_err()
                .name,
                "NotAllowedError"
            );
            options.user_verification = "required".into();
            assert_eq!(
                generate_credential(&request, &options, false)
                    .err()
                    .unwrap()
                    .name,
                "NotAllowedError"
            );
            let required =
                validate_create("https://example.com", "https://example.com", &options).unwrap();
            assert_eq!(
                generate_credential(&required, &options, false)
                    .err()
                    .unwrap()
                    .name,
                "NotAllowedError"
            );
        }
    }
}
