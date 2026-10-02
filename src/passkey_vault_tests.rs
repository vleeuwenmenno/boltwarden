//! Public synthetic interoperability data only; never load a real vault.
//!
//! The PKCS#8 test key below is published by Bitwarden in its authenticator unit
//! tests (GPL-3.0), not a user's credential:
//! https://github.com/bitwarden/clients/blob/1402df876fa11c9be454ec18ef8484121024db38/libs/common/src/platform/services/fido2/fido2-authenticator.service.spec.ts#L867
//! The UUID/base64url equivalence is their public credential-ID fixture:
//! https://github.com/bitwarden/clients/blob/1402df876fa11c9be454ec18ef8484121024db38/libs/common/src/platform/services/fido2/credential-id-utils.spec.ts
//! Independently imported using Node OpenSSL and WebCrypto, the key is 138-byte
//! PKCS#8 P-256; SHA256(der) =
//! 170d52b4347a87cec99de802bd6ce22a5e7bd58ba579c9c424e03d516083e117.
//! PUBLIC_KEY is OpenSSL's independently derived SPKI, used to verify Rust output.

use super::*;
use crate::passkeys::{self, CreateOptions, GetOptions, PasskeyResult, ValidatedRequest};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::pkcs8::DecodePublicKey;
use sha2::Digest;

const PUBLIC_TEST_KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTC-7XDZipXbaVBlnkjlBgO16ZmqBZWejK2iYo6lV0dehRANCAASOcM2WduNq1DriRYN7ZekvZz-bRhA-qNT4v0fbp5suUFJyWmgOQ0bybZcLXHaerK5Ep1JiSrQcewtQNgLtry7f";
const PUBLIC_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjnDNlnbjatQ64kWDe2XpL2c_m0YQPqjU-L9H26ebLlBSclpoDkNG8m2XC1x2nqyuRKdSYkq0HHsLUDYC7a8u3w";
const CREDENTIAL_UUID: &str = "08d70b74-e9f5-4522-a425-e5dcd40107e7";
const CREDENTIAL_B64: &str = "CNcLdOn1RSKkJeXc1AEH5w";

fn encrypted_credential(key: &[u8]) -> Value {
    let mut value = json!({
        "credentialId": CREDENTIAL_UUID,
        "keyType": "public-key",
        "keyAlgorithm": "ECDSA",
        "keyCurve": "P-256",
        "keyValue": PUBLIC_TEST_KEY,
        "rpId": "example.com",
        "userHandle": "AAECAwQFBgcICQoLDA0ODw",
        "userName": "alice@example.com",
        "userDisplayName": "Alice",
        "counter": "0",
        "rpName": "Example",
        "discoverable": "true",
    });
    for entry in value.as_object_mut().unwrap().values_mut() {
        *entry = encrypt_value(entry.as_str().unwrap(), key).unwrap();
    }
    value["creationDate"] = json!("2026-01-01T00:00:00.000Z");
    value
}

pub(super) fn fixture() -> BwClient {
    let mut client = tests::protected_fixture();
    let stored = client.ciphers.get_mut("cipher-edit").unwrap();
    stored.raw["login"]["fido2Credentials"] = json!([encrypted_credential(&stored.item_key)]);
    client.last_sync_attempt = Some(Instant::now());
    client
}

fn get_options() -> (GetOptions, ValidatedRequest) {
    let options: GetOptions = serde_json::from_value(json!({
        "challenge": "AQIDBA", "rp_id": "example.com", "allow_credentials": [],
        "user_verification": "required", "timeout_ms": 60000,
    }))
    .unwrap();
    let context = passkeys::validate_get(
        "https://example.com/login",
        "https://example.com/login",
        &options,
    )
    .unwrap();
    (options, context)
}

fn create_options() -> (CreateOptions, ValidatedRequest) {
    let options: CreateOptions = serde_json::from_value(json!({
        "challenge": "AQIDBA", "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": "AQIDBAU", "name": "alice", "display_name": "Alice"},
        "pub_key_cred_params": [{"type": "public-key", "alg": -7}],
        "exclude_credentials": [], "resident_key": "preferred", "user_verification": "required",
        "cred_props": true, "timeout_ms": 60000,
    }))
    .unwrap();
    let context = passkeys::validate_create(
        "https://example.com/register",
        "https://example.com/register",
        &options,
    )
    .unwrap();
    (options, context)
}

fn verify_assertion(result: &PasskeyResult, public_key: &str) {
    verify_assertion_uv(result, public_key, true);
}

fn verify_assertion_uv(result: &PasskeyResult, public_key: &str, user_verified: bool) {
    let public =
        VerifyingKey::from_public_key_der(&passkeys::decode(public_key, 1024).unwrap()).unwrap();
    let signature =
        Signature::from_der(&passkeys::decode(result.signature.as_ref().unwrap(), 128).unwrap())
            .unwrap();
    let mut signed = passkeys::decode(&result.authenticator_data, 1024).unwrap();
    assert_eq!(&signed[..32], &Sha256::digest(b"example.com")[..]);
    assert_eq!(
        &signed[32..],
        &[if user_verified { 0x1d } else { 0x19 }, 0, 0, 0, 0]
    );
    let client_data = passkeys::decode(&result.client_data_json, 4096).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&client_data).unwrap(),
        json!({
            "type": "webauthn.get", "challenge": "AQIDBA", "origin": "https://example.com", "crossOrigin": false,
        })
    );
    signed.extend_from_slice(&Sha256::digest(client_data));
    public.verify(&signed, &signature).unwrap();
}

#[test]
fn public_bitwarden_fixture_signs_with_independently_derived_public_key() {
    let mut client = fixture();
    let before = client.ciphers["cipher-edit"].raw.clone();
    let selected = client
        .browser_passkey_candidates("example.com", &[])
        .unwrap()
        .remove(0);
    assert_eq!(selected.credential_id, CREDENTIAL_B64);
    assert_eq!(selected.user_name.as_deref(), Some("alice@example.com"));
    let (options, context) = get_options();
    let result = client
        .browser_passkey_assert(
            &selected,
            &context,
            &options,
            PasskeyVerificationEvidence::FreshPassword,
        )
        .unwrap();
    verify_assertion(&result, PUBLIC_KEY);
    assert_eq!(
        result.user_handle.as_deref(),
        Some("AAECAwQFBgcICQoLDA0ODw")
    );
    assert_eq!(
        client.ciphers["cipher-edit"].raw, before,
        "zero-counter assertion must never mutate a cipher"
    );
    assert!(
        client.item_grants.is_empty(),
        "passkeys must not grant desktop item access"
    );
    let result_json = serde_json::to_string(&result).unwrap();
    assert!(!result_json.contains(PUBLIC_TEST_KEY));
    assert!(!result_json.contains("keyValue"));
    assert!(matches!(
        client.get_item("cipher-edit"),
        Err(BwError::RepromptRequired)
    ));
}

#[test]
fn zero_counter_assertion_works_offline_but_creation_requires_online() {
    let mut client = fixture();
    client.browser_test_use_offline_session();
    let selected = client
        .browser_passkey_candidates("example.com", &[])
        .unwrap()
        .remove(0);
    let (options, context) = get_options();
    verify_assertion(
        &client
            .browser_passkey_assert(
                &selected,
                &context,
                &options,
                PasskeyVerificationEvidence::FreshPassword,
            )
            .unwrap(),
        PUBLIC_KEY,
    );
    assert!(client.browser_passkey_can_create().is_err());
    let (options, context) = create_options();
    assert!(
        client
            .browser_passkey_create(
                &context,
                &options,
                PasskeyVerificationEvidence::FreshPassword
            )
            .is_err()
    );
}

#[test]
fn refuses_unsupported_counters_algorithms_keys_and_malformed_metadata_before_approval() {
    for (field, value) in [
        ("counter", "1"),
        ("counter", "-1"),
        ("counter", "4294967296"),
        ("counter", "garbage"),
        ("keyType", "other"),
        ("keyAlgorithm", "RSA"),
        ("keyCurve", "P-384"),
        ("keyValue", "bm90IGEga2V5"),
        ("discoverable", "TRUE"),
        ("userHandle", ""),
    ] {
        let mut client = fixture();
        let stored = client.ciphers.get_mut("cipher-edit").unwrap();
        stored.raw["login"]["fido2Credentials"][0][field] =
            encrypt_value(value, &stored.item_key).unwrap();
        assert!(
            client
                .browser_passkey_candidates("example.com", &[])
                .unwrap()
                .is_empty(),
            "{field}: {value}"
        );
        assert!(
            client
                .browser_passkey_excluded(
                    "example.com",
                    &[passkeys::decode(CREDENTIAL_B64, 16).unwrap()]
                )
                .unwrap(),
            "unsupported credential still excludes creation"
        );
    }
}

#[test]
fn selection_rechecks_revision_active_state_rp_allowlist_and_duplicate_ids() {
    let (mut options, context) = get_options();
    let mut client = fixture();
    let selected = client
        .browser_passkey_candidates("example.com", &[])
        .unwrap()
        .remove(0);
    client.ciphers.get_mut("cipher-edit").unwrap().raw["futureField"] = json!(true);
    assert!(
        client
            .browser_passkey_assert(
                &selected,
                &context,
                &options,
                PasskeyVerificationEvidence::FreshPassword
            )
            .is_err()
    );
    let selected = client
        .browser_passkey_candidates("example.com", &[])
        .unwrap()
        .remove(0);
    client.items[0].state = ItemState::Archived;
    assert!(
        client
            .browser_passkey_candidates("example.com", &[])
            .unwrap()
            .is_empty()
    );
    assert!(
        client
            .browser_passkey_assert(
                &selected,
                &context,
                &options,
                PasskeyVerificationEvidence::FreshPassword
            )
            .is_err()
    );
    client.items[0].state = ItemState::Active;
    let wrong_context = ValidatedRequest {
        rp_id: "other.example.com".into(),
        ..context.clone()
    };
    assert!(
        client
            .browser_passkey_assert(
                &selected,
                &wrong_context,
                &options,
                PasskeyVerificationEvidence::FreshPassword
            )
            .is_err()
    );
    options.allow_credentials =
        serde_json::from_value(json!([{"type": "public-key", "id": "AQID"}])).unwrap();
    assert!(
        client
            .browser_passkey_assert(
                &selected,
                &context,
                &options,
                PasskeyVerificationEvidence::FreshPassword
            )
            .is_err()
    );
    options.allow_credentials.clear();
    let stored = client.ciphers.get_mut("cipher-edit").unwrap();
    let raw = stored.raw["login"]["fido2Credentials"][0].clone();
    stored.raw["login"]["fido2Credentials"]
        .as_array_mut()
        .unwrap()
        .push(raw);
    let selected = client
        .browser_passkey_candidates("example.com", &[])
        .unwrap()
        .remove(0);
    assert!(
        client
            .browser_passkey_assert(
                &selected,
                &context,
                &options,
                PasskeyVerificationEvidence::FreshPassword
            )
            .is_err()
    );
}

#[test]
fn b64_ids_pascal_aliases_and_nonresident_allowlist_use_original_entry() {
    let mut client = fixture();
    let stored = client.ciphers.get_mut("cipher-edit").unwrap();
    let mut credential = encrypted_credential(&stored.item_key);
    credential["credentialId"] =
        encrypt_value(&format!("b64.{CREDENTIAL_B64}"), &stored.item_key).unwrap();
    credential["discoverable"] = encrypt_value("false", &stored.item_key).unwrap();
    credential.as_object_mut().unwrap().remove("userHandle");
    let pascal = credential
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key[..1].to_ascii_uppercase() + &key[1..], value.clone()))
        .collect::<serde_json::Map<_, _>>();
    stored.raw["login"]["fido2Credentials"] = json!([{"rpId": "invalid"}, pascal]);
    let ids = [passkeys::decode(CREDENTIAL_B64, 16).unwrap()];
    assert!(
        client
            .browser_passkey_candidates("example.com", &[])
            .unwrap()
            .is_empty()
    );
    assert!(
        client
            .browser_passkey_candidates("EXAMPLE.com", &ids)
            .unwrap()
            .is_empty()
    );
    let selected = client
        .browser_passkey_candidates("example.com", &ids)
        .unwrap()
        .remove(0);
    let (mut options, context) = get_options();
    options.allow_credentials =
        serde_json::from_value(json!([{"type": "public-key", "id": CREDENTIAL_B64}])).unwrap();
    let result = client
        .browser_passkey_assert(
            &selected,
            &context,
            &options,
            PasskeyVerificationEvidence::FreshPassword,
        )
        .unwrap();
    verify_assertion(&result, PUBLIC_KEY);
    assert!(result.user_handle.is_none());
}

/// Echo a single encrypted cipher create request, without real network services.
fn creation_server(status: u16, omit_passkey: bool) -> (String, std::thread::JoinHandle<Value>) {
    cipher_server(status, omit_passkey, false)
}

fn cipher_server(
    status: u16,
    omit_passkey: bool,
    update: bool,
) -> (String, std::thread::JoinHandle<Value>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            headers.push(byte[0]);
        }
        let headers = String::from_utf8(headers).unwrap();
        assert!(headers.starts_with(if update {
            "PUT /api/ciphers/cipher-edit HTTP/1.1\r\n"
        } else {
            "POST /api/ciphers HTTP/1.1\r\n"
        }));
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|value| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        let request: Value = serde_json::from_slice(&body).unwrap();
        let mut response = request.clone();
        response["id"] = json!(if update { "cipher-edit" } else { "new-passkey" });
        response["revisionDate"] = json!("2026-01-01T00:00:00.000Z");
        if omit_passkey {
            response["login"]["fido2Credentials"] = json!([]);
        }
        let response = response.to_string();
        write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
        request
    });
    (url, server)
}

#[test]
fn creation_persists_encrypted_personal_item_then_get_and_edit_preserve_passkey() {
    config::with_test_config(|_| {
        let mut client = fixture();
        let old_raw = client.ciphers["cipher-edit"].raw.clone();
        let (url, server) = creation_server(200, false);
        client.base_url = url;
        client.client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let (options, context) = create_options();
        let created = client
            .browser_passkey_create(
                &context,
                &options,
                PasskeyVerificationEvidence::FreshPassword,
            )
            .unwrap();
        let posted = server.join().unwrap();
        assert_eq!(posted["organizationId"], Value::Null);
        assert!(posted.get("id").is_none());
        let passkey = &posted["login"]["fido2Credentials"][0];
        for (field, value) in passkey.as_object().unwrap() {
            if field != "creationDate" {
                assert!(
                    value.as_str().unwrap().starts_with("2."),
                    "{field} must be encrypted"
                );
            }
        }
        let key = Zeroizing::new(client.user_key.clone().unwrap());
        assert_eq!(passkey_field(passkey, "counter", &key).unwrap(), "0");
        assert_eq!(
            passkey_field(passkey, "discoverable", &key).unwrap(),
            "true"
        );
        assert_eq!(
            passkeys::credential_id(&passkey_field(passkey, "credentialId", &key).unwrap())
                .unwrap(),
            passkeys::decode(&created.credential_id, 16).unwrap()
        );
        assert_eq!(
            passkey_field(passkey, "userHandle", &key).unwrap(),
            options.user.id
        );
        assert_eq!(
            client.ciphers["cipher-edit"].raw, old_raw,
            "creation must never modify an existing item"
        );
        let selected = client
            .browser_passkey_candidates("example.com", &[])
            .unwrap()
            .into_iter()
            .find(|item| item.id == "new-passkey")
            .unwrap();
        let (options, context) = get_options();
        let assertion = client
            .browser_passkey_assert(
                &selected,
                &context,
                &options,
                PasskeyVerificationEvidence::FreshPassword,
            )
            .unwrap();
        verify_assertion(&assertion, created.public_key.as_ref().unwrap());
        let stored = &client.ciphers["new-passkey"];
        let mut draft = draft_from_raw(&stored.raw, &stored.item_key).unwrap();
        draft.notes = "A desktop edit".into();
        let edited = build_save_request(stored, &draft, "2026-01-02T00:00:00.000Z").unwrap();
        assert_eq!(
            edited["login"]["fido2Credentials"],
            posted["login"]["fido2Credentials"]
        );
        let public = serde_json::to_string(&created).unwrap();
        let private_key = passkey_field(passkey, "keyValue", &key).unwrap();
        assert!(!public.contains(&private_key));
        assert!(
            !serde_json::to_string(&client.get_item("new-passkey").unwrap())
                .unwrap()
                .contains(&private_key)
        );
    });
}

#[test]
fn failed_or_incomplete_persistence_never_releases_registration_success() {
    config::with_test_config(|_| {
        for (status, omit_passkey) in [(400, false), (200, true)] {
            let mut client = fixture();
            let (url, server) = creation_server(status, omit_passkey);
            client.base_url = url;
            client.client = Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let (options, context) = create_options();
            assert!(
                client
                    .browser_passkey_create(
                        &context,
                        &options,
                        PasskeyVerificationEvidence::FreshPassword
                    )
                    .is_err()
            );
            server.join().unwrap();
            assert!(!client.ciphers.contains_key("new-passkey"));
        }
    });
}

#[test]
fn excluded_credential_blocks_creation_without_network_or_desktop_grants() {
    let mut client = fixture();
    let (mut options, context) = create_options();
    options.exclude_credentials =
        serde_json::from_value(json!([{"type": "public-key", "id": CREDENTIAL_B64}])).unwrap();
    client.base_url = "http://127.0.0.1:1".into();
    assert!(
        client
            .browser_passkey_create(
                &context,
                &options,
                PasskeyVerificationEvidence::FreshPassword
            )
            .unwrap_err()
            .to_string()
            .contains("excluded")
    );
    assert!(client.item_grants.is_empty());
}

#[test]
fn approval_only_assertion_respects_site_verification_and_raw_item_reprompt() {
    let mut client = fixture();
    client.browser_passkey_test_set_reprompt("cipher-edit", false);
    let mut selected = client
        .browser_passkey_candidates("example.com", &[])
        .unwrap()
        .remove(0);
    assert!(!selected.requires_password);
    let (required, required_context) = get_options();
    assert!(matches!(
        client.browser_passkey_assert(
            &selected,
            &required_context,
            &required,
            PasskeyVerificationEvidence::None
        ),
        Err(BwError::RepromptRequired)
    ));
    let mut optional = required.clone();
    optional.user_verification = "preferred".into();
    let context = passkeys::validate_get(
        "https://example.com/login",
        "https://example.com/login",
        &optional,
    )
    .unwrap();
    let result = client
        .browser_passkey_assert(
            &selected,
            &context,
            &optional,
            PasskeyVerificationEvidence::None,
        )
        .unwrap();
    verify_assertion_uv(&result, PUBLIC_KEY, false);
    client.browser_passkey_test_set_reprompt("cipher-edit", true);
    assert!(matches!(
        client.browser_passkey_assert(
            &selected,
            &context,
            &optional,
            PasskeyVerificationEvidence::None
        ),
        Err(BwError::NotFound)
    ));
    selected = client
        .browser_passkey_candidates("example.com", &[])
        .unwrap()
        .remove(0);
    assert!(selected.requires_password);
    client.authorize_item("cipher-edit", "correct").unwrap();
    selected.requires_password = false; // Forged selection metadata cannot bypass the raw item.
    assert!(matches!(
        client.browser_passkey_assert(
            &selected,
            &context,
            &optional,
            PasskeyVerificationEvidence::None
        ),
        Err(BwError::RepromptRequired)
    ));
    verify_assertion(
        &client
            .browser_passkey_assert(
                &selected,
                &context,
                &optional,
                PasskeyVerificationEvidence::FreshPassword,
            )
            .unwrap(),
        PUBLIC_KEY,
    );
}

#[test]
fn creation_requires_verification_when_requested_but_persists_optional_uv_false() {
    config::with_test_config(|_| {
        let mut client = fixture();
        let (mut options, required_context) = create_options();
        assert!(matches!(
            client.browser_passkey_create(
                &required_context,
                &options,
                PasskeyVerificationEvidence::None
            ),
            Err(BwError::RepromptRequired)
        ));
        options.user_verification = "preferred".into();
        let context = passkeys::validate_create(
            "https://example.com/register",
            "https://example.com/register",
            &options,
        )
        .unwrap();
        let (url, server) = creation_server(200, false);
        client.base_url = url;
        client.client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let created = client
            .browser_passkey_create(&context, &options, PasskeyVerificationEvidence::None)
            .unwrap();
        server.join().unwrap();
        assert_eq!(
            passkeys::decode(&created.authenticator_data, 1024).unwrap()[32],
            0x59
        );
        let selected = client
            .browser_passkey_candidates("example.com", &[])
            .unwrap()
            .into_iter()
            .find(|item| item.id == "new-passkey")
            .unwrap();
        assert!(!selected.requires_password);
        let (mut options, _) = get_options();
        options.user_verification = "preferred".into();
        let context = passkeys::validate_get(
            "https://example.com/login",
            "https://example.com/login",
            &options,
        )
        .unwrap();
        let assertion = client
            .browser_passkey_assert(
                &selected,
                &context,
                &options,
                PasskeyVerificationEvidence::None,
            )
            .unwrap();
        verify_assertion_uv(&assertion, created.public_key.as_ref().unwrap(), false);
    });
}

#[test]
fn verified_unlock_signs_required_assertions_but_never_bypasses_item_reprompt() {
    let mut client = fixture();
    assert!(client.has_verified_unlock());
    let (options, context) = get_options();
    let mut selected = client
        .browser_passkey_candidates("example.com", &[])
        .unwrap()
        .remove(0);
    client.authorize_item("cipher-edit", "correct").unwrap();
    selected.requires_password = false;
    assert!(matches!(
        client.browser_passkey_assert(
            &selected,
            &context,
            &options,
            PasskeyVerificationEvidence::VaultUnlock
        ),
        Err(BwError::RepromptRequired)
    ));
    client.browser_passkey_test_set_reprompt("cipher-edit", false);
    selected = client
        .browser_passkey_candidates("example.com", &[])
        .unwrap()
        .remove(0);
    let result = client
        .browser_passkey_assert(
            &selected,
            &context,
            &options,
            PasskeyVerificationEvidence::VaultUnlock,
        )
        .unwrap();
    verify_assertion_uv(&result, PUBLIC_KEY, true);
    client.browser_test_use_offline_session();
    assert!(client.has_verified_unlock());
    let offline = client
        .browser_passkey_assert(
            &selected,
            &context,
            &options,
            PasskeyVerificationEvidence::VaultUnlock,
        )
        .unwrap();
    verify_assertion_uv(&offline, PUBLIC_KEY, true);
    client.browser_test_clear_unlock_verification();
    assert!(client.has_session());
    assert!(matches!(
        client.browser_passkey_assert(
            &selected,
            &context,
            &options,
            PasskeyVerificationEvidence::VaultUnlock
        ),
        Err(BwError::RepromptRequired)
    ));
    // Session keys and reauthentication metadata alone are insufficient evidence.
    client.verify_master_password("correct").unwrap();
    assert!(!client.has_verified_unlock());
    let fresh = client
        .browser_passkey_assert(
            &selected,
            &context,
            &options,
            PasskeyVerificationEvidence::FreshPassword,
        )
        .unwrap();
    verify_assertion_uv(&fresh, PUBLIC_KEY, true);
}

#[test]
fn verified_unlock_registration_requires_proof_and_persists_uv_true_key() {
    config::with_test_config(|_| {
        let mut client = fixture();
        let (options, context) = create_options();
        client.browser_test_clear_unlock_verification();
        assert!(matches!(
            client.browser_passkey_create(
                &context,
                &options,
                PasskeyVerificationEvidence::VaultUnlock
            ),
            Err(BwError::RepromptRequired)
        ));
        // This fixture represents a completed unlock with the synthetic password.
        client.verify_master_password("correct").unwrap();
        client.verified_unlock = true;
        let (url, server) = creation_server(200, false);
        client.base_url = url;
        client.client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let created = client
            .browser_passkey_create(&context, &options, PasskeyVerificationEvidence::VaultUnlock)
            .unwrap();
        server.join().unwrap();
        assert_eq!(
            passkeys::decode(&created.authenticator_data, 1024).unwrap()[32],
            0x5d
        );
        let selected = client
            .browser_passkey_candidates("example.com", &[])
            .unwrap()
            .into_iter()
            .find(|item| item.id == "new-passkey")
            .unwrap();
        let (options, context) = get_options();
        let assertion = client
            .browser_passkey_assert(
                &selected,
                &context,
                &options,
                PasskeyVerificationEvidence::VaultUnlock,
            )
            .unwrap();
        verify_assertion_uv(&assertion, created.public_key.as_ref().unwrap(), true);
    });
}

#[test]
fn attaching_passkey_preserves_login_and_requires_fresh_item_verification() {
    config::with_test_config(|_| {
        let mut client = fixture();
        let target = client
            .browser_write_targets("https://one.example/login", UriMatchType::Host)
            .unwrap()
            .remove(0);
        let before = client.ciphers["cipher-edit"].raw.clone();
        let (options, context) = create_options();
        assert!(matches!(
            client.browser_passkey_create_on(
                &context,
                &options,
                PasskeyVerificationEvidence::VaultUnlock,
                Some(&target)
            ),
            Err(BwError::RepromptRequired)
        ));
        let (url, server) = cipher_server(200, false, true);
        client.base_url = url;
        client.client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let created = client
            .browser_passkey_create_on(
                &context,
                &options,
                PasskeyVerificationEvidence::FreshPassword,
                Some(&target),
            )
            .unwrap();
        let posted = server.join().unwrap();
        for field in ["password", "username", "totp", "uris"] {
            assert_eq!(posted["login"][field], before["login"][field], "{field}");
        }
        for field in [
            "notes",
            "fields",
            "favorite",
            "reprompt",
            "folderId",
            "passwordHistory",
        ] {
            assert_eq!(posted[field], before[field], "{field}");
        }
        assert_eq!(
            posted["login"]["fido2Credentials"][0],
            before["login"]["fido2Credentials"][0]
        );
        assert_eq!(
            posted["login"]["fido2Credentials"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(client.ciphers.len(), 1);
        let candidate = client
            .browser_passkey_candidates("example.com", &[])
            .unwrap()
            .into_iter()
            .find(|item| item.credential_id == created.credential_id)
            .unwrap();
        let (get, context) = get_options();
        let assertion = client
            .browser_passkey_assert(
                &candidate,
                &context,
                &get,
                PasskeyVerificationEvidence::FreshPassword,
            )
            .unwrap();
        verify_assertion(&assertion, created.public_key.as_ref().unwrap());
        assert!(client.item_grants.is_empty());
        assert!(
            client.browser_write_target(&target, true).is_err(),
            "old revision must be rejected"
        );
    });
}

#[test]
fn browser_password_update_preserves_passkeys_and_history_without_desktop_grants() {
    config::with_test_config(|_| {
        let mut client = fixture();
        let targets = client
            .browser_write_targets("https://one.example/login", UriMatchType::Host)
            .unwrap();
        assert!(client.browser_password_already_saved(&targets, "alice", "current-password"));
        assert!(!client.browser_password_already_saved(&targets, "alice", "new-password"));
        let target = &targets[0];
        let before = client.ciphers["cipher-edit"].raw.clone();
        assert!(matches!(
            client.browser_save_password(
                "https://one.example/login",
                "alice",
                "new-password",
                Some(target),
                false
            ),
            Err(BwError::RepromptRequired)
        ));
        let (url, server) = cipher_server(200, false, true);
        client.base_url = url;
        client.client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        client
            .browser_save_password(
                "https://one.example/login",
                "",
                "new-password",
                Some(target),
                true,
            )
            .unwrap();
        let posted = server.join().unwrap();
        assert_eq!(
            posted["login"]["fido2Credentials"],
            before["login"]["fido2Credentials"]
        );
        assert_eq!(posted["fields"], before["fields"]);
        assert_eq!(posted["login"]["uris"], before["login"]["uris"]);
        assert_eq!(
            raw_decrypt(
                &posted["passwordHistory"][0],
                "password",
                &client.ciphers["cipher-edit"].item_key
            )
            .unwrap(),
            "current-password"
        );
        let draft = draft_from_raw(
            &client.ciphers["cipher-edit"].raw,
            &client.ciphers["cipher-edit"].item_key,
        )
        .unwrap();
        let login = draft.login.unwrap();
        assert_eq!(login.password, "new-password");
        assert_eq!(login.username, "alice");
        assert!(client.item_grants.is_empty());
        assert!(
            client
                .browser_save_password(
                    "https://one.example/login",
                    "alice",
                    "stale",
                    Some(target),
                    true
                )
                .is_err()
        );
    });
}
