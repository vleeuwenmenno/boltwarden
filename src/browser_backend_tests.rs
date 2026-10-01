//! Exercise browser framing, pairing, the real vault backend, and desktop decisions
//! together. Fixtures contain only deterministic test credentials and use no server.

use crate::browser::protocol::{BrowserRequest, FillInteraction, RequestEnvelope, VERSION};
use crate::browser::{BrowserHub, session};
use crate::browser_approval::{BrowserApprovalDecision, BrowserApprovalRequest, BrowserApprovals};
use crate::browser_backend::DaemonBrowserBackend;
use crate::bw::{BwClient, BwError};
use crate::rpc::{RpcRequest, RpcResponse};
use crate::ssh_agent::{SshApprovalService, SshKeyStore};
use crate::{DaemonCommand, VaultState, interaction, uri_match};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use serde_json::Value;
use signature::Signer;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

static TEST_LOCK: Mutex<()> = Mutex::new(());

struct Harness {
    vault: Arc<Mutex<VaultState>>,
    hub: BrowserHub,
    client: UnixStream,
    notices: mpsc::Receiver<()>,
    daemon: mpsc::Sender<DaemonCommand>,
    ssh_approvals: SshApprovalService,
    directory: PathBuf,
    pairing_id: String,
}

impl Harness {
    fn paired() -> Self {
        let (notify, notices) = mpsc::channel();
        let (ssh_notify, _) = mpsc::channel();
        let (unlock_notify, _) = mpsc::channel();
        let (daemon, _) = mpsc::channel();
        let ssh_approvals = SshApprovalService::new(ssh_notify);
        let vault = Arc::new(Mutex::new(VaultState {
            browser_hub: None,
            browser_handler: None,
            browser_approvals: BrowserApprovals::new(notify),
            browser_enabled: true,
            browser_default_match: uri_match::UriMatchType::Host,
            passkey_verification: crate::config::PasskeyVerification::Always,
            browser_epoch: 1,
            browser_unlock: None,
            popup: Arc::new(Mutex::new(None)),
            window: Arc::new(Mutex::new(None)),
            clipboard: crate::clipboard::Clipboard::default(),
            auto_lock_warning: None,
            bw: BwClient::browser_test_fixture(),
            pending_two_factor: None,
            ssh_agent: None,
            ssh_agent_status: crate::ssh_agent::disabled_status(),
            ssh_approvals: ssh_approvals.clone(),
            ssh_key_store: SshKeyStore::new(unlock_notify.clone()),
        }));
        let backend = Arc::new(DaemonBrowserBackend {
            vault: Arc::downgrade(&vault),
            unlock: unlock_notify,
        });
        let directory =
            std::env::temp_dir().join(format!("boltwarden-backend-{}", uuid::Uuid::new_v4()));
        let (hub, client) = BrowserHub::test_connection(backend.clone(), &directory).unwrap();
        {
            let mut state = vault.lock().unwrap();
            state.browser_hub = Some(hub.clone());
            state.browser_handler = Some(backend);
        }
        let mut harness = Self {
            vault,
            hub,
            client,
            notices,
            daemon,
            ssh_approvals,
            directory,
            pairing_id: String::new(),
        };
        harness.pair();
        harness
    }

    fn send(&mut self, id: &str, request: BrowserRequest) {
        let payload = serde_json::to_vec(&RequestEnvelope {
            version: VERSION,
            id: id.into(),
            request,
        })
        .unwrap();
        session::write_frame(&mut self.client, &payload, false).unwrap();
    }

    fn read(&mut self, id: &str) -> Value {
        for _ in 0..20 {
            let response: Value =
                serde_json::from_slice(&session::read_frame(&mut self.client, false).unwrap())
                    .unwrap();
            if response["id"] == id {
                return response;
            }
            assert_ne!(
                response["type"], "Credentials",
                "unexpected secret response"
            );
            assert_ne!(
                response["type"], "PasskeyResult",
                "unexpected assertion response"
            );
            assert!(
                response.get("id").is_none(),
                "unexpected response: {response:?}"
            );
        }
        panic!("too many events before response {id}");
    }

    fn approval(&self) -> BrowserApprovalRequest {
        self.notices.recv_timeout(Duration::from_secs(2)).unwrap();
        self.vault
            .lock()
            .unwrap()
            .browser_approvals
            .active()
            .unwrap()
    }

    fn decide(&self, request_id: &str, approved: bool, password: &str) -> Result<(), String> {
        match crate::handle_rpc_request(
            RpcRequest::DecideBrowserApproval(BrowserApprovalDecision {
                request_id: request_id.into(),
                approved,
                selected_id: None,
                use_other_device: false,
                password: password.into(),
            }),
            &self.vault,
            &self.ssh_approvals,
            &self.daemon,
        ) {
            RpcResponse::BrowserApprovalDecided(result) => result,
            _ => panic!("unexpected desktop decision response"),
        }
    }

    fn use_passkey_fixture(&mut self) {
        self.vault.lock().unwrap().bw = BwClient::browser_passkey_test_fixture();
    }

    fn get_passkey(&mut self, id: &str) {
        self.send(
            id,
            BrowserRequest::PasskeyGet {
                top_url: "https://example.com/login".into(),
                frame_url: "https://example.com/login".into(),
                document_id: "passkey-document".into(),
                options: passkey_get_options(),
            },
        );
    }

    fn choose(
        &self,
        request: &BrowserApprovalRequest,
        selected: Option<&str>,
        password: &str,
        fallback: bool,
    ) -> Result<(), String> {
        match crate::handle_rpc_request(
            RpcRequest::DecideBrowserApproval(BrowserApprovalDecision {
                request_id: request.id.clone(),
                approved: !fallback,
                selected_id: selected.map(str::to_owned),
                use_other_device: fallback,
                password: password.into(),
            }),
            &self.vault,
            &self.ssh_approvals,
            &self.daemon,
        ) {
            RpcResponse::BrowserApprovalDecided(result) => result,
            _ => panic!("unexpected desktop decision response"),
        }
    }

    fn pair(&mut self) {
        self.send("hello", BrowserRequest::Hello { pairing_id: None });
        let challenge = self.read("hello");
        let pairing_id = challenge["pairing_id"].as_str().unwrap().to_owned();
        let key = SigningKey::from_slice(&[19; 32]).unwrap();
        let pid = std::process::id();
        let signature: Signature = key.sign(&session::transcript(
            challenge["nonce"].as_str().unwrap(),
            &pairing_id,
            pid,
        ));
        self.send(
            "pair",
            BrowserRequest::RequestPairing {
                pairing_id: pairing_id.clone(),
                public_key_spki: URL_SAFE_NO_PAD
                    .encode(key.verifying_key().to_public_key_der().unwrap().as_bytes()),
                label: "Backend integration test".into(),
                sig: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                host_pid: pid,
            },
        );
        let approval = self.approval();
        assert!(!approval.requires_password);
        self.decide(&approval.id, true, "").unwrap();
        assert_eq!(self.read("pair")["type"], "Paired");
        self.pairing_id = pairing_id;
    }

    fn revision(&mut self) -> String {
        self.send(
            "list",
            BrowserRequest::ListMatches {
                top_url: "https://one.example/".into(),
                frame_url: "https://one.example/login".into(),
                document_id: "document-1".into(),
                offset: 0,
            },
        );
        let response = self.read("list");
        assert_eq!(response["type"], "Matches");
        assert_eq!(response["items"].as_array().unwrap().len(), 1);
        assert_eq!(response["items"][0]["reprompt"], true);
        response["items"][0]["revision"].as_str().unwrap().into()
    }

    fn fill(&mut self, id: &str, revision: &str, interaction: FillInteraction) {
        self.send(
            id,
            BrowserRequest::FillLogin {
                item_id: "cipher-edit".into(),
                revision: revision.into(),
                top_url: "https://one.example/".into(),
                frame_url: "https://one.example/login".into(),
                document_id: "document-1".into(),
                interaction,
                confirm_insecure: false,
                confirm_cross_origin: false,
            },
        );
    }

    fn wait_for_approval_end(&self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let active = self
                .vault
                .lock()
                .unwrap()
                .browser_approvals
                .active()
                .is_some();
            if !active {
                // The waiter clears the slot just before dropping its interaction lease.
                if let Ok(lease) = interaction::global().acquire(interaction::Kind::Browser) {
                    drop(lease);
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "cancelled browser approval remained active"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn assert_no_credentials(&mut self) {
        self.client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        while let Ok(body) = session::read_frame(&mut self.client, false) {
            let response: Value = serde_json::from_slice(&body).unwrap();
            assert_ne!(
                response["type"], "Credentials",
                "cancelled request released credentials"
            );
            assert_ne!(
                response["type"], "PasskeyResult",
                "cancelled request released a passkey"
            );
        }
        self.client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.hub.shutdown();
        if let Ok(state) = self.vault.lock() {
            state.browser_approvals.clear();
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn browser_fill_requires_correct_password_and_never_grants_desktop_access() {
    let _serial = TEST_LOCK.lock().unwrap();
    let mut h = Harness::paired();
    let revision = h.revision();
    h.fill("fill", &revision, FillInteraction::Popup);
    let approval = h.approval();
    assert!(approval.requires_password);
    assert!(
        h.decide(&approval.id, true, "wrong")
            .unwrap_err()
            .contains("Incorrect master password")
    );
    h.assert_no_credentials();
    assert_eq!(
        h.vault
            .lock()
            .unwrap()
            .browser_approvals
            .active()
            .unwrap()
            .id,
        approval.id
    );
    assert!(matches!(
        h.vault.lock().unwrap().bw.get_item("cipher-edit"),
        Err(BwError::RepromptRequired)
    ));
    h.decide(&approval.id, true, "correct").unwrap();
    let response = h.read("fill");
    assert_eq!(response["type"], "Credentials");
    assert_eq!(response["password"], "current-password");
    assert_eq!(response["document_id"], "document-1");
    assert!(matches!(
        h.vault.lock().unwrap().bw.get_item("cipher-edit"),
        Err(BwError::RepromptRequired)
    ));
    h.fill("second-fill", &revision, FillInteraction::Popup);
    let next = h.approval();
    assert_ne!(next.id, approval.id);
    h.decide(&next.id, false, "").unwrap();
    assert_eq!(h.read("second-fill")["code"], "Cancelled");
}

#[test]
fn browser_fill_ignores_desktop_grants_and_rejects_stale_revisions() {
    let _serial = TEST_LOCK.lock().unwrap();
    let mut h = Harness::paired();
    let revision = h.revision();
    h.vault
        .lock()
        .unwrap()
        .bw
        .authorize_item("cipher-edit", "correct")
        .unwrap();
    h.fill("shortcut", &revision, FillInteraction::Shortcut);
    assert_eq!(h.read("shortcut")["code"], "RepromptRequired");
    h.fill("stale", "old-item-revision", FillInteraction::Popup);
    assert_eq!(h.read("stale")["code"], "StaleRequest");
    assert!(h.vault.lock().unwrap().browser_approvals.active().is_none());
    h.fill("popup", &revision, FillInteraction::Popup);
    let approval = h.approval();
    assert!(approval.requires_password);
    h.decide(&approval.id, false, "").unwrap();
    assert_eq!(h.read("popup")["code"], "Cancelled");
}

#[test]
fn browser_fill_rechecks_changed_item_after_desktop_approval() {
    let _serial = TEST_LOCK.lock().unwrap();
    let mut h = Harness::paired();
    let revision = h.revision();
    h.fill("fill", &revision, FillInteraction::Popup);
    let approval = h.approval();
    // A sync or desktop edit can replace the item while the browser approval is open.
    h.vault.lock().unwrap().bw.browser_test_change_password();
    h.decide(&approval.id, true, "correct").unwrap();
    let response = h.read("fill");
    assert_eq!(response["type"], "Error");
    assert!(matches!(
        response["code"].as_str(),
        Some("NoMatch" | "StaleRequest")
    ));
    h.assert_no_credentials();
}

#[test]
fn browser_fill_cancellation_and_lock_epoch_discard_pending_secrets() {
    let _serial = TEST_LOCK.lock().unwrap();
    for change_epoch in [false, true] {
        let mut h = Harness::paired();
        let revision = h.revision();
        h.fill("fill", &revision, FillInteraction::Popup);
        let approval = h.approval();
        if change_epoch {
            // Exercise exactly the invalidation used by lock and account replacement,
            // even while the old fixture's decrypted item still exists in memory.
            crate::invalidate_browser(&mut h.vault.lock().unwrap(), false);
        } else {
            h.send(
                "cancel",
                BrowserRequest::Cancel {
                    request_id: "fill".into(),
                },
            );
            assert_eq!(h.read("cancel")["type"], "Cancelled");
        }
        h.wait_for_approval_end();
        assert!(h.decide(&approval.id, true, "correct").is_err());
        h.assert_no_credentials();
    }
}

#[test]
fn browser_fill_revoke_and_disconnect_cancel_desktop_approval() {
    let _serial = TEST_LOCK.lock().unwrap();
    for revoke in [false, true] {
        let mut h = Harness::paired();
        let revision = h.revision();
        h.fill("fill", &revision, FillInteraction::Popup);
        let approval = h.approval();
        if revoke {
            assert!(matches!(
                crate::handle_rpc_request(
                    RpcRequest::RevokePairedBrowser {
                        id: h.pairing_id.clone()
                    },
                    &h.vault,
                    &h.ssh_approvals,
                    &h.daemon,
                ),
                RpcResponse::BrowserRevoked(Ok(()))
            ));
            assert!(h.hub.list_pairings().unwrap().is_empty());
        } else {
            h.client.shutdown(Shutdown::Both).unwrap();
        }
        h.wait_for_approval_end();
        assert!(h.decide(&approval.id, true, "correct").is_err());
        h.assert_no_credentials();
    }
}

#[test]
fn disabled_browser_integration_lists_and_revokes_durable_pairings_and_reports_store_errors() {
    use std::os::unix::fs::PermissionsExt;
    let _serial = TEST_LOCK.lock().unwrap();
    crate::config::with_test_config(|root| {
        let h = Harness::paired();
        h.hub.shutdown();
        {
            let mut state = h.vault.lock().unwrap();
            state.browser_hub = None;
            state.browser_enabled = false;
        }
        let path = root.join("boltwarden/browsers.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::copy(h.directory.join("browsers.json"), &path).unwrap();
        let list = || {
            crate::handle_rpc_request(
                RpcRequest::ListPairedBrowsers,
                &h.vault,
                &h.ssh_approvals,
                &h.daemon,
            )
        };
        match list() {
            RpcResponse::PairedBrowsers(Ok(records)) => assert_eq!(records[0].id, h.pairing_id),
            other => panic!("unexpected browser list response: {other:?}"),
        }
        assert!(matches!(
            crate::handle_rpc_request(
                RpcRequest::RevokePairedBrowser {
                    id: h.pairing_id.clone()
                },
                &h.vault,
                &h.ssh_approvals,
                &h.daemon,
            ),
            RpcResponse::BrowserRevoked(Ok(()))
        ));
        assert!(
            crate::browser::pairing::PairingStore::load()
                .unwrap()
                .list()
                .is_empty()
        );
        assert!(matches!(list(), RpcResponse::PairedBrowsers(Ok(records)) if records.is_empty()));
        std::fs::write(&path, b"invalid JSON").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            matches!(list(), RpcResponse::PairedBrowsers(Err(message)) if message.contains("Could not load paired browsers"))
        );
        assert!(matches!(
            crate::handle_rpc_request(
                RpcRequest::RevokePairedBrowser {
                    id: h.pairing_id.clone()
                },
                &h.vault,
                &h.ssh_approvals,
                &h.daemon,
            ),
            RpcResponse::BrowserRevoked(Err(_))
        ));
    });
}

#[test]
fn offline_browser_fill_preserves_master_password_policy() {
    let _serial = TEST_LOCK.lock().unwrap();
    crate::config::with_test_config(|_| {
        let mut h = Harness::paired();
        h.vault
            .lock()
            .unwrap()
            .bw
            .browser_test_use_offline_session();
        let revision = h.revision();
        h.fill("offline-fill", &revision, FillInteraction::Popup);
        let approval = h.approval();
        assert!(approval.requires_password);
        assert!(h.decide(&approval.id, true, "wrong").is_err());
        h.assert_no_credentials();
        h.decide(&approval.id, true, "correct").unwrap();
        assert_eq!(h.read("offline-fill")["password"], "current-password");
        assert!(matches!(
            h.vault.lock().unwrap().bw.get_item("cipher-edit"),
            Err(BwError::RepromptRequired)
        ));
    });
}

#[test]
fn browser_sync_revocation_locks_daemon_and_cancels_pending_fill() {
    let _serial = TEST_LOCK.lock().unwrap();
    crate::config::with_test_config(|_| {
        for sync_via_fill in [false, true] {
            let mut h = Harness::paired();
            let revision = h.revision();
            h.fill("pending-fill", &revision, FillInteraction::Popup);
            let approval = h.approval();
            let (epoch, server) = {
                let mut state = h.vault.lock().unwrap();
                (
                    state.browser_epoch,
                    state.bw.browser_test_revoke_on_next_sync(),
                )
            };
            if sync_via_fill {
                h.fill("sync-fill", &revision, FillInteraction::Popup);
            } else {
                h.send(
                    "sync-list",
                    BrowserRequest::ListMatches {
                        top_url: "https://one.example/".into(),
                        frame_url: "https://one.example/login".into(),
                        document_id: "document-1".into(),
                        offset: 0,
                    },
                );
            }
            h.wait_for_approval_end();
            server.join().unwrap();
            {
                let state = h.vault.lock().unwrap();
                assert!(!state.bw.has_session());
                assert_eq!(state.browser_epoch, epoch.wrapping_add(1));
            }
            assert!(h.decide(&approval.id, true, "correct").is_err());
            h.assert_no_credentials();
            h.send("status", BrowserRequest::Status);
            assert_eq!(h.read("status")["unlocked"], false);
        }
    });
}

fn passkey_get_options() -> crate::passkeys::GetOptions {
    serde_json::from_value(serde_json::json!({
        "challenge": "Y2hhbGxlbmdl", "rp_id": "example.com", "allow_credentials": [],
        "user_verification": "preferred", "timeout_ms": 60000
    }))
    .unwrap()
}

fn passkey_create_options() -> crate::passkeys::CreateOptions {
    serde_json::from_value(serde_json::json!({
        "challenge": "Y2hhbGxlbmdl", "rp": {"id":"example.com", "name":"Example"},
        "user": {"id":"dXNlcg", "name":"alice@example.com", "display_name":"Alice"},
        "pub_key_cred_params": [{"type":"public-key", "alg":-7}],
        "exclude_credentials": [{"type":"public-key", "id":"CNcLdOn1RSKkJeXc1AEH5w"}],
        "resident_key":"required", "user_verification":"preferred", "cred_props":true, "timeout_ms":60000
    })).unwrap()
}

#[test]
fn browser_passkey_requires_fresh_password_and_prompt_bound_account_choice() {
    let _serial = TEST_LOCK.lock().unwrap();
    let mut h = Harness::paired();
    h.use_passkey_fixture();
    h.vault.lock().unwrap().bw.browser_passkey_test_add_second();
    h.vault
        .lock()
        .unwrap()
        .bw
        .authorize_item("cipher-second", "correct")
        .unwrap();
    h.get_passkey("assertion");
    let approval = h.approval();
    assert!(approval.requires_password);
    assert_eq!(approval.action_label.as_deref(), Some("Sign in"));
    assert_eq!(approval.choices.len(), 2);
    let selected = &approval.choices[1].id;
    assert_ne!(selected, "cipher-edit");
    assert!(
        h.choose(&approval, Some("cipher-edit"), "correct", false)
            .is_err()
    );
    assert!(h.choose(&approval, None, "correct", false).is_err());
    assert!(h.choose(&approval, Some(selected), "wrong", false).is_err());
    h.assert_no_credentials();
    h.choose(&approval, Some(selected), "correct", false)
        .unwrap();
    let response = h.read("assertion");
    assert_eq!(response["type"], "PasskeyResult");
    assert_eq!(response["kind"], "get");
    assert_eq!(response["document_id"], "passkey-document");
    assert_eq!(
        response["credential_id"],
        crate::passkeys::encode(
            uuid::Uuid::parse_str("18d70b74-e9f5-4522-a425-e5dcd40107e7")
                .unwrap()
                .as_bytes()
        )
    );
    let data = URL_SAFE_NO_PAD
        .decode(response["authenticator_data"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        data[32] & 0x05,
        0x05,
        "UP and UV must follow fresh desktop verification"
    );
    assert!(response["signature"].as_str().is_some());
    h.get_passkey("another-assertion");
    let second = h.approval();
    assert_ne!(second.choices[0].id, *selected);
    assert!(h.choose(&second, Some(selected), "correct", false).is_err());
    h.decide(&second.id, false, "").unwrap();
    assert_eq!(h.read("another-assertion")["code"], "NotAllowedError");
}

#[test]
fn browser_passkey_stale_item_and_explicit_fallback_do_not_release_assertions() {
    let _serial = TEST_LOCK.lock().unwrap();
    let mut h = Harness::paired();
    h.use_passkey_fixture();
    h.get_passkey("changed");
    let approval = h.approval();
    h.vault.lock().unwrap().bw.browser_test_change_password();
    h.choose(&approval, Some(&approval.choices[0].id), "correct", false)
        .unwrap();
    assert_eq!(h.read("changed")["code"], "NotAllowedError");
    h.get_passkey("fallback");
    let approval = h.approval();
    h.choose(&approval, None, "", true).unwrap();
    assert_eq!(h.read("fallback")["code"], "FallbackRequested");
    h.assert_no_credentials();
}

#[test]
fn browser_passkey_cancel_lock_revoke_and_disconnect_end_the_exact_pending_approval() {
    let _serial = TEST_LOCK.lock().unwrap();
    for interruption in ["cancel", "lock", "revoke", "disconnect"] {
        let mut h = Harness::paired();
        h.use_passkey_fixture();
        h.get_passkey("assertion");
        let approval = h.approval();
        match interruption {
            "cancel" => {
                h.send(
                    "cancel",
                    BrowserRequest::Cancel {
                        request_id: "assertion".into(),
                    },
                );
                assert_eq!(h.read("cancel")["type"], "Cancelled");
            }
            "lock" => crate::invalidate_browser(&mut h.vault.lock().unwrap(), false),
            "revoke" => {
                h.hub.revoke(&h.pairing_id).unwrap();
            }
            "disconnect" => h.client.shutdown(Shutdown::Both).unwrap(),
            _ => unreachable!(),
        }
        h.wait_for_approval_end();
        assert!(
            h.choose(&approval, Some(&approval.choices[0].id), "correct", false)
                .is_err()
        );
        h.assert_no_credentials();
    }
}

#[test]
fn browser_passkey_exclusion_is_reported_only_after_desktop_consent() {
    let _serial = TEST_LOCK.lock().unwrap();
    let mut h = Harness::paired();
    h.use_passkey_fixture();
    for approved in [false, true] {
        h.send(
            "create",
            BrowserRequest::PasskeyCreate {
                top_url: "https://example.com/register".into(),
                frame_url: "https://example.com/register".into(),
                document_id: "passkey-document".into(),
                options: passkey_create_options(),
            },
        );
        let approval = h.approval();
        assert!(approval.requires_password);
        assert_eq!(approval.action_label.as_deref(), Some("Create passkey"));
        h.decide(
            &approval.id,
            approved,
            if approved { "correct" } else { "" },
        )
        .unwrap();
        assert_eq!(
            h.read("create")["code"],
            if approved {
                "InvalidStateError"
            } else {
                "NotAllowedError"
            }
        );
    }
}

#[test]
fn browser_passkey_invalid_rp_and_offline_create_fail_before_prompting() {
    let _serial = TEST_LOCK.lock().unwrap();
    let mut h = Harness::paired();
    h.use_passkey_fixture();
    let mut options = passkey_get_options();
    options.rp_id = Some("other.example".into());
    h.send(
        "invalid-rp",
        BrowserRequest::PasskeyGet {
            top_url: "https://example.com/login".into(),
            frame_url: "https://example.com/login".into(),
            document_id: "passkey-document".into(),
            options,
        },
    );
    assert_eq!(h.read("invalid-rp")["code"], "SecurityError");
    assert!(h.vault.lock().unwrap().browser_approvals.active().is_none());
    h.vault
        .lock()
        .unwrap()
        .bw
        .browser_test_use_offline_session();
    h.send(
        "offline-create",
        BrowserRequest::PasskeyCreate {
            top_url: "https://example.com/register".into(),
            frame_url: "https://example.com/register".into(),
            document_id: "passkey-document".into(),
            options: passkey_create_options(),
        },
    );
    assert_eq!(h.read("offline-create")["code"], "Unavailable");
    assert!(h.vault.lock().unwrap().browser_approvals.active().is_none());
}

#[test]
fn browser_passkey_verification_policy_and_site_requirement_control_actual_uv() {
    use crate::config::PasskeyVerification::{Always, VaultUnlock, WhenRequired};
    let _serial = TEST_LOCK.lock().unwrap();
    for policy in [Always, WhenRequired, VaultUnlock] {
        for site_requirement in ["required", "preferred", "discouraged"] {
            let mut h = Harness::paired();
            h.use_passkey_fixture();
            {
                let mut state = h.vault.lock().unwrap();
                state.passkey_verification = policy;
                state
                    .bw
                    .browser_passkey_test_set_reprompt("cipher-edit", false);
            }
            let mut options = passkey_get_options();
            options.user_verification = site_requirement.into();
            h.send(
                "policy-assertion",
                BrowserRequest::PasskeyGet {
                    top_url: "https://example.com/login".into(),
                    frame_url: "https://example.com/login".into(),
                    document_id: "policy-document".into(),
                    options,
                },
            );
            let approval = h.approval();
            let selected = &approval.choices[0].id;
            let requires_password =
                policy == Always || (policy == WhenRequired && site_requirement == "required");
            assert_eq!(
                approval.requires_password_for(Some(selected)).unwrap(),
                requires_password
            );
            if requires_password {
                assert!(h.choose(&approval, Some(selected), "", false).is_err());
                assert!(h.choose(&approval, Some(selected), "wrong", false).is_err());
                assert_eq!(
                    h.vault
                        .lock()
                        .unwrap()
                        .browser_approvals
                        .active()
                        .unwrap()
                        .id,
                    approval.id
                );
            }
            h.choose(
                &approval,
                Some(selected),
                if requires_password { "correct" } else { "" },
                false,
            )
            .unwrap();
            let response = h.read("policy-assertion");
            assert_eq!(response["type"], "PasskeyResult");
            let bytes = URL_SAFE_NO_PAD
                .decode(response["authenticator_data"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                bytes[32] & 0x04 != 0,
                requires_password || policy == VaultUnlock,
                "{policy:?}/{site_requirement}"
            );
            assert_eq!(bytes[32] & 0x19, 0x19, "consent preserves UP, BE and BS");
        }
    }
}

#[test]
fn browser_passkey_protected_account_cannot_use_plain_accounts_approval_policy() {
    let _serial = TEST_LOCK.lock().unwrap();
    for policy in [
        crate::config::PasskeyVerification::WhenRequired,
        crate::config::PasskeyVerification::VaultUnlock,
    ] {
        let mut h = Harness::paired();
        h.use_passkey_fixture();
        {
            let mut state = h.vault.lock().unwrap();
            state.passkey_verification = policy;
            state.bw.browser_passkey_test_add_second();
            state
                .bw
                .browser_passkey_test_set_reprompt("cipher-second", false);
            state.bw.authorize_item("cipher-edit", "correct").unwrap();
        }
        h.get_passkey("choice-policy");
        let approval = h.approval();
        assert!(!approval.requires_password);
        let protected = approval
            .choices
            .iter()
            .find(|choice| choice.requires_password)
            .unwrap();
        let plain = approval
            .choices
            .iter()
            .find(|choice| !choice.requires_password)
            .unwrap();
        assert!(approval.requires_password_for(Some(&protected.id)).unwrap());
        assert!(!approval.requires_password_for(Some(&plain.id)).unwrap());
        assert!(h.choose(&approval, Some(&protected.id), "", false).is_err());
        assert!(
            h.choose(&approval, Some(&protected.id), "wrong", false)
                .is_err()
        );
        h.choose(&approval, Some(&plain.id), "", false).unwrap();
        let response = h.read("choice-policy");
        assert_eq!(response["type"], "PasskeyResult");
        assert_eq!(
            response["credential_id"],
            crate::passkeys::encode(
                uuid::Uuid::parse_str("18d70b74-e9f5-4522-a425-e5dcd40107e7")
                    .unwrap()
                    .as_bytes()
            )
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(response["authenticator_data"].as_str().unwrap())
                .unwrap()[32]
                & 4,
            if policy == crate::config::PasskeyVerification::VaultUnlock {
                4
            } else {
                0
            }
        );
        h.get_passkey("protected-choice");
        let approval = h.approval();
        let protected = approval
            .choices
            .iter()
            .find(|choice| choice.requires_password)
            .unwrap();
        h.choose(&approval, Some(&protected.id), "correct", false)
            .unwrap();
        let response = h.read("protected-choice");
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(response["authenticator_data"].as_str().unwrap())
                .unwrap()[32]
                & 4,
            4
        );
    }
}

#[test]
fn browser_passkey_policy_change_invalidates_pending_consent_but_unchanged_policy_does_not() {
    let _serial = TEST_LOCK.lock().unwrap();
    let mut h = Harness::paired();
    h.use_passkey_fixture();
    let mut settings = crate::config::AppSettings::default();
    settings.passkey_verification = crate::config::PasskeyVerification::WhenRequired;
    {
        let mut state = h.vault.lock().unwrap();
        state
            .bw
            .browser_passkey_test_set_reprompt("cipher-edit", false);
        crate::apply_browser_request_preferences(&mut state, &settings);
    }
    h.get_passkey("same-policy");
    let approval = h.approval();
    let epoch = h.vault.lock().unwrap().browser_epoch;
    crate::apply_browser_request_preferences(&mut h.vault.lock().unwrap(), &settings);
    assert_eq!(h.vault.lock().unwrap().browser_epoch, epoch);
    h.choose(&approval, Some(&approval.choices[0].id), "", false)
        .unwrap();
    assert_eq!(h.read("same-policy")["type"], "PasskeyResult");
    h.get_passkey("changed-policy");
    let approval = h.approval();
    settings.passkey_verification = crate::config::PasskeyVerification::Always;
    crate::apply_browser_request_preferences(&mut h.vault.lock().unwrap(), &settings);
    assert_ne!(h.vault.lock().unwrap().browser_epoch, epoch);
    h.wait_for_approval_end();
    assert!(
        h.choose(&approval, Some(&approval.choices[0].id), "", false)
            .is_err()
    );
    h.assert_no_credentials();
}

#[test]
fn browser_passkey_vault_unlock_requires_live_proof_or_falls_back_to_fresh_password() {
    let _serial = TEST_LOCK.lock().unwrap();
    for scenario in ["offline", "no-proof", "proof-lost"] {
        let mut h = Harness::paired();
        h.use_passkey_fixture();
        {
            let mut state = h.vault.lock().unwrap();
            state.passkey_verification = crate::config::PasskeyVerification::VaultUnlock;
            state
                .bw
                .browser_passkey_test_set_reprompt("cipher-edit", false);
            if scenario == "offline" {
                state.bw.browser_test_use_offline_session();
            } else if scenario == "no-proof" {
                state.bw.browser_test_clear_unlock_verification();
            }
        }
        let mut options = passkey_get_options();
        options.user_verification = "required".into();
        h.send(
            "proof",
            BrowserRequest::PasskeyGet {
                top_url: "https://example.com/login".into(),
                frame_url: "https://example.com/login".into(),
                document_id: "proof-document".into(),
                options,
            },
        );
        let approval = h.approval();
        let selected = Some(approval.choices[0].id.as_str());
        assert_eq!(approval.requires_password, scenario == "no-proof");
        if scenario == "no-proof" {
            assert!(h.choose(&approval, selected, "", false).is_err());
            assert!(h.choose(&approval, selected, "wrong", false).is_err());
        }
        if scenario == "proof-lost" {
            h.vault
                .lock()
                .unwrap()
                .bw
                .browser_test_clear_unlock_verification();
        }
        h.choose(
            &approval,
            selected,
            if scenario == "no-proof" {
                "correct"
            } else {
                ""
            },
            false,
        )
        .unwrap();
        let response = h.read("proof");
        if scenario == "proof-lost" {
            assert_eq!(response["code"], "NotAllowedError");
            h.assert_no_credentials();
        } else {
            assert_eq!(response["type"], "PasskeyResult", "{scenario}: {response}");
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(response["authenticator_data"].as_str().unwrap())
                    .unwrap()[32]
                    & 4,
                4
            );
        }
    }
}

#[test]
fn browser_passkey_vault_unlock_consent_cannot_survive_session_or_policy_replacement() {
    let _serial = TEST_LOCK.lock().unwrap();
    for change in ["lock", "account", "policy"] {
        let mut h = Harness::paired();
        h.use_passkey_fixture();
        let mut settings = crate::config::AppSettings::default();
        settings.passkey_verification = crate::config::PasskeyVerification::VaultUnlock;
        {
            let mut state = h.vault.lock().unwrap();
            state
                .bw
                .browser_passkey_test_set_reprompt("cipher-edit", false);
            crate::apply_browser_request_preferences(&mut state, &settings);
        }
        h.get_passkey("replaced");
        let approval = h.approval();
        assert!(!approval.requires_password);
        let epoch = h.vault.lock().unwrap().browser_epoch;
        {
            let mut state = h.vault.lock().unwrap();
            // Reapplying the same preference must preserve the pending consent.
            crate::apply_browser_request_preferences(&mut state, &settings);
            assert_eq!(state.browser_epoch, epoch);
            assert_eq!(state.browser_approvals.active().unwrap().id, approval.id);
            match change {
                "lock" => {
                    crate::lock_vault_state(&mut state, "test");
                    assert!(!state.bw.has_verified_unlock());
                }
                "account" => {
                    // The successful login path invalidates before replacing the client.
                    crate::invalidate_browser(&mut state, true);
                    state.bw = BwClient::browser_passkey_test_fixture();
                }
                "policy" => {
                    settings.passkey_verification =
                        crate::config::PasskeyVerification::WhenRequired;
                    crate::apply_browser_request_preferences(&mut state, &settings);
                }
                _ => unreachable!(),
            }
            assert_ne!(state.browser_epoch, epoch);
        }
        h.wait_for_approval_end();
        assert!(
            h.choose(&approval, Some(&approval.choices[0].id), "", false)
                .is_err()
        );
        h.assert_no_credentials();
    }
}

#[test]
fn browser_passkey_vault_unlock_creation_still_requires_explicit_consent() {
    let _serial = TEST_LOCK.lock().unwrap();
    let mut h = Harness::paired();
    h.use_passkey_fixture();
    h.vault.lock().unwrap().passkey_verification = crate::config::PasskeyVerification::VaultUnlock;
    for approved in [false, true] {
        let mut options = passkey_create_options();
        options.user_verification = "required".into();
        h.send(
            "create-consent",
            BrowserRequest::PasskeyCreate {
                top_url: "https://example.com/register".into(),
                frame_url: "https://example.com/register".into(),
                document_id: "create-document".into(),
                options,
            },
        );
        let approval = h.approval();
        assert!(!approval.requires_password);
        h.decide(&approval.id, approved, "").unwrap();
        assert_eq!(
            h.read("create-consent")["code"],
            if approved {
                "InvalidStateError"
            } else {
                "NotAllowedError"
            }
        );
    }
}
