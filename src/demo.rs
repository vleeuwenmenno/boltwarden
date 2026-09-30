//! In-memory backend with made-up items, for trying the UI without a vault:
//! `BWQA_DEMO=1 bw-quick-access --popup`. `BWQA_DEMO=locked` starts at the login screen
//! (the master password "2fa" leads to the two-step screen) and `BWQA_DEMO=ssh` opens an
//! SSH approval prompt. Nothing is read from or written to disk except the icon cache.

use crate::backend::{BackendError, SearchResult};
use crate::bw::TwoFactorProvider;
use crate::model::{
    BwItem, BwItemDetail, CustomField, DraftField, DraftFieldKind, DraftUri, ItemAction,
    ItemDates, ItemDraft, ItemState, LoginDraft, SshAgentClientInfo, SshApprovalKind, SshApprovalRequest,
    SshApprovalStatus, SshApprovalStatusKind, SshKey, SyncStatus, TotpCode,
};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

const DEMO_TOTP_SEED: &str = "JBSWY3DPEHPK3PXP";

pub struct DemoBackend {
    unlocked: AtomicBool,
    ssh_request_pending: AtomicBool,
    items: Mutex<Vec<BwItemDetail>>,
}

pub fn enabled() -> bool {
    std::env::var_os("BWQA_DEMO").is_some()
}

impl DemoBackend {
    pub fn new() -> Self {
        let mode = std::env::var("BWQA_DEMO").unwrap_or_default();
        Self {
            unlocked: AtomicBool::new(mode != "locked"),
            ssh_request_pending: AtomicBool::new(mode == "ssh"),
            items: Mutex::new(details()),
        }
    }

    pub fn has_session(&self) -> bool {
        self.unlocked.load(Ordering::Relaxed)
    }

    pub fn login(&self, password: &str) -> Result<(), BackendError> {
        std::thread::sleep(std::time::Duration::from_millis(400));
        match password {
            "wrong" => Err(BackendError::Message("invalid master password".into())),
            "2fa" => Err(BackendError::TwoFactorRequired(vec![
                TwoFactorProvider::Authenticator,
                TwoFactorProvider::Email,
            ])),
            _ => {
                self.unlocked.store(true, Ordering::Relaxed);
                Ok(())
            }
        }
    }

    pub fn complete_two_factor(&self) -> Result<(), BackendError> {
        self.unlocked.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub fn lock(&self) {
        self.unlocked.store(false, Ordering::Relaxed);
    }

    fn items(&self) -> Result<std::sync::MutexGuard<'_, Vec<BwItemDetail>>, BackendError> {
        self.items
            .lock()
            .map_err(|_| BackendError::Message("demo items lock poisoned".into()))
    }

    pub fn list_items(&self, state: ItemState, query: &str) -> Result<SearchResult, BackendError> {
        std::thread::sleep(std::time::Duration::from_millis(120));
        let query = query.to_lowercase();
        let items: Vec<BwItem> = self
            .items()?
            .iter()
            .filter(|item| item.state == state)
            .cloned()
            .filter(|item| {
                item.name.to_lowercase().contains(&query)
                    || item
                        .username
                        .as_deref()
                        .is_some_and(|username| username.to_lowercase().contains(&query))
            })
            .map(|detail| BwItem {
                id: detail.id,
                name: detail.name,
                username: detail.username,
                folder: detail.folder,
                icon_host: crate::icons::icon_host(&detail.uris),
                item_type: detail.item_type,
                state: detail.state,
                dates: detail.dates,
            })
            .collect();
        Ok(SearchResult {
            status: SyncStatus {
                server_ciphers: items.len(),
                decrypted_items: items.len(),
                ..SyncStatus::default()
            },
            items,
            warning: None,
            icons_url: Some(crate::icons::icons_url_for_server(
                "https://vault.bitwarden.com",
            )),
        })
    }

    pub fn get_item(&self, id: &str) -> Result<BwItemDetail, BackendError> {
        self.items()?
            .iter()
            .find(|item| item.id == id)
            .cloned()
            .ok_or_else(|| BackendError::Message("item not found".into()))
    }

    pub fn apply_action(&self, id: &str, action: ItemAction) -> Result<(), BackendError> {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let mut items = self.items()?;
        let idx = items
            .iter()
            .position(|item| item.id == id)
            .ok_or_else(|| BackendError::Message("item not found".into()))?;
        if !crate::bw::action_allowed(action, items[idx].state) {
            return Err(BackendError::Message(format!(
                "{action:?} is not available for this item"
            )));
        }
        if action == ItemAction::DeleteForever {
            items.remove(idx);
        } else {
            items[idx].state = crate::bw::state_after(action);
            items[idx].dates.state_changed_at = (items[idx].state != ItemState::Active)
                .then(|| crate::bw::iso8601_now());
        }
        Ok(())
    }

    pub fn edit_draft(&self, id: &str) -> Result<ItemDraft, BackendError> {
        let item = self.get_item(id)?;
        let login = (item.item_type == "login").then(|| LoginDraft {
            username: item.username.clone().unwrap_or_default(),
            password: item.password.clone().unwrap_or_default(),
            totp: item.totp.clone().unwrap_or_default(),
            uris: item
                .uris
                .iter()
                .enumerate()
                .map(|(idx, uri)| DraftUri {
                    uri: uri.clone(),
                    original_index: Some(idx),
                })
                .collect(),
        });
        Ok(ItemDraft {
            name: item.name,
            notes: item.notes.unwrap_or_default(),
            login,
            fields: item
                .custom_fields
                .into_iter()
                .enumerate()
                .map(|(idx, field)| DraftField {
                    name: field.name,
                    value: field.value,
                    kind: if field.hidden {
                        DraftFieldKind::Hidden
                    } else {
                        DraftFieldKind::Text
                    },
                    original_index: Some(idx),
                })
                .collect(),
        })
    }

    pub fn create_item(&self, draft: &ItemDraft) -> Result<BwItemDetail, BackendError> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut item = detail(&id, &draft.name, None, None);
        item.password = None;
        if draft.login.is_none() {
            item.item_type = "secureNote".into();
        }
        self.items()?.push(item);
        self.save_item(&id, draft)
    }

    pub fn save_item(&self, id: &str, draft: &ItemDraft) -> Result<BwItemDetail, BackendError> {
        std::thread::sleep(std::time::Duration::from_millis(400));
        if draft.name.trim().is_empty() {
            return Err(BackendError::Message("name is required".into()));
        }
        let mut items = self.items()?;
        let item = items
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| BackendError::Message("item not found".into()))?;
        let non_empty = |value: &str| (!value.is_empty()).then(|| value.to_string());
        item.name = draft.name.clone();
        item.notes = non_empty(&draft.notes);
        if let Some(login) = &draft.login {
            item.username = non_empty(&login.username);
            item.password = non_empty(&login.password);
            item.totp = non_empty(&login.totp);
            item.uris = login
                .uris
                .iter()
                .filter(|uri| !uri.uri.trim().is_empty())
                .map(|uri| uri.uri.clone())
                .collect();
        }
        item.custom_fields = draft
            .fields
            .iter()
            .filter(|field| !field.name.trim().is_empty())
            .map(|field| CustomField {
                name: field.name.clone(),
                value: field.value.clone(),
                hidden: field.kind == DraftFieldKind::Hidden,
            })
            .collect();
        Ok(item.clone())
    }

    pub fn get_totp(&self) -> Result<TotpCode, BackendError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        crate::bw::generate_totp(DEMO_TOTP_SEED, now).map_err(BackendError::from)
    }

    pub fn ssh_approval(&self) -> Option<SshApprovalRequest> {
        self.ssh_request_pending
            .load(Ordering::Relaxed)
            .then(demo_ssh_request)
    }

    pub fn decide_ssh_approval(&self, approved: bool) -> SshApprovalStatus {
        self.ssh_request_pending.store(false, Ordering::Relaxed);
        let request = demo_ssh_request();
        SshApprovalStatus {
            request_id: request.id,
            key_name: request.key_name,
            process_name: request.client.process_name,
            kind: if approved {
                SshApprovalStatusKind::Approved
            } else {
                SshApprovalStatusKind::Denied
            },
            message: if approved {
                "Approved".into()
            } else {
                "Denied".into()
            },
            at_unix_ms: 0,
        }
    }
}

fn detail(id: &str, name: &str, username: Option<&str>, folder: Option<&str>) -> BwItemDetail {
    BwItemDetail {
        id: id.into(),
        name: name.into(),
        username: username.map(Into::into),
        password: Some("correct-horse-battery-staple".into()),
        uris: Vec::new(),
        totp: None,
        notes: None,
        custom_fields: Vec::new(),
        folder: folder.map(Into::into),
        item_type: "login".into(),
        ssh_key: None,
        state: ItemState::Active,
        dates: ItemDates::default(),
    }
}

fn details() -> Vec<BwItemDetail> {
    let mut github = detail(
        "github",
        "GitHub",
        Some("menno@example.com"),
        Some("Development"),
    );
    github.uris = vec!["https://github.com/login".into()];
    github.totp = Some(DEMO_TOTP_SEED.into());
    github.custom_fields = vec![CustomField {
        name: "Recovery code".into(),
        value: "a1b2-c3d4-e5f6".into(),
        hidden: true,
    }];
    github.notes = Some("Personal account.\nSSO for work goes through Okta.".into());

    let mut gitlab = detail(
        "gitlab",
        "GitLab (work)",
        Some("m.vanleeuwen"),
        Some("Work"),
    );
    gitlab.uris = vec!["https://gitlab.com/users/sign_in".into()];

    let mut bank = detail(
        "bank",
        "Bank",
        Some("NL00 BANK 0123 4567 89"),
        Some("Finance"),
    );
    bank.totp = Some(DEMO_TOTP_SEED.into());

    let mut note = detail("wifi", "Home Wi-Fi", None, None);
    note.item_type = "secureNote".into();
    note.password = None;
    note.notes = Some("SSID: Skynet\nPassword: in the drawer".into());

    let mut card = detail("card", "Visa", Some("M. van Leeuwen"), Some("Finance"));
    card.item_type = "card".into();
    card.password = None;
    card.custom_fields = vec![
        CustomField {
            name: "Number".into(),
            value: "4111 1111 1111 1111".into(),
            hidden: true,
        },
        CustomField {
            name: "Expiry".into(),
            value: "12/29".into(),
            hidden: false,
        },
        CustomField {
            name: "CVV".into(),
            value: "123".into(),
            hidden: true,
        },
    ];

    let mut ssh = detail("ssh", "Laptop SSH key", None, Some("Development"));
    ssh.item_type = "sshKey".into();
    ssh.password = None;
    ssh.ssh_key = Some(SshKey {
        id: "ssh".into(),
        name: "Laptop SSH key".into(),
        public_key:
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoDemoDemoDemoDemoDemoDemoDemo menno@laptop"
                .into(),
        private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\ndemo\n-----END OPENSSH PRIVATE KEY-----"
            .into(),
        fingerprint: Some("SHA256:3fGdemo0fingerprint0value0for0the0ui0only".into()),
    });

    let mut items = vec![github, gitlab, bank, note, card, ssh];
    // Archived and trashed items with different dates, so the list sort is visible.
    for (id, name, uri, state, changed, revised) in [
        ("dropbox", "Dropbox (old)", "https://www.dropbox.com/login", ItemState::Archived, "2026-03-02", "2025-11-20"),
        ("evernote", "Evernote", "https://www.evernote.com", ItemState::Archived, "2026-08-14", "2024-06-01"),
        ("aws-old", "AWS (old account)", "https://aws.amazon.com", ItemState::Archived, "2025-12-24", "2026-01-05"),
        ("myspace", "MySpace", "https://myspace.com", ItemState::Deleted, "2026-09-12", "2019-02-02"),
        ("icq", "ICQ", "https://icq.com", ItemState::Deleted, "2026-09-28", "2012-07-07"),
    ] {
        let mut item = detail(id, name, Some("menno"), None);
        item.uris = vec![uri.into()];
        item.state = state;
        item.dates = ItemDates {
            state_changed_at: Some(format!("{changed}T10:00:00.000Z")),
            revision_date: Some(format!("{revised}T10:00:00.000Z")),
            creation_date: Some("2018-01-01T10:00:00.000Z".into()),
        };
        items.push(item);
    }
    for (idx, (name, uri)) in [
        ("Grafana", "https://grafana.com"),
        ("Gmail", "https://mail.google.com"),
        ("Google Cloud", "https://console.cloud.google.com"),
        ("Gitea", "https://gitea.com"),
        // A LAN host: never sent to the icon service.
        ("Home Assistant", "http://homeassistant.local:8123"),
    ]
    .iter()
    .enumerate()
    {
        let mut item = detail(&format!("extra-{idx}"), name, Some("menno"), Some("Homelab"));
        item.uris = vec![(*uri).into()];
        items.push(item);
    }
    // Spread edit and creation dates over the active items so the start lists differ.
    for (idx, item) in items.iter_mut().enumerate() {
        if item.state == ItemState::Active {
            let day = |offset: usize| format!("2026-{:02}-{:02}T09:00:00.000Z", 1 + idx % 9, 1 + (idx * 7 + offset) % 28);
            item.dates.revision_date = Some(day(idx * 3));
            item.dates.creation_date = Some(format!("20{:02}-06-01T09:00:00.000Z", 15 + (idx * 5) % 11));
        }
    }
    items
}

fn demo_ssh_request() -> SshApprovalRequest {
    // A fixed expiry in the current minute keeps the countdown moving without state.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    SshApprovalRequest {
        id: "demo-request".into(),
        kind: SshApprovalKind::Sign,
        key_id: "ssh".into(),
        key_name: "Laptop SSH key".into(),
        public_key: String::new(),
        fingerprint: Some("SHA256:3fGdemo0fingerprint0value0for0the0ui0only".into()),
        algorithm: "ssh-ed25519".into(),
        client: SshAgentClientInfo {
            pid: 4242,
            uid: 1000,
            gid: 1000,
            ppid: Some(4200),
            start_time_ticks: None,
            process_name: Some("ssh".into()),
            command_line: Some(
                "ssh git@git.example.com git-upload-pack 'menno/dotfiles.git'".into(),
            ),
            executable: Some("/usr/bin/ssh".into()),
            cwd: Some("/home/menno/Projects/bw-quick-access".into()),
            parent_pid: Some(4200),
            parent_name: Some("git".into()),
            parent_start_time_ticks: None,
        },
        created_at_unix_ms: now_ms,
        expires_at_unix_ms: (now_ms / 60_000 + 1) * 60_000,
    }
}
