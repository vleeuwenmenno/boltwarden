use crate::bw::{BwClient, BwError, TwoFactorChallenge, TwoFactorProvider};
use crate::config::{self, AppSettings};
use crate::demo::DemoBackend;
use crate::model::{
    BwItem, BwItemDetail, Folder, HealthReport, ItemAction, ItemDraft, ItemState, SshAgentStatus,
    SshApprovalDecision, SshApprovalRequest, SshApprovalStatus, SyncStatus, TotpCode,
};
use crate::rpc::{RpcClient, RpcError, RpcRequest, RpcResponse};
use std::fmt;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub enum AppBackend {
    Local(Arc<Mutex<LocalBackend>>),
    Remote(RpcClient),
    Demo(Arc<DemoBackend>),
}

pub struct LocalBackend {
    bw: BwClient,
    pending_two_factor: Option<TwoFactorChallenge>,
}

#[derive(Debug, Clone)]
pub enum BackendError {
    RepromptRequired,
    Network(String),
    Message(String),
    TwoFactorRequired(Vec<TwoFactorProvider>),
}

pub struct SearchResult {
    pub items: Vec<BwItem>,
    pub warning: Option<String>,
    pub status: SyncStatus,
    pub icons_url: Option<String>,
}

impl AppBackend {
    pub fn shortcut_status(&self) -> Result<crate::shortcut::Status, String> {
        match self {
            Self::Remote(client) => match client.call(&RpcRequest::GetShortcut)? {
                RpcResponse::Shortcut(result) => result,
                _ => Err("Unexpected shortcut response".into()),
            },
            _ => Ok(crate::shortcut::Status::unavailable(
                "Demo: shortcut changes are not applied",
            )),
        }
    }

    pub fn set_shortcut(
        &self,
        value: Option<crate::shortcut::Shortcut>,
    ) -> Result<crate::shortcut::Status, String> {
        match self {
            Self::Remote(client) => match client.call(&RpcRequest::SetShortcut(value))? {
                RpcResponse::Shortcut(result) => result,
                _ => Err("Unexpected shortcut response".into()),
            },
            _ => Err("Shortcut changes require the running daemon".into()),
        }
    }

    pub fn shortcut_binding(&self, value: crate::shortcut::Shortcut) -> Result<String, String> {
        match self {
            Self::Remote(client) => match client.call(&RpcRequest::ShortcutBinding(value))? {
                RpcResponse::ShortcutBinding(result) => result,
                _ => Err("Unexpected shortcut response".into()),
            },
            _ => crate::shortcut::binding(&value),
        }
    }

    pub fn browser_approval(&self) -> Option<crate::browser_approval::BrowserApprovalRequest> {
        match self {
            Self::Remote(client) => match client.call(&RpcRequest::GetBrowserApproval) {
                Ok(RpcResponse::BrowserApproval(request)) => request,
                _ => None,
            },
            _ => None,
        }
    }

    pub fn decide_browser_approval(
        &self,
        decision: crate::browser_approval::BrowserApprovalDecision,
    ) -> Result<(), String> {
        match self {
            Self::Remote(client) => {
                match client.call(&RpcRequest::DecideBrowserApproval(decision))? {
                    RpcResponse::BrowserApprovalDecided(result) => result,
                    _ => Err("Unexpected browser approval response".into()),
                }
            }
            _ => Err("Browser integration requires the daemon".into()),
        }
    }

    pub fn paired_browsers(&self) -> Result<Vec<crate::browser::pairing::PairingRecord>, String> {
        match self {
            Self::Remote(client) => match client.call(&RpcRequest::ListPairedBrowsers)? {
                RpcResponse::PairedBrowsers(result) => result,
                _ => Err("Unexpected paired browsers response".into()),
            },
            Self::Local(_) => Err("Browser integration requires the daemon".into()),
            Self::Demo(_) => Ok(Vec::new()),
        }
    }

    pub fn revoke_browser(&self, id: String) -> Result<(), String> {
        match self {
            Self::Remote(client) => match client.call(&RpcRequest::RevokePairedBrowser { id })? {
                RpcResponse::BrowserRevoked(result) => result,
                _ => Err("Unexpected browser revocation response".into()),
            },
            _ => Err("Browser integration requires the daemon".into()),
        }
    }

    pub fn cancel_unlock(&self) {
        if let Self::Remote(client) = self {
            let _ = client.send(&RpcRequest::CancelUnlock);
        }
    }

    pub fn local() -> Self {
        Self::Local(Arc::new(Mutex::new(LocalBackend {
            bw: BwClient::new(),
            pending_two_factor: None,
        })))
    }

    pub fn remote(client: RpcClient) -> Self {
        Self::Remote(client)
    }

    pub fn demo() -> Self {
        Self::Demo(Arc::new(DemoBackend::new()))
    }

    pub fn security_warning(&self) -> Option<String> {
        match self {
            Self::Remote(client) => match client.call(&RpcRequest::SecurityWarning) {
                Ok(RpcResponse::SecurityWarning(warning)) => warning,
                _ => Some("Could not check automatic locking status".into()),
            },
            Self::Local(_) => {
                Some("Standalone popup: automatic session locking is unavailable".into())
            }
            Self::Demo(_) => None,
        }
    }

    pub fn has_session(&self) -> bool {
        match self {
            Self::Local(local) => local
                .lock()
                .map(|backend| backend.bw.has_session())
                .unwrap_or(false),
            Self::Demo(demo) => demo.has_session(),
            Self::Remote(client) => match client.call(&RpcRequest::HasSession) {
                Ok(RpcResponse::HasSession(has_session)) => has_session,
                _ => false,
            },
        }
    }

    pub fn login(
        &self,
        server_url: &str,
        email: &str,
        password: &str,
        remember: bool,
    ) -> Result<(), BackendError> {
        match self {
            Self::Local(local) => local
                .lock()
                .map_err(|_| BackendError::Message("session lock poisoned".into()))?
                .login(server_url, email, password, remember),
            Self::Demo(demo) => demo.login(password),
            Self::Remote(client) => match client.call(&RpcRequest::Login {
                server_url: server_url.to_string(),
                email: email.to_string(),
                password: password.to_string(),
                remember,
            }) {
                Ok(RpcResponse::Login(result)) => result.map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon login response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
        }
    }

    pub fn complete_two_factor(
        &self,
        provider: TwoFactorProvider,
        token: &str,
        remember: bool,
    ) -> Result<(), BackendError> {
        match self {
            Self::Local(local) => local
                .lock()
                .map_err(|_| BackendError::Message("session lock poisoned".into()))?
                .complete_two_factor(provider, token, remember),
            Self::Demo(demo) => demo.complete_two_factor(),
            Self::Remote(client) => match client.call(&RpcRequest::CompleteTwoFactor {
                provider,
                token: token.to_string(),
                remember,
            }) {
                Ok(RpcResponse::TwoFactor(result)) => result.map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon two factor response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
        }
    }

    pub fn sync(&self) -> Result<SyncStatus, BackendError> {
        match self {
            Self::Local(local) => local
                .lock()
                .map_err(|_| BackendError::Message("session lock poisoned".into()))?
                .bw
                .sync_now()
                .map_err(BackendError::from),
            Self::Demo(demo) => demo
                .list_items(ItemState::Active, "")
                .map(|result| result.status),
            Self::Remote(client) => match client.call(&RpcRequest::Sync) {
                Ok(RpcResponse::Synced(result)) => result.map_err(BackendError::from),
                Err(error) => Err(BackendError::Message(error)),
                _ => Err(BackendError::Message("Unexpected sync response".into())),
            },
        }
    }

    pub fn list_items(&self, state: ItemState, query: &str) -> Result<SearchResult, BackendError> {
        match self {
            Self::Local(local) => {
                let mut backend = local
                    .lock()
                    .map_err(|_| BackendError::Message("session lock poisoned".into()))?;
                backend.bw.sync_if_stale();
                let items = backend
                    .bw
                    .list_items_in(state, query)
                    .map_err(BackendError::from)?;
                Ok(SearchResult {
                    items,
                    warning: backend.bw.sync_warning(),
                    status: backend.bw.sync_status(),
                    icons_url: Some(backend.bw.icons_url()),
                })
            }
            Self::Demo(demo) => demo.list_items(state, query),
            Self::Remote(client) => match client.call(&RpcRequest::ListItems {
                query: query.to_string(),
                state,
            }) {
                Ok(RpcResponse::Search(result)) => result
                    .map(|payload| SearchResult {
                        items: payload.items,
                        warning: payload.warning,
                        status: payload.status,
                        icons_url: payload.icons_url,
                    })
                    .map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon search response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
        }
    }

    pub fn authorize_item(&self, id: &str, password: &str) -> Result<BwItemDetail, BackendError> {
        match self {
            Self::Local(local) => local
                .lock()
                .map_err(|_| BackendError::Message("session lock poisoned".into()))?
                .bw
                .authorize_item(id, password)
                .map_err(BackendError::from),
            Self::Demo(demo) => demo.get_item(id),
            Self::Remote(client) => match client.call(&RpcRequest::AuthorizeItem {
                id: id.into(),
                password: password.into(),
            }) {
                Ok(RpcResponse::Detail(result)) => result.map_err(BackendError::from),
                _ => Err(BackendError::Message("Could not verify item access".into())),
            },
        }
    }

    pub fn revoke_item_grants(&self) {
        match self {
            Self::Local(local) => {
                if let Ok(mut local) = local.lock() {
                    local.bw.revoke_item_grants();
                }
            }
            Self::Remote(client) => {
                let _ = client.call(&RpcRequest::RevokeItemGrants);
            }
            Self::Demo(_) => {}
        }
    }

    pub fn copy_field(&self, id: &str, index: usize, version: [u8; 32]) -> Result<(), String> {
        match self {
            Self::Remote(client) => match client.call(&RpcRequest::CopyField {
                id: id.into(),
                index,
                version,
            }) {
                Ok(RpcResponse::Copied(result)) => result,
                Err(error) => Err(error),
                _ => Err("Unexpected clipboard response".into()),
            },
            Self::Demo(_) => Err("Clipboard copying is disabled in demo mode".into()),
            Self::Local(_) => Err("Run the daemon to use secure clipboard copying".into()),
        }
    }

    pub fn get_item(&self, id: &str) -> Result<BwItemDetail, BackendError> {
        match self {
            Self::Local(local) => local
                .lock()
                .map_err(|_| BackendError::Message("session lock poisoned".into()))?
                .bw
                .get_item(id)
                .map_err(BackendError::from),
            Self::Demo(demo) => demo.get_item(id),
            Self::Remote(client) => match client.call(&RpcRequest::GetItem { id: id.into() }) {
                Ok(RpcResponse::Detail(result)) => result.map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon detail response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
        }
    }

    pub fn get_totp(&self, id: &str) -> Result<TotpCode, BackendError> {
        match self {
            Self::Local(local) => local
                .lock()
                .map_err(|_| BackendError::Message("session lock poisoned".into()))?
                .bw
                .get_totp(id)
                .map_err(BackendError::from),
            Self::Demo(demo) => demo.get_totp(),
            Self::Remote(client) => match client.call(&RpcRequest::GetTotp { id: id.into() }) {
                Ok(RpcResponse::Totp(result)) => result.map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon TOTP response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
        }
    }

    pub fn apply_action(&self, id: &str, action: ItemAction) -> Result<(), BackendError> {
        match self {
            Self::Local(local) => local
                .lock()
                .map_err(|_| BackendError::Message("session lock poisoned".into()))?
                .bw
                .apply_action(id, action)
                .map_err(BackendError::from),
            Self::Demo(demo) => demo.apply_action(id, action),
            Self::Remote(client) => match client.call(&RpcRequest::ItemAction {
                id: id.into(),
                action,
            }) {
                Ok(RpcResponse::ItemAction(result)) => result.map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon item action response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
        }
    }

    pub fn edit_draft(&self, id: &str) -> Result<ItemDraft, BackendError> {
        match self {
            Self::Local(local) => local
                .lock()
                .map_err(|_| BackendError::Message("session lock poisoned".into()))?
                .bw
                .edit_draft(id)
                .map_err(BackendError::from),
            Self::Demo(demo) => demo.edit_draft(id),
            Self::Remote(client) => {
                match client.call(&RpcRequest::GetEditDraft { id: id.into() }) {
                    Ok(RpcResponse::EditDraft(result)) => result.map_err(BackendError::from),
                    Ok(_) => Err(BackendError::Message(
                        "unexpected daemon edit draft response".into(),
                    )),
                    Err(e) => Err(BackendError::Message(e)),
                }
            }
        }
    }

    pub fn save_item(&self, id: &str, draft: &ItemDraft) -> Result<BwItemDetail, BackendError> {
        match self {
            Self::Local(local) => local
                .lock()
                .map_err(|_| BackendError::Message("session lock poisoned".into()))?
                .bw
                .save_item(id, draft)
                .map_err(BackendError::from),
            Self::Demo(demo) => demo.save_item(id, draft),
            Self::Remote(client) => match client.call(&RpcRequest::SaveItem {
                id: id.into(),
                draft: draft.clone(),
            }) {
                Ok(RpcResponse::Saved(result)) => result.map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon save response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
        }
    }

    pub fn create_item(&self, draft: &ItemDraft) -> Result<BwItemDetail, BackendError> {
        match self {
            Self::Local(local) => local
                .lock()
                .map_err(|_| BackendError::Message("session lock poisoned".into()))?
                .bw
                .create_item(draft)
                .map_err(BackendError::from),
            Self::Demo(demo) => demo.create_item(draft),
            Self::Remote(client) => match client.call(&RpcRequest::CreateItem {
                draft: draft.clone(),
            }) {
                Ok(RpcResponse::Created(result)) => result.map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon create response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
        }
    }

    pub fn folders(&self) -> Result<Vec<Folder>, BackendError> {
        match self {
            Self::Local(local) => local
                .lock()
                .map_err(|_| BackendError::Message("session lock poisoned".into()))?
                .bw
                .folders()
                .map_err(BackendError::from),
            Self::Demo(demo) => demo.folders(),
            Self::Remote(client) => match client.call(&RpcRequest::ListFolders) {
                Ok(RpcResponse::Folders(result)) => result.map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon folders response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
        }
    }

    fn with_local<T>(
        local: &Mutex<LocalBackend>,
        work: impl FnOnce(&mut BwClient) -> Result<T, BwError>,
    ) -> Result<T, BackendError> {
        let mut local = local
            .lock()
            .map_err(|_| BackendError::Message("session lock poisoned".into()))?;
        work(&mut local.bw).map_err(BackendError::from)
    }

    pub fn move_item(&self, id: &str, folder_id: Option<&str>) -> Result<(), BackendError> {
        match self {
            Self::Local(local) => Self::with_local(local, |bw| bw.move_item(id, folder_id)),
            Self::Demo(demo) => demo.move_item(id, folder_id),
            Self::Remote(client) => match client.call(&RpcRequest::MoveItem {
                id: id.into(),
                folder_id: folder_id.map(Into::into),
            }) {
                Ok(RpcResponse::ItemMoved(result)) => result.map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon move response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
        }
    }

    pub fn create_folder(&self, name: &str) -> Result<Folder, BackendError> {
        match self {
            Self::Local(local) => Self::with_local(local, |bw| bw.create_folder(name)),
            Self::Demo(demo) => demo.create_folder(name),
            Self::Remote(client) => {
                match client.call(&RpcRequest::CreateFolder { name: name.into() }) {
                    Ok(RpcResponse::FolderCreated(result)) => result.map_err(BackendError::from),
                    Ok(_) => Err(BackendError::Message(
                        "unexpected daemon folder response".into(),
                    )),
                    Err(e) => Err(BackendError::Message(e)),
                }
            }
        }
    }

    pub fn rename_folders(&self, renames: &[(String, String)]) -> Result<(), BackendError> {
        match self {
            Self::Local(local) => Self::with_local(local, |bw| bw.rename_folders(renames)),
            Self::Demo(demo) => demo.rename_folders(renames),
            Self::Remote(client) => match client.call(&RpcRequest::RenameFolders {
                renames: renames.to_vec(),
            }) {
                Ok(RpcResponse::FoldersChanged(result)) => result.map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon folder response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
        }
    }

    pub fn delete_folders(&self, ids: &[String]) -> Result<(), BackendError> {
        match self {
            Self::Local(local) => Self::with_local(local, |bw| bw.delete_folders(ids)),
            Self::Demo(demo) => demo.delete_folders(ids),
            Self::Remote(client) => {
                match client.call(&RpcRequest::DeleteFolders { ids: ids.to_vec() }) {
                    Ok(RpcResponse::FoldersChanged(result)) => result.map_err(BackendError::from),
                    Ok(_) => Err(BackendError::Message(
                        "unexpected daemon folder response".into(),
                    )),
                    Err(e) => Err(BackendError::Message(e)),
                }
            }
        }
    }

    pub fn health_report(&self) -> Result<HealthReport, BackendError> {
        match self {
            Self::Local(local) => {
                let directory = crate::health::directory();
                local
                    .lock()
                    .map_err(|_| BackendError::Message("session lock poisoned".into()))?
                    .bw
                    .health_report(&directory)
                    .map_err(BackendError::from)
            }
            Self::Demo(demo) => demo.health_report(),
            Self::Remote(client) => match client.call(&RpcRequest::VaultHealth) {
                Ok(RpcResponse::Health(result)) => result.map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon health response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
        }
    }

    /// Asks the daemon to show the vault window.
    pub fn open_window(&self) -> Result<(), String> {
        match self {
            Self::Local(_) => Err("Run the daemon to open the vault window".into()),
            Self::Demo(_) => Err("The vault window runs on its own in demo mode: --window".into()),
            Self::Remote(client) => match client.call(&RpcRequest::OpenWindow) {
                Ok(RpcResponse::WindowOpened(result)) => result,
                Ok(_) => Err("unexpected daemon window response".into()),
                Err(e) => Err(e),
            },
        }
    }

    pub fn clear_saved_session(&self) -> Result<(), String> {
        match self {
            Self::Local(local) => {
                config::clear_saved_session().map_err(|e| e.to_string())?;
                let _ = config::clear_recent_item();
                if let Ok(mut backend) = local.lock() {
                    backend.bw = BwClient::new();
                    backend.pending_two_factor = None;
                }
                Ok(())
            }
            Self::Demo(demo) => {
                demo.lock();
                Ok(())
            }
            Self::Remote(client) => match client.call(&RpcRequest::ClearSavedSession) {
                Ok(RpcResponse::ClearSavedSession(result)) => result,
                Ok(_) => Err("unexpected daemon forget-user response".into()),
                Err(e) => Err(e),
            },
        }
    }

    pub fn lock_vault(&self) -> Result<(), String> {
        match self {
            Self::Local(local) => {
                let mut backend = local
                    .lock()
                    .map_err(|_| "session lock poisoned".to_string())?;
                backend.bw = BwClient::new();
                backend.pending_two_factor = None;
                let _ = config::clear_recent_item();
                Ok(())
            }
            Self::Demo(demo) => {
                demo.lock();
                Ok(())
            }
            Self::Remote(client) => match client.call(&RpcRequest::LockVault) {
                Ok(RpcResponse::LockVault(result)) => result,
                Ok(_) => Err("unexpected daemon lock-vault response".into()),
                Err(e) => Err(e),
            },
        }
    }

    pub fn apply_settings(&self, settings: &AppSettings) -> Result<SshAgentStatus, String> {
        match self {
            Self::Local(local) => {
                config::save_settings(settings).map_err(|e| e.to_string())?;
                local
                    .lock()
                    .map_err(|_| "session lock poisoned".to_string())?
                    .bw
                    .apply_offline_setting()
                    .map_err(|e| e.to_string())?;
                Ok(local_ssh_agent_status(settings))
            }
            Self::Demo(_) => Ok(local_ssh_agent_status(settings)),
            Self::Remote(client) => match client.call(&RpcRequest::ApplySettings(settings.clone()))
            {
                Ok(RpcResponse::SettingsApplied(result)) => result,
                Ok(_) => Err("unexpected daemon settings response".into()),
                Err(e) => Err(e),
            },
        }
    }

    pub fn ssh_agent_status(&self, settings: &AppSettings) -> SshAgentStatus {
        match self {
            Self::Local(_) => local_ssh_agent_status(settings),
            Self::Demo(_) => local_ssh_agent_status(settings),
            Self::Remote(client) => match client.call(&RpcRequest::GetSshAgentStatus) {
                Ok(RpcResponse::SshAgentStatus(status)) => status,
                _ => local_ssh_agent_status(settings),
            },
        }
    }

    pub fn ssh_approval(&self) -> Option<SshApprovalRequest> {
        match self {
            Self::Local(_) => None,
            Self::Demo(demo) => demo.ssh_approval(),
            Self::Remote(client) => match client.call(&RpcRequest::GetSshApproval) {
                Ok(RpcResponse::SshApproval(request)) => request,
                _ => None,
            },
        }
    }

    pub fn decide_ssh_approval(
        &self,
        decision: SshApprovalDecision,
    ) -> Result<SshApprovalStatus, String> {
        match self {
            Self::Local(_) => Err("SSH approval is only available in daemon mode".into()),
            Self::Demo(demo) => Ok(demo.decide_ssh_approval(decision.approved)),
            Self::Remote(client) => match client.call(&RpcRequest::DecideSshApproval(decision)) {
                Ok(RpcResponse::SshApprovalDecided(result)) => result,
                Ok(_) => Err("unexpected daemon SSH approval response".into()),
                Err(e) => Err(e),
            },
        }
    }

    pub fn send_ssh_approval_decision(&self, decision: SshApprovalDecision) -> Result<(), String> {
        match self {
            Self::Local(_) => Err("SSH approval is only available in daemon mode".into()),
            Self::Demo(demo) => {
                demo.decide_ssh_approval(decision.approved);
                Ok(())
            }
            Self::Remote(client) => client.send(&RpcRequest::DecideSshApproval(decision)),
        }
    }

    pub fn ssh_approval_status(&self) -> Option<SshApprovalStatus> {
        match self {
            Self::Local(_) => None,
            Self::Demo(_) => None,
            Self::Remote(client) => match client.call(&RpcRequest::GetSshApprovalStatus) {
                Ok(RpcResponse::SshApprovalStatus(status)) => status,
                _ => None,
            },
        }
    }
}

fn local_ssh_agent_status(settings: &AppSettings) -> SshAgentStatus {
    SshAgentStatus {
        enabled: settings.ssh_agent_enabled,
        active: false,
        socket_path: config::expand_ssh_agent_socket_path(&settings.ssh_agent_socket_path)
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| settings.ssh_agent_socket_path.clone()),
        identity_count: 0,
        skipped_count: 0,
        message: if settings.ssh_agent_enabled {
            "SSH agent is only available in daemon mode".into()
        } else {
            "SSH agent disabled".into()
        },
    }
}

impl LocalBackend {
    fn login(
        &mut self,
        server_url: &str,
        email: &str,
        password: &str,
        remember: bool,
    ) -> Result<(), BackendError> {
        let mut candidate = BwClient::new();
        let saved = config::load_saved_session();
        let result = if let Some(saved) = saved.filter(|saved| {
            saved.server_url.trim_end_matches('/') == server_url.trim_end_matches('/')
                && saved.email.eq_ignore_ascii_case(email.trim())
        }) {
            candidate.unlock_saved_session(&saved, password)
        } else {
            candidate.login(server_url, email, password, remember)
        };

        match result {
            Ok(()) => {
                self.bw = candidate;
                self.pending_two_factor = None;
                Ok(())
            }
            Err(BwError::TwoFactorRequired(challenge)) => {
                let providers = challenge.providers().to_vec();
                self.pending_two_factor = Some(challenge);
                Err(BackendError::TwoFactorRequired(providers))
            }
            Err(e) => Err(BackendError::from(e)),
        }
    }

    fn complete_two_factor(
        &mut self,
        provider: TwoFactorProvider,
        token: &str,
        remember: bool,
    ) -> Result<(), BackendError> {
        let Some(challenge) = self.pending_two_factor.clone() else {
            return Err(BackendError::Message("missing two factor challenge".into()));
        };
        let mut candidate = BwClient::new();
        match candidate.complete_two_factor(&challenge, provider, token, remember) {
            Ok(()) => {
                self.bw = candidate;
                self.pending_two_factor = None;
                Ok(())
            }
            Err(e) => Err(BackendError::from(e)),
        }
    }
}

impl From<BwError> for BackendError {
    fn from(error: BwError) -> Self {
        match error {
            BwError::Network(message) => Self::Network(message),
            BwError::RepromptRequired => Self::RepromptRequired,
            BwError::TwoFactorRequired(challenge) => {
                Self::TwoFactorRequired(challenge.providers().to_vec())
            }
            other => Self::Message(other.to_string()),
        }
    }
}

impl From<RpcError> for BackendError {
    fn from(error: RpcError) -> Self {
        match error {
            RpcError::RepromptRequired => Self::RepromptRequired,
            RpcError::Network(message) => Self::Network(message),
            RpcError::Message(message) => Self::Message(message),
            RpcError::TwoFactorRequired { providers } => Self::TwoFactorRequired(providers),
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RepromptRequired => write!(f, "Master password required for this item"),
            Self::Network(message) | Self::Message(message) => write!(f, "{message}"),
            Self::TwoFactorRequired(_) => write!(f, "two factor required"),
        }
    }
}

impl std::error::Error for BackendError {}

#[cfg(test)]
mod browser_management_tests {
    use super::*;
    use crate::platform::ipc::Listener as UnixListener;
    use std::io::{Read, Write};

    #[test]
    fn paired_browser_list_preserves_daemon_errors_and_rejects_unexpected_responses() {
        let path = std::env::temp_dir().join(format!("bw-list-test-{}", uuid::Uuid::new_v4()));
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            for response in [
                RpcResponse::PairedBrowsers(Err("Pairing store unreadable".into())),
                RpcResponse::PairedBrowsers(Ok(Vec::new())),
                RpcResponse::HasSession(true),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                #[cfg(unix)]
                let mut request = String::new();
                #[cfg(unix)]
                stream.read_to_string(&mut request).unwrap();
                #[cfg(windows)]
                let request = {
                    let mut length = [0; 4];
                    stream.read_exact(&mut length).unwrap();
                    let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
                    stream.read_exact(&mut bytes).unwrap();
                    String::from_utf8(bytes).unwrap()
                };
                let request: crate::rpc::RpcEnvelope = serde_json::from_str(&request).unwrap();
                assert!(matches!(request.request, RpcRequest::ListPairedBrowsers));
                let payload = serde_json::to_vec(&response).unwrap();
                #[cfg(windows)]
                stream
                    .write_all(&(payload.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(&payload).unwrap();
                #[cfg(windows)]
                stream.read_exact(&mut [0; 1]).unwrap();
            }
        });
        let backend = AppBackend::remote(RpcClient::new(path.clone(), "test-token".into()));
        assert_eq!(
            backend.paired_browsers().unwrap_err(),
            "Pairing store unreadable"
        );
        assert!(backend.paired_browsers().unwrap().is_empty());
        assert_eq!(
            backend.paired_browsers().unwrap_err(),
            "Unexpected paired browsers response"
        );
        server.join().unwrap();
        #[cfg(unix)]
        std::fs::remove_file(path).unwrap();
        assert!(
            backend
                .paired_browsers()
                .unwrap_err()
                .contains("could not connect to daemon")
        );
    }
}
