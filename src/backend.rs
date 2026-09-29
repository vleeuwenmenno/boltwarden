use crate::bw::{BwClient, BwError, TwoFactorChallenge, TwoFactorProvider};
use crate::config::{self, AppSettings};
use crate::demo::DemoBackend;
use crate::model::{
    BwItem, BwItemDetail, SshAgentStatus, SshApprovalDecision, SshApprovalRequest,
    SshApprovalStatus, SyncStatus, TotpCode,
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
    Message(String),
    TwoFactorRequired(Vec<TwoFactorProvider>),
}

pub struct SearchResult {
    pub items: Vec<BwItem>,
    pub warning: Option<String>,
    pub status: SyncStatus,
}

impl AppBackend {
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

    pub fn list_items(&self, query: &str) -> Result<SearchResult, BackendError> {
        match self {
            Self::Local(local) => {
                let backend = local
                    .lock()
                    .map_err(|_| BackendError::Message("session lock poisoned".into()))?;
                let items = backend.bw.list_items(query).map_err(BackendError::from)?;
                Ok(SearchResult {
                    items,
                    warning: backend.bw.sync_warning(),
                    status: backend.bw.sync_status(),
                })
            }
            Self::Demo(demo) => demo.list_items(query),
            Self::Remote(client) => match client.call(&RpcRequest::ListItems {
                query: query.to_string(),
            }) {
                Ok(RpcResponse::Search(result)) => result
                    .map(|payload| SearchResult {
                        items: payload.items,
                        warning: payload.warning,
                        status: payload.status,
                    })
                    .map_err(BackendError::from),
                Ok(_) => Err(BackendError::Message(
                    "unexpected daemon search response".into(),
                )),
                Err(e) => Err(BackendError::Message(e)),
            },
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
            Self::Local(_) => {
                config::save_settings(settings).map_err(|e| e.to_string())?;
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
        let saved = config::load_saved_session();
        let result = if let Some(saved) = saved.filter(|saved| {
            saved.server_url.trim_end_matches('/') == server_url.trim_end_matches('/')
                && saved.email.eq_ignore_ascii_case(email.trim())
        }) {
            self.bw.unlock_saved_session(&saved, password)
        } else {
            self.bw.login(server_url, email, password, remember)
        };

        match result {
            Ok(()) => {
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
        match self
            .bw
            .complete_two_factor(&challenge, provider, token, remember)
        {
            Ok(()) => {
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
            RpcError::Message(message) => Self::Message(message),
            RpcError::TwoFactorRequired { providers } => Self::TwoFactorRequired(providers),
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => write!(f, "{message}"),
            Self::TwoFactorRequired(_) => write!(f, "two factor required"),
        }
    }
}

impl std::error::Error for BackendError {}
