use crate::bw::TwoFactorProvider;
use crate::config::AppSettings;
use crate::model::{
    BwItem, BwItemDetail, SshAgentStatus, SshApprovalDecision, SshApprovalRequest,
    SshApprovalStatus, SyncStatus,
};
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

const SOCKET_NAME: &str = "bw-quick-access-rpc.sock";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum RpcRequest {
    HasSession,
    Login {
        server_url: String,
        email: String,
        password: String,
        remember: bool,
    },
    CompleteTwoFactor {
        provider: TwoFactorProvider,
        token: String,
        remember: bool,
    },
    ListItems {
        query: String,
    },
    GetItem {
        id: String,
    },
    GetTotp {
        id: String,
    },
    ApplySettings(AppSettings),
    GetSshAgentStatus,
    GetSshApproval,
    DecideSshApproval(SshApprovalDecision),
    GetSshApprovalStatus,
    LockVault,
    ClearSavedSession,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum RpcResponse {
    HasSession(bool),
    Login(Result<(), RpcError>),
    TwoFactor(Result<(), RpcError>),
    Search(Result<SearchPayload, RpcError>),
    Detail(Result<BwItemDetail, RpcError>),
    Totp(Result<String, RpcError>),
    SettingsApplied(Result<SshAgentStatus, String>),
    SshAgentStatus(SshAgentStatus),
    SshApproval(Option<SshApprovalRequest>),
    SshApprovalDecided(Result<SshApprovalStatus, String>),
    SshApprovalStatus(Option<SshApprovalStatus>),
    LockVault(Result<(), String>),
    ClearSavedSession(Result<(), String>),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RpcError {
    Message(String),
    TwoFactorRequired { providers: Vec<TwoFactorProvider> },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SearchPayload {
    pub items: Vec<BwItem>,
    pub warning: Option<String>,
    pub status: SyncStatus,
}

#[derive(Debug, Clone)]
pub struct RpcClient {
    socket_path: PathBuf,
}

impl RpcClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    pub fn call(&self, request: &RpcRequest) -> Result<RpcResponse, String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| format!("could not connect to daemon: {e}"))?;
        let payload = serde_json::to_vec(request)
            .map_err(|e| format!("could not encode daemon request: {e}"))?;
        stream
            .write_all(&payload)
            .map_err(|e| format!("could not send daemon request: {e}"))?;
        let _ = stream.shutdown(Shutdown::Write);

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| format!("could not read daemon response: {e}"))?;
        serde_json::from_str(&response)
            .map_err(|e| format!("could not decode daemon response: {e}"))
    }
}

pub fn prepare_listener() -> io::Result<(PathBuf, UnixListener)> {
    let path = socket_path();
    let _ = fs::remove_file(&path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(&path)?;
    Ok((path, listener))
}

fn socket_path() -> PathBuf {
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join(SOCKET_NAME);
    }

    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    std::env::temp_dir()
        .join(format!("bw-quick-access-{user}"))
        .join(SOCKET_NAME)
}
