use crate::bw::TwoFactorProvider;
use crate::config::AppSettings;
use crate::model::{
    BwItem, BwItemDetail, SshAgentStatus, SshApprovalDecision, SshApprovalRequest,
    SshApprovalStatus, SyncStatus, TotpCode,
};
use crate::unix_socket;
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
    Totp(Result<TotpCode, RpcError>),
    SettingsApplied(Result<SshAgentStatus, String>),
    SshAgentStatus(SshAgentStatus),
    SshApproval(Option<SshApprovalRequest>),
    SshApprovalDecided(Result<SshApprovalStatus, String>),
    SshApprovalStatus(Option<SshApprovalStatus>),
    LockVault(Result<(), String>),
    ClearSavedSession(Result<(), String>),
    /// The request was rejected before it reached a handler (bad token, unreadable body).
    Error(String),
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

/// What the popup sends: the request plus the per-daemon secret proving it was started
/// by the daemon. Any other process running as the user can reach the socket, so the
/// socket permissions alone are not enough to protect vault data and SSH approvals.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RpcEnvelope {
    pub token: String,
    pub request: RpcRequest,
}

/// Largest request body the daemon reads before authenticating it.
pub const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

/// Where the vault RPC listens and the secret a client needs to use it. The daemon hands
/// the token to the popups it spawns over their stdin pipe, never via argv or environment.
#[derive(Debug, Clone)]
pub struct RpcEndpoint {
    pub path: PathBuf,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct RpcClient {
    socket_path: PathBuf,
    token: String,
}

impl RpcClient {
    pub fn new(socket_path: PathBuf, token: String) -> Self {
        Self { socket_path, token }
    }

    pub fn call(&self, request: &RpcRequest) -> Result<RpcResponse, String> {
        let mut stream = self.write_request(request)?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| format!("could not read daemon response: {e}"))?;
        match serde_json::from_str(&response)
            .map_err(|e| format!("could not decode daemon response: {e}"))?
        {
            RpcResponse::Error(message) => Err(message),
            response => Ok(response),
        }
    }

    pub fn send(&self, request: &RpcRequest) -> Result<(), String> {
        self.write_request(request).map(|_| ())
    }

    fn write_request(&self, request: &RpcRequest) -> Result<UnixStream, String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| format!("could not connect to daemon: {e}"))?;
        let envelope = EnvelopeRef {
            token: &self.token,
            request,
        };
        let payload = serde_json::to_vec(&envelope)
            .map_err(|e| format!("could not encode daemon request: {e}"))?;
        stream
            .write_all(&payload)
            .map_err(|e| format!("could not send daemon request: {e}"))?;
        let _ = stream.shutdown(Shutdown::Write);
        Ok(stream)
    }
}

#[derive(serde::Serialize)]
struct EnvelopeRef<'a> {
    token: &'a str,
    request: &'a RpcRequest,
}

pub fn prepare_listener() -> io::Result<(RpcEndpoint, UnixListener)> {
    let path = unix_socket::runtime_dir()?.join(SOCKET_NAME);
    let listener = unix_socket::bind_private(&path)?;
    let token = generate_token()?;
    Ok((RpcEndpoint { path, token }, listener))
}

fn generate_token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Constant-time comparison so response timing does not reveal how much of a guess matched.
pub fn token_matches(expected: &str, candidate: &str) -> bool {
    let (expected, candidate) = (expected.as_bytes(), candidate.as_bytes());
    expected.len() == candidate.len()
        && expected
            .iter()
            .zip(candidate)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_distinct_hex_tokens() {
        let first = generate_token().unwrap();
        let second = generate_token().unwrap();

        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn compares_tokens_exactly() {
        assert!(token_matches("abc123", "abc123"));
        assert!(!token_matches("abc123", "abc124"));
        assert!(!token_matches("abc123", "abc12"));
        assert!(!token_matches("abc123", ""));
    }

    #[test]
    fn envelope_round_trips() {
        let payload = serde_json::to_vec(&EnvelopeRef {
            token: "secret",
            request: &RpcRequest::GetItem { id: "item".into() },
        })
        .unwrap();
        let envelope: RpcEnvelope = serde_json::from_slice(&payload).unwrap();

        assert_eq!(envelope.token, "secret");
        assert!(matches!(envelope.request, RpcRequest::GetItem { id } if id == "item"));
    }
}
