use crate::config::{AppSettings, expand_ssh_agent_socket_path};
use crate::model::{
    SshAgentClientInfo, SshAgentStatus, SshApprovalDecision, SshApprovalKind, SshApprovalRemember,
    SshApprovalRequest, SshApprovalStatus, SshApprovalStatusKind, SshKey,
};
use signature::Signer;
use ssh_key::encoding::Encode;
use ssh_key::{Algorithm, PrivateKey, Signature};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_APPROVAL_TIMEOUT: Duration = Duration::from_secs(30);
pub const SSH_APPROVAL_TTL: Duration = Duration::from_secs(15 * 60);
/// Longest "remember" the approval popup offers (8 hours).
const MAX_REMEMBER_DURATION: Duration = Duration::from_secs(8 * 60 * 60);
pub const SSH_UNLOCK_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct SshApprovalService {
    inner: Arc<ApprovalInner>,
}

struct ApprovalInner {
    state: Mutex<ApprovalState>,
    changed: Condvar,
    notify_popup: mpsc::Sender<()>,
}

#[derive(Default)]
struct ApprovalState {
    pending: Option<PendingApproval>,
    recent: Option<SshApprovalStatus>,
    cached: Vec<CachedApproval>,
}

struct PendingApproval {
    request: SshApprovalRequest,
    decision: Option<SshApprovalDecision>,
}

#[derive(Clone)]
struct CachedApproval {
    key_id: String,
    scope: SshApprovalRemember,
    pid: u32,
    start_time_ticks: Option<u64>,
    command: Option<String>,
    executable: Option<String>,
    cwd: Option<String>,
    expires_at_unix_ms: u64,
}

impl SshApprovalService {
    pub fn new(notify_popup: mpsc::Sender<()>) -> Self {
        Self {
            inner: Arc::new(ApprovalInner {
                state: Mutex::new(ApprovalState::default()),
                changed: Condvar::new(),
                notify_popup,
            }),
        }
    }

    pub fn active_request(&self) -> Option<SshApprovalRequest> {
        self.inner.state.lock().ok().and_then(|state| {
            state
                .pending
                .as_ref()
                .map(|pending| pending.request.clone())
        })
    }

    pub fn recent_status(&self) -> Option<SshApprovalStatus> {
        self.inner
            .state
            .lock()
            .ok()
            .and_then(|state| state.recent.clone())
    }

    pub fn decide(&self, decision: SshApprovalDecision) -> Result<SshApprovalStatus, String> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "SSH approval state lock poisoned".to_string())?;
        let Some(pending) = state.pending.as_mut() else {
            return Err("no pending SSH approval request".into());
        };
        if pending.request.id != decision.request_id {
            return Err("SSH approval request is no longer pending".into());
        }
        pending.decision = Some(decision.clone());
        let status = approval_status(
            &pending.request,
            if decision.approved {
                SshApprovalStatusKind::Approved
            } else {
                SshApprovalStatusKind::Denied
            },
        );
        state.recent = Some(status.clone());
        self.inner.changed.notify_all();
        Ok(status)
    }

    pub fn clear_all(&self, message: &str) {
        let Ok(mut state) = self.inner.state.lock() else {
            return;
        };
        let recent = state.pending.as_ref().map(|pending| {
            approval_status_with_message(&pending.request, SshApprovalStatusKind::Cleared, message)
        });
        state.pending = None;
        state.cached.clear();
        if let Some(recent) = recent {
            state.recent = Some(recent);
        }
        self.inner.changed.notify_all();
    }

    fn approve_sign(&self, request: SshApprovalRequest) -> bool {
        let mut state = match self.inner.state.lock() {
            Ok(state) => state,
            Err(_) => return false,
        };

        prune_cached_approvals(&mut state);
        if cached_approval_matches(&state.cached, &request) {
            state.recent = Some(approval_status(
                &request,
                SshApprovalStatusKind::AutoApproved,
            ));
            return true;
        }

        if state.pending.is_some() {
            return false;
        }

        let Ok(_interaction) = crate::interaction::global().acquire(crate::interaction::Kind::Ssh)
        else {
            return false;
        };

        state.recent = Some(approval_status(&request, SshApprovalStatusKind::Pending));
        state.pending = Some(PendingApproval {
            request: request.clone(),
            decision: None,
        });
        let _ = self.inner.notify_popup.send(());
        let deadline = std::time::Instant::now() + SSH_APPROVAL_TIMEOUT;
        loop {
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                return self.timeout_pending(&mut state, &request);
            };
            let (next_state, wait_result) = match self.inner.changed.wait_timeout(state, remaining)
            {
                Ok(result) => result,
                Err(_) => return false,
            };
            state = next_state;
            let Some(pending) = state.pending.as_mut() else {
                return false;
            };
            if pending.request.id != request.id {
                return false;
            }
            if let Some(decision) = pending.decision.take() {
                state.pending = None;
                if decision.approved {
                    if let Some(approval) =
                        CachedApproval::from_request(&request, decision.remember)
                    {
                        state.cached.push(approval);
                    }
                    state.recent = Some(approval_status(&request, SshApprovalStatusKind::Approved));
                    return true;
                }
                state.recent = Some(approval_status(&request, SshApprovalStatusKind::Denied));
                return false;
            }
            if wait_result.timed_out() {
                return self.timeout_pending(&mut state, &request);
            }
        }
    }

    fn timeout_pending(&self, state: &mut ApprovalState, request: &SshApprovalRequest) -> bool {
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.request.id == request.id)
        {
            state.pending = None;
            state.recent = Some(approval_status(request, SshApprovalStatusKind::TimedOut));
        }
        false
    }
}

impl CachedApproval {
    fn from_request(request: &SshApprovalRequest, scope: SshApprovalRemember) -> Option<Self> {
        // Older clients may send broad scopes. Never cache these approvals.
        if scope != SshApprovalRemember::Process {
            return None;
        }
        request.client.start_time_ticks?;
        request.client.executable.as_ref()?;
        let command = request.client.command_line.clone();
        let cwd = request.client.cwd.clone();
        Some(Self {
            key_id: request.key_id.clone(),
            scope,
            pid: request.client.pid,
            start_time_ticks: request.client.start_time_ticks,
            command,
            executable: request.client.executable.clone(),
            cwd,
            expires_at_unix_ms: unix_millis_now()
                .saturating_add(duration_millis(remember_duration(scope))),
        })
    }
}

#[derive(Clone)]
pub struct SshKeyStore {
    inner: Arc<(Mutex<SshKeyStoreState>, Condvar)>,
    notify_unlock: mpsc::Sender<()>,
}

#[derive(Default)]
struct SshKeyStoreState {
    unlocked: bool,
    generation: u64,
    keys: Vec<SshKey>,
    prompt_pending: bool,
}

impl SshKeyStore {
    pub fn new(notify_unlock: mpsc::Sender<()>) -> Self {
        Self {
            inner: Arc::new((Mutex::new(SshKeyStoreState::default()), Condvar::new())),
            notify_unlock,
        }
    }

    pub fn set_unlocked(&self, keys: Vec<SshKey>) {
        let (lock, changed) = &*self.inner;
        let Ok(mut state) = lock.lock() else {
            return;
        };
        if !state.unlocked
            || state.keys.len() != keys.len()
            || state
                .keys
                .iter()
                .zip(&keys)
                .any(|(old, new)| old.id != new.id || old.private_key != new.private_key)
        {
            state.generation = state.generation.wrapping_add(1);
        }
        state.unlocked = true;
        state.keys = keys;
        state.prompt_pending = false;
        changed.notify_all();
    }

    pub fn set_locked(&self) {
        let (lock, changed) = &*self.inner;
        let Ok(mut state) = lock.lock() else {
            return;
        };
        state.unlocked = false;
        state.generation = state.generation.wrapping_add(1);
        state.keys.clear();
        state.prompt_pending = false;
        changed.notify_all();
    }

    fn load_keys_or_prompt(&self) -> Result<(Vec<SshKey>, u64), String> {
        let (lock, changed) = &*self.inner;
        let mut state = lock
            .lock()
            .map_err(|_| "SSH key store lock poisoned".to_string())?;
        if state.unlocked {
            return Ok((state.keys.clone(), state.generation));
        }

        let _interaction =
            crate::interaction::global().acquire(crate::interaction::Kind::Unlock)?;

        if !state.prompt_pending {
            state.prompt_pending = true;
            if !_interaction.shared() {
                let _ = self.notify_unlock.send(());
            }
        }

        let deadline = std::time::Instant::now() + SSH_UNLOCK_TIMEOUT;
        loop {
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                state.prompt_pending = false;
                return Err("vault unlock timed out".into());
            };
            let (next_state, wait_result) = changed
                .wait_timeout(state, remaining)
                .map_err(|_| "SSH key store wait failed".to_string())?;
            state = next_state;
            if state.unlocked {
                return Ok((state.keys.clone(), state.generation));
            }
            if _interaction.expired() || !state.prompt_pending {
                return Err("vault unlock cancelled".into());
            }
            if wait_result.timed_out() {
                state.prompt_pending = false;
                return Err("vault unlock timed out".into());
            }
        }
    }

    pub fn cancel_unlock(&self) {
        let (lock, changed) = &*self.inner;
        if let Ok(mut state) = lock.lock() {
            state.prompt_pending = false;
            changed.notify_all();
        }
    }
}

pub struct SshAgentHandle {
    path: PathBuf,
    stop_tx: Option<mpsc::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
    status: SshAgentStatus,
}

impl SshAgentHandle {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn status(&self) -> SshAgentStatus {
        self.status.clone()
    }

    pub fn stop(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = remove_owned_socket_if_present(&self.path);
    }
}

impl Drop for SshAgentHandle {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

#[derive(Clone)]
struct AgentKey {
    id: String,
    name: String,
    public_key: String,
    fingerprint: Option<String>,
    public_blob: Vec<u8>,
    private_key: PrivateKey,
}

pub fn disabled_status() -> SshAgentStatus {
    SshAgentStatus {
        enabled: false,
        active: false,
        socket_path: expand_status_path(&crate::config::default_ssh_agent_socket_path()),
        identity_count: 0,
        skipped_count: 0,
        message: "SSH agent disabled".into(),
    }
}

pub fn waiting_for_unlock_status(settings: &AppSettings) -> SshAgentStatus {
    SshAgentStatus {
        enabled: settings.ssh_agent_enabled,
        active: true,
        socket_path: expand_status_path(&settings.ssh_agent_socket_path),
        identity_count: 0,
        skipped_count: 0,
        message: "Listening; vault is locked and SSH use will prompt to unlock".into(),
    }
}

pub fn error_status(settings: &AppSettings, message: impl Into<String>) -> SshAgentStatus {
    SshAgentStatus {
        enabled: settings.ssh_agent_enabled,
        active: false,
        socket_path: expand_status_path(&settings.ssh_agent_socket_path),
        identity_count: 0,
        skipped_count: 0,
        message: message.into(),
    }
}

pub fn start(
    settings: &AppSettings,
    key_store: SshKeyStore,
    approvals: SshApprovalService,
) -> Result<SshAgentHandle, String> {
    let path = expand_ssh_agent_socket_path(&settings.ssh_agent_socket_path)?;
    prepare_socket_path(&path)?;
    let listener = UnixListener::bind(&path).map_err(|e| format!("could not bind socket: {e}"))?;
    secure_bound_socket(&path)?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("could not configure socket: {e}"))?;

    let (stop_tx, stop_rx) = mpsc::channel();
    let thread_path = path.clone();
    let thread_key_store = key_store.clone();
    let thread_approvals = approvals.clone();
    let join = thread::spawn(move || {
        loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let key_store = thread_key_store.clone();
                    let approvals = thread_approvals.clone();
                    thread::spawn(move || handle_stream(stream, key_store, approvals));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(_) => break,
            }
        }
        thread_approvals.clear_all("SSH agent stopped");
        let _ = remove_owned_socket_if_present(&thread_path);
    });

    Ok(SshAgentHandle {
        path: path.clone(),
        stop_tx: Some(stop_tx),
        join: Some(join),
        status: SshAgentStatus {
            enabled: true,
            active: true,
            socket_path: path.display().to_string(),
            identity_count: 0,
            skipped_count: 0,
            message: format!(
                "Listening at {}; vault unlock required before listing or signing",
                path.display()
            ),
        },
    })
}

fn prepare_socket_path(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Err("SSH agent socket path must have a parent directory".into());
    };
    fs::create_dir_all(parent).map_err(|e| format!("could not create socket dir: {e}"))?;
    ensure_owned_directory(parent)?;
    remove_owned_socket_if_present(path)?;
    Ok(())
}

fn ensure_owned_directory(path: &Path) -> Result<(), String> {
    let metadata =
        fs::metadata(path).map_err(|e| format!("could not inspect socket directory: {e}"))?;
    if !metadata.is_dir() {
        return Err("SSH agent socket parent must be a directory".into());
    }
    if metadata.uid() != current_uid() {
        return Err("SSH agent socket directory must be owned by the current user".into());
    }
    Ok(())
}

fn remove_owned_socket_if_present(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("could not inspect existing SSH agent socket: {e}")),
    };
    if metadata.uid() != current_uid() {
        return Err("existing SSH agent socket is not owned by the current user".into());
    }
    if !metadata.file_type().is_socket() {
        return Err("SSH agent path already exists and is not a socket".into());
    }
    fs::remove_file(path).map_err(|e| format!("could not remove stale SSH agent socket: {e}"))
}

fn secure_bound_socket(path: &Path) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("could not set SSH agent socket permissions: {e}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("could not inspect SSH agent socket: {e}"))?;
    if metadata.uid() != current_uid() {
        return Err("SSH agent socket is not owned by the current user".into());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "SSH agent socket permissions must be 0600, got {mode:04o}"
        ));
    }
    Ok(())
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn prepared_key_counts(vault_keys: &[SshKey]) -> (usize, usize) {
    let (keys, skipped) = prepare_agent_keys(vault_keys);
    (keys.len(), skipped)
}

fn prepare_agent_keys(vault_keys: &[SshKey]) -> (Vec<AgentKey>, usize) {
    let mut keys = Vec::new();
    let mut skipped = 0;
    for key in vault_keys {
        match prepare_agent_key(key) {
            Ok(agent_key) => keys.push(agent_key),
            Err(_) => skipped += 1,
        }
    }
    (keys, skipped)
}

fn prepare_agent_key(key: &SshKey) -> Result<AgentKey, String> {
    let private_key = PrivateKey::from_openssh(&key.private_key)
        .map_err(|e| format!("could not parse private key: {e}"))?;
    if private_key.is_encrypted() {
        return Err("encrypted private key is not supported".into());
    }
    if !matches!(
        private_key.algorithm(),
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. }
    ) {
        return Err("SSH agent supports Ed25519 and ECDSA keys; RSA signing is disabled".into());
    }
    let public_blob = encode_ssh(private_key.public_key().key_data())
        .map_err(|e| format!("could not encode public key: {e}"))?;
    Ok(AgentKey {
        id: key.id.clone(),
        name: key.name.clone(),
        public_key: key.public_key.clone(),
        fingerprint: key.fingerprint.clone(),
        public_blob,
        private_key,
    })
}

fn handle_stream(mut stream: UnixStream, key_store: SshKeyStore, approvals: SshApprovalService) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let connected = peer_client_info(&stream).ok();
    while let Ok(message) = read_agent_message(&mut stream) {
        let client = peer_client_info(&stream).ok().filter(|now| {
            connected.as_ref().is_some_and(|first| {
                first.pid == now.pid
                    && first.uid == now.uid
                    && first.start_time_ticks.is_some()
                    && first.start_time_ticks == now.start_time_ticks
            })
        });
        let response = handle_message(&message, &key_store, &approvals, client.clone())
            .unwrap_or_else(|_| vec![SSH_AGENT_FAILURE]);
        if write_agent_message(&mut stream, &response).is_err() {
            break;
        }
    }
}

fn handle_message(
    message: &[u8],
    key_store: &SshKeyStore,
    approvals: &SshApprovalService,
    client: Option<SshAgentClientInfo>,
) -> Result<Vec<u8>, String> {
    let Some((&kind, body)) = message.split_first() else {
        return Ok(vec![SSH_AGENT_FAILURE]);
    };
    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            let keys = prepare_keys_from_store(key_store)?;
            identities_answer(&keys)
        }
        SSH_AGENTC_SIGN_REQUEST => {
            let (vault_keys, generation) = key_store.load_keys_or_prompt()?;
            let (keys, _) = prepare_agent_keys(&vault_keys);
            sign_response(body, &keys, approvals, client, key_store, generation)
        }
        _ => Ok(vec![SSH_AGENT_FAILURE]),
    }
}

fn prepare_keys_from_store(key_store: &SshKeyStore) -> Result<Vec<AgentKey>, String> {
    let (vault_keys, _) = key_store.load_keys_or_prompt()?;
    let (keys, _) = prepare_agent_keys(&vault_keys);
    Ok(keys)
}

fn identities_answer(keys: &[AgentKey]) -> Result<Vec<u8>, String> {
    let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
    write_u32(&mut out, keys.len() as u32);
    for key in keys {
        write_string(&mut out, &key.public_blob);
        write_string(&mut out, key.name.as_bytes());
    }
    Ok(out)
}

fn sign_response(
    body: &[u8],
    keys: &[AgentKey],
    approvals: &SshApprovalService,
    client: Option<SshAgentClientInfo>,
    key_store: &SshKeyStore,
    generation: u64,
) -> Result<Vec<u8>, String> {
    let mut reader = AgentReader::new(body);
    let public_blob = reader.read_string()?;
    let data = reader.read_string()?;
    let flags = reader.read_u32()?;
    let Some(key) = keys.iter().find(|key| key.public_blob == public_blob) else {
        return Ok(vec![SSH_AGENT_FAILURE]);
    };
    let Some(client) = client else {
        return Ok(vec![SSH_AGENT_FAILURE]);
    };
    if client.uid != current_uid()
        || client.start_time_ticks.is_none()
        || client.executable.is_none()
    {
        return Ok(vec![SSH_AGENT_FAILURE]);
    }

    let expected_client = client.clone();
    let request = SshApprovalRequest {
        id: uuid::Uuid::new_v4().to_string(),
        kind: SshApprovalKind::Sign,
        key_id: key.id.clone(),
        key_name: key.name.clone(),
        public_key: key.public_key.clone(),
        fingerprint: key.fingerprint.clone(),
        algorithm: sign_algorithm_label(key, flags),
        client,
        created_at_unix_ms: unix_millis_now(),
        expires_at_unix_ms: unix_millis_now().saturating_add(duration_millis(SSH_APPROVAL_TIMEOUT)),
    };
    if !approvals.approve_sign(request) {
        return Ok(vec![SSH_AGENT_FAILURE]);
    }

    // Check again after the user decision; the peer may have exited or exec'd.
    let current = process_info(expected_client.pid);
    if current.start_time_ticks != expected_client.start_time_ticks
        || current.executable != expected_client.executable
        || current.command_line != expected_client.command_line
        || current.cwd != expected_client.cwd
    {
        return Ok(vec![SSH_AGENT_FAILURE]);
    }
    // Serialize the actual signing operation with vault locking/key revocation.
    let store = key_store.inner.0.lock().map_err(|_| "key store poisoned")?;
    if !store.unlocked
        || store.generation != generation
        || !store.keys.iter().any(|k| k.id == key.id)
    {
        return Ok(vec![SSH_AGENT_FAILURE]);
    }
    let signature = sign_key(key, data, flags)?;
    drop(store);
    let signature_blob = encode_ssh(&signature).map_err(|e| format!("encode signature: {e}"))?;
    let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
    write_string(&mut out, &signature_blob);
    Ok(out)
}

fn sign_key(key: &AgentKey, data: &[u8], flags: u32) -> Result<Signature, String> {
    if flags != 0 {
        return Err("Signing flags are not supported for this key".into());
    }
    key.private_key
        .try_sign(data)
        .map_err(|_| "could not sign with key".to_string())
}

fn sign_algorithm_label(key: &AgentKey, _flags: u32) -> String {
    format!("{:?}", key.private_key.algorithm())
}

fn approval_status(request: &SshApprovalRequest, kind: SshApprovalStatusKind) -> SshApprovalStatus {
    let message = match kind {
        SshApprovalStatusKind::Pending => "Waiting for SSH approval",
        SshApprovalStatusKind::Approved => "SSH request approved",
        SshApprovalStatusKind::Denied => "SSH request denied",
        SshApprovalStatusKind::TimedOut => "SSH request timed out",
        SshApprovalStatusKind::AutoApproved => "SSH request allowed by temporary approval",
        SshApprovalStatusKind::Cleared => "SSH approval cleared",
    };
    approval_status_with_message(request, kind, message)
}

fn approval_status_with_message(
    request: &SshApprovalRequest,
    kind: SshApprovalStatusKind,
    message: &str,
) -> SshApprovalStatus {
    SshApprovalStatus {
        request_id: request.id.clone(),
        key_name: request.key_name.clone(),
        process_name: request.client.process_name.clone(),
        kind,
        message: message.into(),
        at_unix_ms: unix_millis_now(),
    }
}

fn prune_cached_approvals(state: &mut ApprovalState) {
    let now = unix_millis_now();
    state
        .cached
        .retain(|approval| approval.expires_at_unix_ms > now);
}

fn cached_approval_matches(cached: &[CachedApproval], request: &SshApprovalRequest) -> bool {
    cached.iter().any(|approval| {
        if approval.key_id != request.key_id {
            return false;
        }
        approval.scope == SshApprovalRemember::Process
            && approval.pid == request.client.pid
            && approval.start_time_ticks.is_some()
            && approval.start_time_ticks == request.client.start_time_ticks
            && approval.executable.is_some()
            && approval.executable == request.client.executable
            && approval.command == request.client.command_line
            && approval.cwd == request.client.cwd
    })
}

fn remember_duration(scope: SshApprovalRemember) -> Duration {
    match scope {
        // The duration arrives over RPC, so cap it instead of trusting the UI's choices.
        SshApprovalRemember::CommandInCwd { duration_seconds } => {
            Duration::from_secs(duration_seconds).min(MAX_REMEMBER_DURATION)
        }
        SshApprovalRemember::Once | SshApprovalRemember::Process | SshApprovalRemember::Parent => {
            SSH_APPROVAL_TTL
        }
    }
}

fn peer_client_info(stream: &UnixStream) -> Result<SshAgentClientInfo, String> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "could not inspect SSH agent peer credentials: {}",
            io::Error::last_os_error()
        ));
    }
    let pid = u32::try_from(credentials.pid).map_err(|_| "invalid peer pid".to_string())?;
    let mut info = process_info(pid);
    info.uid = credentials.uid;
    info.gid = credentials.gid;
    Ok(info)
}

fn process_info(pid: u32) -> SshAgentClientInfo {
    let ppid = read_ppid(pid);
    let parent_pid = ppid.filter(|ppid| *ppid > 1);
    SshAgentClientInfo {
        pid,
        uid: current_uid(),
        gid: unsafe { libc::getegid() },
        ppid,
        start_time_ticks: read_start_time_ticks(pid),
        process_name: read_comm(pid),
        command_line: read_cmdline(pid),
        executable: fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.display().to_string()),
        cwd: fs::read_link(format!("/proc/{pid}/cwd"))
            .ok()
            .map(|path| path.display().to_string()),
        parent_pid,
        parent_name: parent_pid.and_then(read_comm),
        parent_start_time_ticks: parent_pid.and_then(read_start_time_ticks),
    }
}

fn read_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_cmdline(pid: u32) -> Option<String> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let parts = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .filter_map(|part| std::str::from_utf8(part).ok())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn read_ppid(pid: u32) -> Option<u32> {
    read_stat_field(pid, 1).and_then(|value| value.parse().ok())
}

fn read_start_time_ticks(pid: u32) -> Option<u64> {
    read_stat_field(pid, 19).and_then(|value| value.parse().ok())
}

fn read_stat_field(pid: u32, index_after_comm: usize) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(") ")?;
    stat[end + 2..]
        .split_whitespace()
        .nth(index_after_comm)
        .map(str::to_string)
}

fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn read_agent_message(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > 256 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "agent message too large",
        ));
    }
    let mut message = vec![0u8; len];
    stream.read_exact(&mut message)?;
    Ok(message)
}

fn write_agent_message(stream: &mut UnixStream, message: &[u8]) -> io::Result<()> {
    stream.write_all(&(message.len() as u32).to_be_bytes())?;
    stream.write_all(message)?;
    stream.flush()
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_string(out: &mut Vec<u8>, value: &[u8]) {
    write_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

fn encode_ssh<T: Encode>(value: &T) -> ssh_key::encoding::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(value.encoded_len()?);
    value.encode(&mut out)?;
    Ok(out)
}

fn expand_status_path(path: &str) -> String {
    expand_ssh_agent_socket_path(path)
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| path.to_string())
}

struct AgentReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> AgentReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn read_string(&mut self) -> Result<&'a [u8], String> {
        let len = self.read_u32()? as usize;
        self.read_exact(len)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| "agent message overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated agent message".into());
        }
        let result = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Verifier;
    use ssh_key::PublicKey;
    use std::sync::mpsc::Receiver;

    #[test]
    fn disabled_agent_does_not_bind_socket() {
        let status = disabled_status();
        assert!(!status.enabled);
        assert!(!status.active);
        assert!(status.socket_path.ends_with(".bitwarden-ssh.sock"));
    }

    #[test]
    fn rsa_keys_are_excluded_before_identity_advertisement() {
        // Textbook RSA parameters, deliberately unsuitable for real credentials.
        let int = |n: u32| ssh_key::Mpint::from_positive_bytes(&n.to_be_bytes());
        let public = ssh_key::public::RsaPublicKey::new(int(17), int(3233)).unwrap();
        let private =
            ssh_key::private::RsaPrivateKey::new(int(2753), int(38), int(61), int(53)).unwrap();
        let pair = ssh_key::private::RsaKeypair::new(public, private).unwrap();
        let private = PrivateKey::new(pair.into(), "test only").unwrap();
        let key = SshKey {
            id: "rsa-fixture".into(),
            name: "RSA fixture".into(),
            public_key: private.public_key().to_string(),
            private_key: private
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
            fingerprint: None,
        };
        assert!(
            prepare_agent_key(&key)
                .err()
                .unwrap()
                .contains("RSA signing is disabled")
        );
        let (advertised, skipped) = prepare_agent_keys(&[key]);
        assert!(advertised.is_empty());
        assert_eq!(skipped, 1);
    }

    #[test]
    fn unsupported_private_key_is_skipped() {
        let key = SshKey {
            id: "1".into(),
            name: "bad key".into(),
            public_key: "ssh-ed25519 AAAA".into(),
            private_key: "not a private key".into(),
            fingerprint: None,
        };
        let (keys, skipped) = prepare_agent_keys(&[key]);
        assert!(keys.is_empty());
        assert_eq!(skipped, 1);
    }

    #[test]
    fn socket_lists_identities_and_signs() {
        // Unix socket paths have a small fixed limit; worktree paths can exceed it.
        let socket_dir = std::env::temp_dir().join(format!("bw-ssh-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&socket_dir).unwrap();
        let socket_path = socket_dir.join("agent.sock");
        let settings = AppSettings {
            ssh_agent_enabled: true,
            ssh_agent_socket_path: socket_path.display().to_string(),
            ..AppSettings::default()
        };
        let private_key = fixture_private_key();
        let public_key = PublicKey::from(&private_key);
        let public_blob = encode_ssh(public_key.key_data()).unwrap();
        let vault_key = SshKey {
            id: "ssh-1".into(),
            name: "test-key".into(),
            public_key: public_key.to_string(),
            private_key: private_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
            fingerprint: None,
        };
        let (key_store, _) = key_store(vec![vault_key]);
        let (approvals, rx) = approval_service();
        let approve = approvals.clone();
        let agent = match start(&settings, key_store, approvals) {
            Ok(agent) => agent,
            Err(e) if e.contains("Operation not permitted") => return,
            Err(e) => panic!("could not start SSH agent: {e}"),
        };
        wait_for_socket(&socket_path);
        let socket_metadata = fs::symlink_metadata(&socket_path).unwrap();
        assert_eq!(socket_metadata.uid(), current_uid());
        assert_eq!(socket_metadata.permissions().mode() & 0o777, 0o600);

        let mut stream = UnixStream::connect(&socket_path).unwrap();
        write_agent_message(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        let response = read_agent_message(&mut stream).unwrap();
        assert_eq!(response[0], SSH_AGENT_IDENTITIES_ANSWER);
        let mut reader = AgentReader::new(&response[1..]);
        assert_eq!(reader.read_u32().unwrap(), 1);
        assert_eq!(reader.read_string().unwrap(), public_blob.as_slice());
        assert_eq!(reader.read_string().unwrap(), b"test-key");

        let data = b"sign me";
        let mut request = vec![SSH_AGENTC_SIGN_REQUEST];
        write_string(&mut request, &public_blob);
        write_string(&mut request, data);
        write_u32(&mut request, 0);
        std::thread::spawn(move || {
            approve_next_request(approve, rx, true, SshApprovalRemember::Once)
        });
        write_agent_message(&mut stream, &request).unwrap();
        let response = read_agent_message(&mut stream).unwrap();
        assert_eq!(response[0], SSH_AGENT_SIGN_RESPONSE);
        let mut reader = AgentReader::new(&response[1..]);
        let signature_blob = reader.read_string().unwrap();
        let signature = Signature::try_from(signature_blob).unwrap();
        public_key.key_data().verify(data, &signature).unwrap();

        agent.stop();
        assert!(!socket_path.exists());
        fs::remove_dir(socket_dir).unwrap();
    }

    #[test]
    fn existing_non_socket_path_is_not_removed() {
        let socket_dir = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("ssh-agent-tests");
        fs::create_dir_all(&socket_dir).unwrap();
        let socket_path = socket_dir.join(format!("{}.sock", uuid::Uuid::new_v4()));
        fs::write(&socket_path, b"not a socket").unwrap();
        let settings = AppSettings {
            ssh_agent_enabled: true,
            ssh_agent_socket_path: socket_path.display().to_string(),
            ..AppSettings::default()
        };

        let (key_store, _) = key_store(Vec::new());
        let (approvals, _) = approval_service();
        let err = match start(&settings, key_store, approvals) {
            Ok(agent) => {
                agent.stop();
                panic!("agent should not start when path is a regular file");
            }
            Err(err) => err,
        };
        assert!(err.contains("not a socket"));
        assert_eq!(fs::read(&socket_path).unwrap(), b"not a socket");
        fs::remove_file(&socket_path).unwrap();
    }

    #[test]
    fn protocol_lists_identities_and_signs() {
        let private_key = fixture_private_key();
        let public_key = PublicKey::from(&private_key);
        let public_blob = encode_ssh(public_key.key_data()).unwrap();
        let vault_key = SshKey {
            id: "ssh-1".into(),
            name: "test-key".into(),
            public_key: public_key.to_string(),
            private_key: private_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
            fingerprint: None,
        };
        let (key_store, unlock_rx) = key_store(vec![vault_key]);

        let (approvals, rx) = approval_service();
        let response = handle_message(
            &[SSH_AGENTC_REQUEST_IDENTITIES],
            &key_store,
            &approvals,
            None,
        )
        .unwrap();
        assert_eq!(response[0], SSH_AGENT_IDENTITIES_ANSWER);
        assert!(rx.try_recv().is_err());
        assert!(unlock_rx.try_recv().is_err());
        let mut reader = AgentReader::new(&response[1..]);
        assert_eq!(reader.read_u32().unwrap(), 1);
        assert_eq!(reader.read_string().unwrap(), public_blob.as_slice());
        assert_eq!(reader.read_string().unwrap(), b"test-key");

        let data = b"sign me";
        let mut request = vec![SSH_AGENTC_SIGN_REQUEST];
        write_string(&mut request, &public_blob);
        write_string(&mut request, data);
        write_u32(&mut request, 0);
        let approve = approvals.clone();
        std::thread::spawn(move || {
            approve_next_request(approve, rx, true, SshApprovalRemember::Once)
        });
        let response =
            handle_message(&request, &key_store, &approvals, Some(fake_client_info())).unwrap();
        assert_eq!(response[0], SSH_AGENT_SIGN_RESPONSE);
        let mut reader = AgentReader::new(&response[1..]);
        let signature_blob = reader.read_string().unwrap();
        let signature = Signature::try_from(signature_blob).unwrap();
        public_key.key_data().verify(data, &signature).unwrap();
    }

    #[test]
    fn sign_request_fails_when_denied() {
        let private_key = fixture_private_key();
        let public_key = PublicKey::from(&private_key);
        let public_blob = encode_ssh(public_key.key_data()).unwrap();
        let vault_key = SshKey {
            id: "ssh-1".into(),
            name: "test-key".into(),
            public_key: public_key.to_string(),
            private_key: private_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
            fingerprint: None,
        };
        let (key_store, _) = key_store(vec![vault_key]);
        let (approvals, rx) = approval_service();
        let approve = approvals.clone();
        std::thread::spawn(move || {
            approve_next_request(approve, rx, false, SshApprovalRemember::Once)
        });

        let mut request = vec![SSH_AGENTC_SIGN_REQUEST];
        write_string(&mut request, &public_blob);
        write_string(&mut request, b"sign me");
        write_u32(&mut request, 0);
        let response =
            handle_message(&request, &key_store, &approvals, Some(fake_client_info())).unwrap();

        assert_eq!(response, vec![SSH_AGENT_FAILURE]);
    }

    #[test]
    fn locking_while_approval_is_pending_prevents_signing() {
        let private_key = fixture_private_key();
        let public_key = PublicKey::from(&private_key);
        let public_blob = encode_ssh(public_key.key_data()).unwrap();
        let vault_key = SshKey {
            id: "ssh-1".into(),
            name: "test-key".into(),
            public_key: public_key.to_string(),
            private_key: private_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
            fingerprint: None,
        };
        let (key_store, _) = key_store(vec![vault_key]);
        let (approvals, rx) = approval_service();
        let approve = approvals.clone();
        let store = key_store.clone();
        let worker = std::thread::spawn(move || {
            rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let request = approve.active_request().unwrap();
            store.set_locked();
            approve
                .decide(SshApprovalDecision {
                    request_id: request.id,
                    approved: true,
                    remember: SshApprovalRemember::Once,
                })
                .unwrap();
        });
        let mut request = vec![SSH_AGENTC_SIGN_REQUEST];
        write_string(&mut request, &public_blob);
        write_string(&mut request, b"must not sign");
        write_u32(&mut request, 0);
        let response =
            handle_message(&request, &key_store, &approvals, Some(fake_client_info())).unwrap();
        worker.join().unwrap();
        assert_eq!(response, vec![SSH_AGENT_FAILURE]);
    }

    #[test]
    fn temporary_process_approval_skips_next_prompt() {
        let private_key = fixture_private_key();
        let public_key = PublicKey::from(&private_key);
        let public_blob = encode_ssh(public_key.key_data()).unwrap();
        let vault_key = SshKey {
            id: "ssh-1".into(),
            name: "test-key".into(),
            public_key: public_key.to_string(),
            private_key: private_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
            fingerprint: None,
        };
        let (key_store, _) = key_store(vec![vault_key]);
        let (approvals, rx) = approval_service();
        let approve = approvals.clone();
        std::thread::spawn(move || {
            approve_next_request(approve, rx, true, SshApprovalRemember::Process)
        });

        let mut request = vec![SSH_AGENTC_SIGN_REQUEST];
        write_string(&mut request, &public_blob);
        write_string(&mut request, b"first");
        write_u32(&mut request, 0);
        let first =
            handle_message(&request, &key_store, &approvals, Some(fake_client_info())).unwrap();
        assert_eq!(first[0], SSH_AGENT_SIGN_RESPONSE);

        let mut second_request = vec![SSH_AGENTC_SIGN_REQUEST];
        write_string(&mut second_request, &public_blob);
        write_string(&mut second_request, b"second");
        write_u32(&mut second_request, 0);
        let second = handle_message(
            &second_request,
            &key_store,
            &approvals,
            Some(fake_client_info()),
        )
        .unwrap();
        assert_eq!(second[0], SSH_AGENT_SIGN_RESPONSE);
        assert!(
            approvals
                .recent_status()
                .is_some_and(|status| status.kind == SshApprovalStatusKind::AutoApproved)
        );
    }

    #[test]
    fn broad_approval_scopes_are_never_cached() {
        let request = SshApprovalRequest {
            id: "test".into(),
            kind: SshApprovalKind::Sign,
            key_id: "key".into(),
            key_name: "Fixture".into(),
            public_key: "fixture".into(),
            fingerprint: None,
            algorithm: "Ed25519".into(),
            client: fake_client_info(),
            created_at_unix_ms: 0,
            expires_at_unix_ms: 0,
        };
        assert!(CachedApproval::from_request(&request, SshApprovalRemember::Parent).is_none());
        assert!(
            CachedApproval::from_request(
                &request,
                SshApprovalRemember::CommandInCwd {
                    duration_seconds: 900
                }
            )
            .is_none()
        );
        let cached = CachedApproval::from_request(&request, SshApprovalRemember::Process).unwrap();
        let mut other = request.clone();
        other.client.pid += 1;
        assert!(!cached_approval_matches(
            std::slice::from_ref(&cached),
            &other
        ));
        other = request.clone();
        other.client.executable = Some("/tmp/unrelated".into());
        assert!(!cached_approval_matches(
            std::slice::from_ref(&cached),
            &other
        ));
        other = request.clone();
        other.client.start_time_ticks = None;
        assert!(!cached_approval_matches(&[cached], &other));
    }

    #[test]
    fn command_cwd_approval_does_not_match_different_directory() {
        let private_key = fixture_private_key();
        let public_key = PublicKey::from(&private_key);
        let public_blob = encode_ssh(public_key.key_data()).unwrap();
        let vault_key = SshKey {
            id: "ssh-1".into(),
            name: "test-key".into(),
            public_key: public_key.to_string(),
            private_key: private_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
            fingerprint: None,
        };
        let (key_store, _) = key_store(vec![vault_key]);
        let (approvals, rx) = approval_service();

        let mut request = vec![SSH_AGENTC_SIGN_REQUEST];
        write_string(&mut request, &public_blob);
        write_string(&mut request, b"first");
        write_u32(&mut request, 0);
        let first_key_store = key_store.clone();
        let first_approvals = approvals.clone();
        let first = thread::spawn(move || {
            handle_message(
                &request,
                &first_key_store,
                &first_approvals,
                Some(fake_client_info()),
            )
            .unwrap()
        });
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let first_request = approvals.active_request().unwrap();
        approvals
            .decide(SshApprovalDecision {
                request_id: first_request.id,
                approved: true,
                remember: SshApprovalRemember::CommandInCwd {
                    duration_seconds: 15 * 60,
                },
            })
            .unwrap();
        let first = first.join().unwrap();
        assert_eq!(first[0], SSH_AGENT_SIGN_RESPONSE);

        let mut second_client = fake_client_info();
        second_client.cwd = Some("/other".into());
        let mut second_request = vec![SSH_AGENTC_SIGN_REQUEST];
        write_string(&mut second_request, &public_blob);
        write_string(&mut second_request, b"second");
        write_u32(&mut second_request, 0);
        let second_key_store = key_store.clone();
        let second_approvals = approvals.clone();
        let second = thread::spawn(move || {
            handle_message(
                &second_request,
                &second_key_store,
                &second_approvals,
                Some(second_client),
            )
            .unwrap()
        });
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let second_request = approvals.active_request().unwrap();
        approvals
            .decide(SshApprovalDecision {
                request_id: second_request.id,
                approved: false,
                remember: SshApprovalRemember::Once,
            })
            .unwrap();
        let second = second.join().unwrap();
        assert_eq!(second, vec![SSH_AGENT_FAILURE]);
        assert!(
            approvals
                .recent_status()
                .is_some_and(|status| status.kind == SshApprovalStatusKind::Denied)
        );
    }

    #[test]
    fn locked_key_store_prompts_before_listing_identities() {
        let private_key = fixture_private_key();
        let public_key = PublicKey::from(&private_key);
        let public_blob = encode_ssh(public_key.key_data()).unwrap();
        let vault_key = SshKey {
            id: "ssh-1".into(),
            name: "test-key".into(),
            public_key: public_key.to_string(),
            private_key: private_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
            fingerprint: None,
        };
        let (key_store, unlock_rx) = key_store(Vec::new());
        key_store.set_locked();
        let (approvals, _) = approval_service();
        let waiter_store = key_store.clone();
        let waiter = thread::spawn(move || {
            handle_message(
                &[SSH_AGENTC_REQUEST_IDENTITIES],
                &waiter_store,
                &approvals,
                None,
            )
            .unwrap()
        });

        unlock_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        key_store.set_unlocked(vec![vault_key]);
        let response = waiter.join().unwrap();
        assert_eq!(response[0], SSH_AGENT_IDENTITIES_ANSWER);
        let mut reader = AgentReader::new(&response[1..]);
        assert_eq!(reader.read_u32().unwrap(), 1);
        assert_eq!(reader.read_string().unwrap(), public_blob.as_slice());
        assert_eq!(reader.read_string().unwrap(), b"test-key");
    }

    fn wait_for_socket(path: &Path) {
        for _ in 0..20 {
            if path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("socket was not created: {}", path.display());
    }

    fn approval_service() -> (SshApprovalService, Receiver<()>) {
        let (tx, rx) = mpsc::channel();
        (SshApprovalService::new(tx), rx)
    }

    fn key_store(keys: Vec<SshKey>) -> (SshKeyStore, Receiver<()>) {
        let (tx, rx) = mpsc::channel();
        let store = SshKeyStore::new(tx);
        store.set_unlocked(keys);
        (store, rx)
    }

    fn approve_next_request(
        approvals: SshApprovalService,
        rx: Receiver<()>,
        approved: bool,
        remember: SshApprovalRemember,
    ) {
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        for _ in 0..20 {
            if let Some(request) = approvals.active_request() {
                approvals
                    .decide(SshApprovalDecision {
                        request_id: request.id,
                        approved,
                        remember,
                    })
                    .unwrap();
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("approval request was not created");
    }

    fn fake_client_info() -> SshAgentClientInfo {
        process_info(std::process::id())
    }

    fn fixture_private_key() -> PrivateKey {
        PrivateKey::from_openssh(
            r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----"#,
        )
        .unwrap()
    }
}
