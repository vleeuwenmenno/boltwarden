//! Bounded, independently authenticated browser transport.
#[cfg_attr(windows, path = "install_windows.rs")]
pub mod install;
pub mod native_host;
pub mod pairing;
pub mod protocol;
pub mod session;

pub use pairing::{PairingRecord, PairingRequest};
pub use protocol::{BrowserEvent, BrowserRequest, BrowserResponse, FillInteraction, MatchSummary};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pairing::PairingStore;
use protocol::{EventEnvelope, RequestEnvelope, ResponseEnvelope, VERSION};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::Shutdown;

use crate::platform::ipc::Stream as UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const MAX_CONNECTIONS: usize = 8;
const MAX_UNAUTHENTICATED: usize = 2;
const MAX_INFLIGHT: usize = 16;
const MAX_CONNECTION_INFLIGHT: usize = 4;
const WRITE_QUEUE: usize = 16;
const SOCKET_NAME: &str = "boltwarden-browser.sock";

pub trait BrowserHandler: Send + Sync + 'static {
    fn handle(&self, context: &RequestContext, request: BrowserRequest) -> BrowserResponse;
    fn approve_pairing(
        &self,
        context: &RequestContext,
        request: &PairingRequest,
    ) -> Result<(), String>;
}

#[derive(Clone)]
pub struct RequestContext {
    pub pairing_id: Option<String>,
    pub peer_pid: u32,
    generation: u64,
    deadline: Option<Instant>,
    cancelled: Arc<AtomicBool>,
    connection: Arc<Connection>,
}

impl RequestContext {
    pub fn is_cancelled(&self) -> bool {
        self.connection.closed.load(Ordering::Acquire)
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            || self.cancelled.load(Ordering::Acquire)
            || self.connection.generation.load(Ordering::Acquire) != self.generation
    }
}

#[derive(Clone)]
pub struct BrowserHub {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    handler: Arc<dyn BrowserHandler>,
    pairings: Mutex<PairingStore>,
    connections: Mutex<HashMap<String, Arc<Connection>>>,
    inflight: AtomicUsize,
    stopped: AtomicBool,
    prompts: Mutex<PromptLimit>,
}

#[derive(Default)]
struct PromptLimit {
    pending: bool,
    attempts: VecDeque<Instant>,
    cooldown_until: Option<Instant>,
}

struct Connection {
    id: String,
    peer_pid: u32,
    accepted_at: Instant,
    state: Mutex<SessionState>,
    generation: AtomicU64,
    closed: AtomicBool,
    inflight: AtomicUsize,
    pending_ids: Mutex<HashMap<String, Arc<AtomicBool>>>,
    release: Mutex<()>,
    sender: mpsc::SyncSender<Outbound>,
    socket: UnixStream,
}

#[derive(Default)]
struct SessionState {
    pairing_id: Option<String>,
    challenge: Option<Challenge>,
    pairing_pending: bool,
    pairing_deadline: Option<Instant>,
}

struct Challenge {
    nonce: String,
    pairing_id: String,
    created: Instant,
    existing: bool,
}
enum Outbound {
    Response(Box<PendingResponse>),
    Event(BrowserEvent),
}

struct PendingResponse {
    envelope: ResponseEnvelope,
    guard: Option<RequestContext>,
    permit: Option<JobPermit>,
}

impl Connection {
    fn context(self: &Arc<Self>) -> RequestContext {
        RequestContext {
            deadline: None,
            pairing_id: self.state.lock().ok().and_then(|s| s.pairing_id.clone()),
            peer_pid: self.peer_pid,
            generation: self.generation.load(Ordering::Acquire),
            cancelled: Arc::new(AtomicBool::new(false)),
            connection: self.clone(),
        }
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.generation.fetch_add(1, Ordering::AcqRel);
        let _ = self.socket.shutdown(Shutdown::Both);
    }
    fn send(&self, outbound: Outbound) {
        if self.sender.try_send(outbound).is_err() {
            self.close();
        }
    }
    fn reply(&self, id: String, response: BrowserResponse, context: Option<RequestContext>) {
        self.send(Outbound::Response(Box::new(PendingResponse {
            envelope: ResponseEnvelope {
                version: VERSION,
                id,
                response,
            },
            guard: context,
            permit: None,
        })));
    }
    fn reply_job(
        &self,
        id: String,
        response: BrowserResponse,
        context: RequestContext,
        permit: JobPermit,
    ) {
        self.send(Outbound::Response(Box::new(PendingResponse {
            envelope: ResponseEnvelope {
                version: VERSION,
                id,
                response,
            },
            guard: Some(context),
            permit: Some(permit),
        })));
    }
}

impl BrowserHub {
    #[cfg(test)]
    pub(crate) fn test_connection(
        handler: Arc<dyn BrowserHandler>,
        directory: &std::path::Path,
    ) -> io::Result<(Self, UnixStream)> {
        #[cfg(unix)]
        std::fs::create_dir_all(directory)?;
        #[cfg(windows)]
        crate::platform::windows::private_dir(directory)?;
        let (client, server) = UnixStream::pair()?;
        client.set_read_timeout(Some(Duration::from_secs(2)))?;
        let inner = Arc::new(Inner {
            path: directory.join("browser.sock"),
            handler,
            pairings: Mutex::new(PairingStore::load_at(directory.join("browsers.json"))?),
            connections: Mutex::new(HashMap::new()),
            inflight: AtomicUsize::new(0),
            stopped: AtomicBool::new(false),
            prompts: Mutex::new(PromptLimit::default()),
        });
        accept(&inner, server)?;
        Ok((Self { inner }, client))
    }

    pub fn start(handler: Arc<dyn BrowserHandler>) -> io::Result<Self> {
        let path = socket_path()?;
        let store = PairingStore::load()?;
        if UnixStream::connect(&path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Browser socket is already active",
            ));
        }
        let listener = crate::platform::ipc::bind_private(&path)?;
        listener.set_nonblocking(true)?;
        let inner = Arc::new(Inner {
            path,
            handler,
            pairings: Mutex::new(store),
            connections: Mutex::new(HashMap::new()),
            inflight: AtomicUsize::new(0),
            stopped: AtomicBool::new(false),
            prompts: Mutex::new(PromptLimit::default()),
        });
        let weak = Arc::downgrade(&inner);
        std::thread::spawn(move || {
            loop {
                let Some(inner) = weak.upgrade() else { break };
                if inner.stopped.load(Ordering::Acquire) {
                    break;
                }
                match listener.accept() {
                    Ok((socket, _)) => {
                        let _ = accept(&inner, socket);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(25))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self { inner })
    }
    pub fn list_pairings(&self) -> Result<Vec<PairingRecord>, String> {
        self.inner
            .pairings
            .lock()
            .map(|p| p.list())
            .map_err(|_| "Pairing store unavailable".into())
    }
    pub fn revoke(&self, id: &str) -> Result<(), String> {
        self.inner
            .pairings
            .lock()
            .map_err(|_| "Pairing store unavailable")?
            .revoke(id)
            .map_err(|e| e.to_string())?;
        let connections: Vec<_> = self
            .inner
            .connections
            .lock()
            .map_err(
                |_| "Browser connections unavailable; restart Boltwarden to disconnect browsers",
            )?
            .values()
            .cloned()
            .collect();
        let revoked: Vec<_> = connections
            .into_iter()
            .filter(|connection| {
                connection
                    .state
                    .lock()
                    .map_or(true, |s| s.pairing_id.as_deref() == Some(id))
            })
            .collect();
        // Cancel every session before waiting for any writer. Socket shutdown also
        // interrupts blocked writes. Disconnect is reliable; a queued event is not.
        for connection in &revoked {
            connection.close();
        }
        for connection in revoked {
            let _release = connection.release.lock();
        }
        Ok(())
    }
    pub fn invalidate(&self, event: BrowserEvent) {
        for connection in self.connections() {
            let Ok(_release) = connection.release.lock() else {
                connection.close();
                continue;
            };
            connection.generation.fetch_add(1, Ordering::AcqRel);
            if let Ok(mut state) = connection.state.lock() {
                state.challenge = None;
            }
            connection.send(Outbound::Event(event.clone()));
        }
    }
    pub fn notify(&self, event: BrowserEvent) {
        for connection in self.connections() {
            connection.send(Outbound::Event(event.clone()));
        }
    }
    pub fn shutdown(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        for connection in self.connections() {
            connection.close();
        }
        let _ = crate::platform::ipc::remove_stale_socket(&self.inner.path);
    }
    fn connections(&self) -> Vec<Arc<Connection>> {
        self.inner
            .connections
            .lock()
            .map(|c| c.values().cloned().collect())
            .unwrap_or_default()
    }
}

pub fn socket_path() -> io::Result<PathBuf> {
    Ok(crate::platform::ipc::runtime_dir()?.join(SOCKET_NAME))
}

fn peer_pid(socket: &UnixStream) -> io::Result<u32> {
    crate::platform::ipc::peer_pid(socket)
}

fn accept(inner: &Arc<Inner>, socket: UnixStream) -> io::Result<()> {
    let pid = peer_pid(&socket)?;
    let mut connections = inner
        .connections
        .lock()
        .map_err(|_| io::Error::other("Connections unavailable"))?;
    let unauthenticated = connections
        .values()
        .filter(|c| c.state.lock().map_or(true, |s| s.pairing_id.is_none()))
        .count();
    if connections.len() >= MAX_CONNECTIONS || unauthenticated >= MAX_UNAUTHENTICATED {
        return Err(io::Error::other("Browser connection limit reached"));
    }
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let (sender, receiver) = mpsc::sync_channel(WRITE_QUEUE);
    let connection = Arc::new(Connection {
        id: uuid::Uuid::new_v4().to_string(),
        peer_pid: pid,
        accepted_at: Instant::now(),
        state: Mutex::new(SessionState::default()),
        generation: AtomicU64::new(0),
        closed: AtomicBool::new(false),
        inflight: AtomicUsize::new(0),
        pending_ids: Mutex::new(HashMap::new()),
        release: Mutex::new(()),
        sender,
        socket: socket.try_clone()?,
    });
    let writer = socket.try_clone()?;
    connections.insert(connection.id.clone(), connection.clone());
    drop(connections);
    let writer_connection = Arc::downgrade(&connection);
    std::thread::spawn(move || write_loop(writer, receiver, writer_connection));
    let inner = inner.clone();
    std::thread::spawn(move || {
        read_loop(&inner, &connection, socket);
        connection.close();
        if let Ok(mut connections) = inner.connections.lock() {
            connections.remove(&connection.id);
        }
    });
    Ok(())
}

fn write_loop(
    mut socket: UnixStream,
    receiver: mpsc::Receiver<Outbound>,
    connection: std::sync::Weak<Connection>,
) {
    while let Ok(message) = receiver.recv() {
        let Some(connection) = connection.upgrade() else {
            break;
        };
        let Ok(_release) = connection.release.lock() else {
            connection.close();
            break;
        };
        let result = match message {
            Outbound::Response(response) => {
                let PendingResponse {
                    envelope,
                    guard,
                    permit: _permit,
                } = *response;
                if guard.as_ref().is_some_and(RequestContext::is_cancelled) {
                    continue;
                }
                let payload =
                    zeroize::Zeroizing::new(serde_json::to_vec(&envelope).unwrap_or_default());
                if guard.as_ref().is_some_and(RequestContext::is_cancelled) {
                    continue;
                }
                session::write_socket_frame(&mut socket, &payload)
            }
            Outbound::Event(event) => {
                let payload = zeroize::Zeroizing::new(
                    serde_json::to_vec(&EventEnvelope {
                        version: VERSION,
                        event,
                    })
                    .unwrap_or_default(),
                );
                session::write_socket_frame(&mut socket, &payload)
            }
        };
        if result.is_err() {
            break;
        }
    }
    if let Some(connection) = connection.upgrade() {
        connection.close();
    }
}

fn read_loop(inner: &Arc<Inner>, connection: &Arc<Connection>, mut socket: UnixStream) {
    let mut requests = VecDeque::new();
    let mut secret_requests = VecDeque::new();
    while !connection.closed.load(Ordering::Acquire) {
        let deadline = match connection.state.lock() {
            Ok(state) => session_deadline(connection.accepted_at, &state),
            Err(_) => break,
        };
        let body = match session::read_socket_frame(&mut socket, deadline) {
            Ok(body) => body,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    && connection
                        .state
                        .lock()
                        .is_ok_and(|state| state.pairing_id.is_some()) =>
            {
                continue;
            }
            Err(_) => break,
        };
        if connection.state.lock().map_or(true, |state| {
            session_deadline(connection.accepted_at, &state)
                .is_some_and(|end| end <= Instant::now())
        }) {
            break;
        }
        let envelope: RequestEnvelope = match serde_json::from_slice(&body) {
            Ok(envelope) => envelope,
            Err(_) => {
                connection.reply(
                    "invalid".into(),
                    BrowserResponse::error("InvalidRequest", "Malformed browser request"),
                    None,
                );
                break;
            }
        };
        if envelope.version != VERSION || envelope.id.is_empty() || envelope.id.len() > 64 {
            connection.reply(
                envelope.id,
                BrowserResponse::error(
                    "InvalidRequest",
                    "Unsupported version or invalid request ID",
                ),
                None,
            );
            break;
        }
        if !allow_rate(&mut requests, 20)
            || (matches!(
                envelope.request,
                BrowserRequest::SaveLogin { .. }
                    | BrowserRequest::FillLogin { .. }
                    | BrowserRequest::FillTotp { .. }
                    | BrowserRequest::FillCard { .. }
                    | BrowserRequest::PasskeyGet { .. }
                    | BrowserRequest::PasskeyCreate { .. }
            ) && !allow_rate(&mut secret_requests, 5))
        {
            connection.reply(
                envelope.id,
                BrowserResponse::error("Busy", "Browser request rate exceeded"),
                None,
            );
            continue;
        }
        let id = envelope.id;
        if connection
            .pending_ids
            .lock()
            .map_or(true, |ids| ids.contains_key(&id))
        {
            connection.reply(
                id,
                BrowserResponse::error("InvalidRequest", "Duplicate pending request ID"),
                None,
            );
            continue;
        }
        let pending = connection.state.lock().map_or(true, |s| s.pairing_pending);
        if pending && !matches!(envelope.request, BrowserRequest::Cancel { .. }) {
            connection.reply(
                id,
                BrowserResponse::error("Busy", "Pairing approval is pending"),
                None,
            );
            continue;
        }
        match envelope.request {
            BrowserRequest::Cancel { request_id } => {
                let Ok(_release) = connection.release.lock() else {
                    connection.close();
                    break;
                };
                if let Ok(ids) = connection.pending_ids.lock()
                    && let Some(cancelled) = ids.get(&request_id)
                {
                    cancelled.store(true, Ordering::Release);
                }
                connection.reply(id, BrowserResponse::Cancelled { request_id }, None);
            }
            BrowserRequest::Hello { pairing_id } => {
                let response = hello(inner, connection, pairing_id);
                connection.reply(id, response, None);
            }
            BrowserRequest::Authenticate {
                pairing_id,
                sig,
                host_pid,
            } => {
                let response = authenticate(inner, connection, pairing_id, sig, host_pid);
                connection.reply(id, response, None);
            }
            BrowserRequest::RequestPairing {
                pairing_id,
                public_key_spki,
                label,
                sig,
                host_pid,
            } => {
                if let Err(response) = request_pairing(
                    inner,
                    connection,
                    id.clone(),
                    pairing_id,
                    public_key_spki,
                    label,
                    sig,
                    host_pid,
                ) {
                    connection.reply(id, response, None);
                }
            }
            request => {
                let mut context = connection.context();
                let Some(pairing) = context.pairing_id.as_deref() else {
                    connection.reply(
                        id,
                        BrowserResponse::error("Unpaired", "Pair this browser in Boltwarden first"),
                        None,
                    );
                    continue;
                };
                if inner
                    .pairings
                    .lock()
                    .map_or(true, |p| p.get(pairing).is_none())
                {
                    connection.close();
                    break;
                }
                let Some(permit) = acquire_job(inner, connection, &id) else {
                    connection.reply(
                        id,
                        BrowserResponse::error("Busy", "Browser operation limit reached"),
                        None,
                    );
                    continue;
                };
                context.cancelled = permit.cancelled.clone();
                // Keep the ceremony deadline attached through the final guarded
                // writer, including time queued behind another response.
                let timeout_ms = match &request {
                    BrowserRequest::PasskeyGet { options, .. } => Some(options.timeout_ms),
                    BrowserRequest::PasskeyCreate { options, .. } => Some(options.timeout_ms),
                    _ => None,
                };
                context.deadline = timeout_ms
                    .filter(|value| (1..=60_000).contains(value))
                    .map(|value| Instant::now() + Duration::from_millis(value));
                let inner = inner.clone();
                let connection = connection.clone();
                std::thread::spawn(move || {
                    if context.is_cancelled() {
                        return;
                    }
                    let response = inner.handler.handle(&context, request);
                    connection.reply_job(id, response, context, permit);
                });
            }
        }
    }
}

fn allow_rate(times: &mut VecDeque<Instant>, maximum: usize) -> bool {
    let now = Instant::now();
    while times
        .front()
        .is_some_and(|at| now.duration_since(*at) >= Duration::from_secs(1))
    {
        times.pop_front();
    }
    if times.len() >= maximum {
        return false;
    }
    times.push_back(now);
    true
}

fn session_deadline(accepted_at: Instant, state: &SessionState) -> Option<Instant> {
    if state.pairing_id.is_some() {
        None
    } else if state.pairing_pending {
        state.pairing_deadline
    } else {
        Some(accepted_at + Duration::from_secs(10))
    }
}

fn hello(
    inner: &Inner,
    connection: &Arc<Connection>,
    requested: Option<String>,
) -> BrowserResponse {
    let mut state = match connection.state.lock() {
        Ok(s) => s,
        Err(_) => return BrowserResponse::error("InternalError", "Browser session unavailable"),
    };
    if state.pairing_id.is_some() {
        return BrowserResponse::error("InvalidRequest", "Connection is already authenticated");
    }
    let pairing_id = match requested {
        Some(id) => match uuid::Uuid::parse_str(&id) {
            Ok(parsed) if parsed.to_string() == id => id,
            _ => return BrowserResponse::error("InvalidRequest", "Invalid pairing ID"),
        },
        None => uuid::Uuid::new_v4().to_string(),
    };
    let existing = inner
        .pairings
        .lock()
        .is_ok_and(|p| p.get(&pairing_id).is_some());
    let nonce = match crate::random::random_bytes::<32>() {
        Ok(bytes) => URL_SAFE_NO_PAD.encode(bytes),
        Err(_) => return BrowserResponse::error("InternalError", "Random source unavailable"),
    };
    state.challenge = Some(Challenge {
        nonce: nonce.clone(),
        pairing_id: pairing_id.clone(),
        created: Instant::now(),
        existing,
    });
    BrowserResponse::Challenge {
        nonce,
        pairing_id,
        paired: existing,
    }
}

fn take_challenge(connection: &Connection, pairing_id: &str) -> Result<Challenge, BrowserResponse> {
    let mut state = connection
        .state
        .lock()
        .map_err(|_| BrowserResponse::error("InternalError", "Browser session unavailable"))?;
    if state.pairing_id.is_some() {
        return Err(BrowserResponse::error(
            "InvalidRequest",
            "Connection is already authenticated",
        ));
    }
    let challenge = state
        .challenge
        .take()
        .ok_or_else(|| BrowserResponse::error("Unauthorized", "A fresh challenge is required"))?;
    if challenge.pairing_id != pairing_id || challenge.created.elapsed() > Duration::from_secs(30) {
        return Err(BrowserResponse::error(
            "Unauthorized",
            "Pairing challenge expired or does not match",
        ));
    }
    Ok(challenge)
}

fn authenticate(
    inner: &Inner,
    connection: &Arc<Connection>,
    pairing_id: String,
    sig: String,
    host_pid: u32,
) -> BrowserResponse {
    let challenge = match take_challenge(connection, &pairing_id) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut store = match inner.pairings.lock() {
        Ok(p) => p,
        Err(_) => return BrowserResponse::error("InternalError", "Pairing store unavailable"),
    };
    let Some(pairing) = store.get(&pairing_id) else {
        return BrowserResponse::error("Unpaired", "Pairing is unknown or revoked");
    };
    if session::verify_proof(
        &pairing.public_key_spki,
        &challenge.nonce,
        &pairing_id,
        host_pid,
        connection.peer_pid,
        &sig,
    )
    .is_err()
    {
        return BrowserResponse::error("Unauthorized", "Pairing proof is not valid");
    }
    match connection.state.lock() {
        Ok(mut state) => {
            if let Err(error) = store.record_authenticated(&pairing_id) {
                return BrowserResponse::error(
                    "InternalError",
                    format!("Could not record browser authentication: {error}"),
                );
            }
            state.pairing_id = Some(pairing_id.clone());
            BrowserResponse::Authenticated { pairing_id }
        }
        Err(_) => BrowserResponse::error("InternalError", "Browser session unavailable"),
    }
}

#[allow(clippy::too_many_arguments)]
fn request_pairing(
    inner: &Arc<Inner>,
    connection: &Arc<Connection>,
    id: String,
    pairing_id: String,
    public_key_spki: String,
    label: String,
    sig: String,
    host_pid: u32,
) -> Result<(), BrowserResponse> {
    let challenge = take_challenge(connection, &pairing_id)?;
    if challenge.existing {
        return Err(BrowserResponse::error(
            "InvalidRequest",
            "Existing pairing must authenticate",
        ));
    }
    if label.trim().is_empty() || label.len() > 100 || label.chars().any(char::is_control) {
        return Err(BrowserResponse::error(
            "InvalidRequest",
            "Browser label must contain 1 to 100 printable bytes",
        ));
    }
    session::verify_proof(
        &public_key_spki,
        &challenge.nonce,
        &pairing_id,
        host_pid,
        connection.peer_pid,
        &sig,
    )
    .map_err(|message| BrowserResponse::error("Unauthorized", message))?;
    let fingerprint = pairing::fingerprint(&public_key_spki)
        .map_err(|message| BrowserResponse::error("InvalidRequest", message))?;
    let permit = acquire_job(inner, connection, &id)
        .ok_or_else(|| BrowserResponse::error("Busy", "Browser operation limit reached"))?;
    {
        let mut prompts = inner
            .prompts
            .lock()
            .map_err(|_| BrowserResponse::error("InternalError", "Approval state unavailable"))?;
        let now = Instant::now();
        while prompts
            .attempts
            .front()
            .is_some_and(|at| now.duration_since(*at) >= Duration::from_secs(600))
        {
            prompts.attempts.pop_front();
        }
        if prompts.pending
            || prompts.attempts.len() >= 3
            || prompts.cooldown_until.is_some_and(|until| until > now)
        {
            return Err(BrowserResponse::error(
                "Busy",
                "Pairing prompt limit reached; try later",
            ));
        }
        prompts.pending = true;
        prompts.attempts.push_back(now);
    }
    let mut state = connection
        .state
        .lock()
        .map_err(|_| BrowserResponse::error("InternalError", "Browser session unavailable"))?;
    state.pairing_pending = true;
    state.pairing_deadline = Some(Instant::now() + Duration::from_secs(60));
    drop(state);
    let mut context = connection.context();
    context.cancelled = permit.cancelled.clone();
    context.pairing_id = Some(pairing_id.clone());
    let request = PairingRequest {
        pairing_id: pairing_id.clone(),
        label,
        public_key_spki,
        fingerprint,
    };
    let inner = inner.clone();
    let connection = connection.clone();
    std::thread::spawn(move || {
        let start = Instant::now();
        let approval = inner.handler.approve_pairing(&context, &request);
        let result = if context.is_cancelled() || start.elapsed() > Duration::from_secs(60) {
            Err("Cancelled".to_string())
        } else {
            approval
        };
        let response = match result {
            Ok(()) => {
                let _release = connection.release.lock();
                if _release.is_err() || context.is_cancelled() {
                    BrowserResponse::error("Cancelled", "Pairing was cancelled")
                } else {
                    match inner.pairings.lock() {
                        Ok(mut store) => match store.insert(&request) {
                            Ok(()) => {
                                if let Ok(mut state) = connection.state.lock() {
                                    state.pairing_id = Some(pairing_id.clone());
                                }
                                BrowserResponse::Paired { pairing_id }
                            }
                            Err(error) => {
                                BrowserResponse::error("InternalError", error.to_string())
                            }
                        },
                        Err(_) => {
                            BrowserResponse::error("InternalError", "Pairing store unavailable")
                        }
                    }
                }
            }
            Err(message) => BrowserResponse::error(
                if matches!(
                    message.as_str(),
                    "Busy" | "Locked" | "Disabled" | "Cancelled"
                ) {
                    message.as_str()
                } else {
                    "Denied"
                },
                message.clone(),
            ),
        };
        if let Ok(mut prompts) = inner.prompts.lock() {
            prompts.pending = false;
            if !matches!(response, BrowserResponse::Paired { .. }) {
                prompts.cooldown_until = Some(Instant::now() + Duration::from_secs(30));
            }
        }
        if let Ok(mut state) = connection.state.lock() {
            state.pairing_pending = false;
        }
        connection.reply_job(id, response, context, permit);
    });
    Ok(())
}

struct JobPermit {
    inner: Arc<Inner>,
    connection: Arc<Connection>,
    id: String,
    cancelled: Arc<AtomicBool>,
}
impl Drop for JobPermit {
    fn drop(&mut self) {
        self.inner.inflight.fetch_sub(1, Ordering::AcqRel);
        self.connection.inflight.fetch_sub(1, Ordering::AcqRel);
        if let Ok(mut ids) = self.connection.pending_ids.lock() {
            ids.remove(&self.id);
        }
    }
}

fn acquire_job(inner: &Arc<Inner>, connection: &Arc<Connection>, id: &str) -> Option<JobPermit> {
    inner
        .inflight
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < MAX_INFLIGHT).then_some(n + 1)
        })
        .ok()?;
    if connection
        .inflight
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < MAX_CONNECTION_INFLIGHT).then_some(n + 1)
        })
        .is_err()
    {
        inner.inflight.fetch_sub(1, Ordering::AcqRel);
        return None;
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    if let Ok(mut ids) = connection.pending_ids.lock() {
        ids.insert(id.to_owned(), cancelled.clone());
    }
    Some(JobPermit {
        inner: inner.clone(),
        connection: connection.clone(),
        id: id.to_owned(),
        cancelled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::ipc::Listener as UnixListener;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use signature::Signer;

    struct Handler {
        approvals: AtomicUsize,
        requests: AtomicUsize,
    }
    impl BrowserHandler for Handler {
        fn handle(&self, _: &RequestContext, _: BrowserRequest) -> BrowserResponse {
            self.requests.fetch_add(1, Ordering::SeqCst);
            BrowserResponse::Status {
                enabled: true,
                unlocked: true,
                epoch: 1,
            }
        }
        fn approve_pairing(&self, _: &RequestContext, _: &PairingRequest) -> Result<(), String> {
            self.approvals.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    struct Harness {
        hub: BrowserHub,
        client: UnixStream,
        directory: PathBuf,
        handler: Arc<Handler>,
    }
    impl Harness {
        fn new() -> Self {
            let directory = std::env::temp_dir()
                .join(format!("boltwarden-browser-test-{}", uuid::Uuid::new_v4()));
            #[cfg(unix)]
            std::fs::create_dir(&directory).unwrap();
            #[cfg(windows)]
            crate::platform::windows::private_dir(&directory).unwrap();
            let path = directory.join("browser.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let client = UnixStream::connect(&path).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let (server, _) = listener.accept().unwrap();
            let handler = Arc::new(Handler {
                approvals: AtomicUsize::new(0),
                requests: AtomicUsize::new(0),
            });
            let inner = Arc::new(Inner {
                path,
                handler: handler.clone(),
                pairings: Mutex::new(
                    PairingStore::load_at(directory.join("browsers.json")).unwrap(),
                ),
                connections: Mutex::new(HashMap::new()),
                inflight: AtomicUsize::new(0),
                stopped: AtomicBool::new(false),
                prompts: Mutex::new(PromptLimit::default()),
            });
            accept(&inner, server).unwrap();
            Self {
                hub: BrowserHub { inner },
                client,
                directory,
                handler,
            }
        }
        fn request(&mut self, id: &str, request: BrowserRequest) -> serde_json::Value {
            Self::request_on(&mut self.client, id, request)
        }
        fn request_on(
            client: &mut UnixStream,
            id: &str,
            request: BrowserRequest,
        ) -> serde_json::Value {
            session::write_frame(
                client,
                &serde_json::to_vec(&RequestEnvelope {
                    version: VERSION,
                    id: id.into(),
                    request,
                })
                .unwrap(),
                false,
            )
            .unwrap();
            serde_json::from_slice(&session::read_frame(client, false).unwrap()).unwrap()
        }
        fn connect(&self) -> UnixStream {
            let (client, server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            accept(&self.hub.inner, server).unwrap();
            client
        }
        fn authenticate(client: &mut UnixStream, id: &str, key: &SigningKey) -> serde_json::Value {
            let challenge = Self::request_on(
                client,
                "hello",
                BrowserRequest::Hello {
                    pairing_id: Some(id.into()),
                },
            );
            let pid = std::process::id();
            let signature: Signature = key.sign(&session::transcript(
                challenge["nonce"].as_str().unwrap(),
                id,
                pid,
            ));
            Self::request_on(
                client,
                "auth",
                BrowserRequest::Authenticate {
                    pairing_id: id.into(),
                    sig: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                    host_pid: pid,
                },
            )
        }
        fn pair(&mut self) -> (String, SigningKey) {
            let key = SigningKey::from_slice(&[9; 32]).unwrap();
            let challenge = self.request("hello", BrowserRequest::Hello { pairing_id: None });
            let id = challenge["pairing_id"].as_str().unwrap().to_owned();
            let nonce = challenge["nonce"].as_str().unwrap();
            let pid = std::process::id();
            let signature: Signature = key.sign(&session::transcript(nonce, &id, pid));
            let response = self.request(
                "pair",
                BrowserRequest::RequestPairing {
                    pairing_id: id.clone(),
                    public_key_spki: URL_SAFE_NO_PAD
                        .encode(key.verifying_key().to_public_key_der().unwrap().as_bytes()),
                    label: "Test browser".into(),
                    sig: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                    host_pid: pid,
                },
            );
            assert_eq!(response["type"], "Paired");
            (id, key)
        }
    }
    impl Drop for Harness {
        fn drop(&mut self) {
            self.hub.shutdown();
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn unauthenticated_requests_never_reach_vault_handler() {
        let mut h = Harness::new();
        let response = h.request("status", BrowserRequest::Status);
        assert_eq!(response["code"], "Unpaired");
        assert_eq!(h.handler.requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn pairing_requires_valid_proof_before_desktop_approval() {
        let mut h = Harness::new();
        let challenge = h.request("hello", BrowserRequest::Hello { pairing_id: None });
        let response = h.request(
            "bad-proof",
            BrowserRequest::RequestPairing {
                pairing_id: challenge["pairing_id"].as_str().unwrap().into(),
                public_key_spki: "invalid".into(),
                label: "Test".into(),
                sig: "invalid".into(),
                host_pid: std::process::id(),
            },
        );
        assert_eq!(response["code"], "Unauthorized");
        assert_eq!(h.handler.approvals.load(Ordering::SeqCst), 0);
        assert!(h.hub.list_pairings().unwrap().is_empty());
        let replay = h.request(
            "replay",
            BrowserRequest::Authenticate {
                pairing_id: challenge["pairing_id"].as_str().unwrap().into(),
                sig: "invalid".into(),
                host_pid: std::process::id(),
            },
        );
        assert_eq!(replay["code"], "Unauthorized");
    }

    #[test]
    fn approved_pairing_authenticates_and_revoke_cancels_connection() {
        let mut h = Harness::new();
        let (id, _) = h.pair();
        assert_eq!(h.handler.approvals.load(Ordering::SeqCst), 1);
        assert_eq!(
            h.request("status", BrowserRequest::Status)["type"],
            "Status"
        );
        assert_eq!(h.hub.list_pairings().unwrap().len(), 1);
        let connection = h.hub.connections().pop().unwrap();
        let context = connection.context();
        h.hub.revoke(&id).unwrap();
        assert!(context.is_cancelled());
        assert!(h.hub.list_pairings().unwrap().is_empty());
    }

    #[test]
    fn revoke_disconnects_every_session_and_prevents_reauthentication_after_reload() {
        let mut h = Harness::new();
        let (id, key) = h.pair();
        let mut second = h.connect();
        assert_eq!(
            Harness::authenticate(&mut second, &id, &key)["type"],
            "Authenticated"
        );
        let contexts: Vec<_> = h
            .hub
            .connections()
            .iter()
            .map(|connection| connection.context())
            .collect();
        assert_eq!(contexts.len(), 2);
        h.hub.revoke(&id).unwrap();
        assert!(contexts.iter().all(RequestContext::is_cancelled));
        let disk = PairingStore::load_at(h.directory.join("browsers.json")).unwrap();
        assert!(disk.list().is_empty());
        *h.hub.inner.pairings.lock().unwrap() = disk;
        let mut reconnect = h.connect();
        assert_eq!(
            Harness::authenticate(&mut reconnect, &id, &key)["code"],
            "Unpaired"
        );
        assert_eq!(h.handler.requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn revoke_cancels_inflight_work_before_waiting_for_writer_completion() {
        let mut h = Harness::new();
        let (id, key) = h.pair();
        let mut second = h.connect();
        assert_eq!(
            Harness::authenticate(&mut second, &id, &key)["type"],
            "Authenticated"
        );
        let contexts: Vec<_> = h
            .hub
            .connections()
            .iter()
            .map(|connection| connection.context())
            .collect();
        let connection = h.hub.connections().pop().unwrap();
        let release = connection.release.lock().unwrap();
        let hub = h.hub.clone();
        let revoke = std::thread::spawn(move || hub.revoke(&id));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !contexts.iter().all(RequestContext::is_cancelled) {
            assert!(
                Instant::now() < deadline,
                "revocation waited for the writer before cancelling"
            );
            std::thread::yield_now();
        }
        assert!(
            !revoke.is_finished(),
            "revoke must wait for writer completion before reporting success"
        );
        drop(release);
        revoke.join().unwrap().unwrap();
    }

    #[test]
    fn last_authenticated_changes_only_after_a_valid_proof_and_is_durable() {
        let mut h = Harness::new();
        let (id, key) = h.pair();
        let path = h.directory.join("browsers.json");
        let mut records = h.hub.list_pairings().unwrap();
        records[0].last_seen_at = 1;
        std::fs::write(&path, serde_json::to_vec(&records).unwrap()).unwrap();
        *h.hub.inner.pairings.lock().unwrap() = PairingStore::load_at(path.clone()).unwrap();
        let mut reconnect = h.connect();
        let wrong_key = SigningKey::from_slice(&[7; 32]).unwrap();
        assert_eq!(
            Harness::authenticate(&mut reconnect, &id, &wrong_key)["code"],
            "Unauthorized"
        );
        assert_eq!(h.hub.list_pairings().unwrap()[0].last_seen_at, 1);
        assert_eq!(
            Harness::authenticate(&mut reconnect, &id, &key)["type"],
            "Authenticated"
        );
        let record = h.hub.list_pairings().unwrap().remove(0);
        assert!(record.last_seen_at > 1);
        assert!(record.last_seen_at >= record.created_at);
        assert_eq!(
            PairingStore::load_at(path).unwrap().list()[0].last_seen_at,
            record.last_seen_at
        );
    }

    #[test]
    fn unavailable_pairing_store_is_reported_instead_of_an_empty_list() {
        let h = Harness::new();
        let inner = h.hub.inner.clone();
        let _ = std::thread::spawn(move || {
            let _store = inner.pairings.lock().unwrap();
            panic!("poison the test pairing store");
        })
        .join();
        assert_eq!(
            h.hub.list_pairings().unwrap_err(),
            "Pairing store unavailable"
        );
    }

    #[test]
    fn invalidation_discards_already_computed_credentials() {
        let mut h = Harness::new();
        h.pair();
        let connection = h.hub.connections().pop().unwrap();
        let context = connection.context();
        h.hub.invalidate(BrowserEvent::Locked { epoch: 2 });
        assert!(context.is_cancelled());
        connection.reply(
            "stale".into(),
            BrowserResponse::Credentials {
                username: "secret-user".into(),
                password: "secret-password".into(),
                document_id: "document".into(),
                epoch: 1,
            },
            Some(context),
        );
        let event: serde_json::Value =
            serde_json::from_slice(&session::read_frame(&mut h.client, false).unwrap()).unwrap();
        assert_eq!(event["type"], "Locked");
        h.client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        assert!(session::read_frame(&mut h.client, false).is_err());
    }

    #[test]
    fn queued_credentials_remain_cancellable_until_writer_finishes() {
        let mut h = Harness::new();
        h.pair();
        let connection = h.hub.connections().pop().unwrap();
        let release = connection.release.lock().unwrap();
        let permit = acquire_job(&h.hub.inner, &connection, "queued-secret").unwrap();
        let mut context = connection.context();
        context.cancelled = permit.cancelled.clone();
        connection.reply_job(
            "queued-secret".into(),
            BrowserResponse::Credentials {
                username: "secret-user".into(),
                password: "secret-password".into(),
                document_id: "document".into(),
                epoch: 1,
            },
            context,
            permit,
        );
        let cancelled = connection
            .pending_ids
            .lock()
            .unwrap()
            .get("queued-secret")
            .cloned()
            .expect("queued responses must retain cancellation tokens");
        cancelled.store(true, Ordering::Release);
        drop(release);
        h.client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        assert!(session::read_frame(&mut h.client, false).is_err());
        assert!(
            !connection
                .pending_ids
                .lock()
                .unwrap()
                .contains_key("queued-secret")
        );
    }

    #[test]
    fn expired_passkey_response_is_discarded_at_the_guarded_writer() {
        let mut h = Harness::new();
        h.pair();
        let connection = h.hub.connections().pop().unwrap();
        let release = connection.release.lock().unwrap();
        let permit = acquire_job(&h.hub.inner, &connection, "late-passkey").unwrap();
        let mut context = connection.context();
        context.cancelled = permit.cancelled.clone();
        context.deadline = Some(Instant::now() + Duration::from_millis(10));
        connection.reply_job(
            "late-passkey".into(),
            BrowserResponse::PasskeyResult {
                result: crate::passkeys::PasskeyResult {
                    signature: Some("assertion".into()),
                    ..Default::default()
                },
            },
            context,
            permit,
        );
        std::thread::sleep(Duration::from_millis(20));
        drop(release);
        h.client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        assert!(session::read_frame(&mut h.client, false).is_err());
        assert!(
            !connection
                .pending_ids
                .lock()
                .unwrap()
                .contains_key("late-passkey")
        );
    }

    #[test]
    fn connection_workers_and_rate_are_bounded() {
        let h = Harness::new();
        let connection = h.hub.connections().pop().unwrap();
        let permits: Vec<_> = (0..MAX_CONNECTION_INFLIGHT)
            .map(|n| acquire_job(&h.hub.inner, &connection, &n.to_string()).unwrap())
            .collect();
        assert!(acquire_job(&h.hub.inner, &connection, "extra").is_none());
        drop(permits);
        assert_eq!(h.hub.inner.inflight.load(Ordering::Acquire), 0);
        assert_eq!(connection.inflight.load(Ordering::Acquire), 0);
        let mut times = VecDeque::new();
        assert!((0..20).all(|_| allow_rate(&mut times, 20)));
        assert!(!allow_rate(&mut times, 20));
    }

    #[test]
    fn credentials_debug_output_is_redacted() {
        let response = BrowserResponse::Credentials {
            username: "secret-user".into(),
            password: "secret-password".into(),
            document_id: "document".into(),
            epoch: 1,
        };
        let debug = format!("{response:?}");
        assert!(!debug.contains("secret-user"));
        assert!(!debug.contains("secret-password"));
    }

    #[test]
    fn handshake_lifetime_is_absolute_and_approval_has_separate_deadline() {
        let accepted = Instant::now() - Duration::from_secs(11);
        let mut state = SessionState::default();
        assert!(session_deadline(accepted, &state).unwrap() < Instant::now());
        state.challenge = Some(Challenge {
            nonce: "new-nonce".into(),
            pairing_id: "id".into(),
            created: Instant::now(),
            existing: false,
        });
        assert!(
            session_deadline(accepted, &state).unwrap() < Instant::now(),
            "Issuing another Hello must not renew the handshake lifetime"
        );
        let approval_deadline = Instant::now() + Duration::from_secs(60);
        state.pairing_pending = true;
        state.pairing_deadline = Some(approval_deadline);
        assert_eq!(session_deadline(accepted, &state), Some(approval_deadline));
        state.pairing_id = Some("id".into());
        assert_eq!(session_deadline(accepted, &state), None);
    }
}
