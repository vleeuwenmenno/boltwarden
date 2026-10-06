mod app;
#[cfg_attr(windows, path = "platform/auto_lock_windows.rs")]
#[cfg_attr(target_os = "macos", path = "platform/auto_lock_macos.rs")]
mod auto_lock;
mod backend;
mod browser;
mod browser_approval;
mod browser_backend;
#[cfg(test)]
mod browser_backend_tests;
mod bw;
#[cfg_attr(windows, path = "platform/clipboard_windows.rs")]
#[cfg_attr(target_os = "macos", path = "platform/clipboard_macos.rs")]
mod clipboard;
mod config;
mod demo;
mod health;
mod icons;
mod instance;
mod interaction;
mod logo;
mod model;
mod offline_cache;
mod passkeys;
mod platform;
mod random;
mod rpc;
#[cfg_attr(windows, path = "platform/screen_capture_windows.rs")]
mod screen_capture;
mod shortcut;
#[cfg_attr(windows, path = "platform/ssh_agent_windows.rs")]
mod ssh_agent;
#[cfg_attr(windows, path = "platform/tray_windows.rs")]
#[cfg_attr(target_os = "macos", path = "platform/tray_macos.rs")]
mod tray;
mod ui;
#[cfg(unix)]
mod unix_socket;
mod uri_match;
mod version;
mod window;

use crate::platform::ipc::{Listener as UnixListener, Stream as UnixStream};
use app::{App, PopupCommand};
use backend::AppBackend;
use bw::{BwClient, BwError, TwoFactorChallenge};
use eframe::egui;
use instance::LaunchCommand;
use model::SshAgentStatus;
use rpc::{RpcEndpoint, RpcEnvelope, RpcError, RpcRequest, RpcResponse, SearchPayload};
use ssh_agent::{SshAgentHandle, SshApprovalService, SshKeyStore};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};
use tray::TrayCommand;

/// Base for test directories. The macOS per-user temp dir is long enough to push socket
/// paths past the 104-byte limit, and sits behind the `/var` -> `/private/var` symlink.
#[cfg(test)]
pub(crate) fn test_temp_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/private/tmp")
    } else {
        std::env::temp_dir()
    }
}

const POPUP_TOKEN_PREFIX: &str = "token ";
/// Internal flag that starts the vault window process; users run `boltwarden window`.
const WINDOW_FLAG: &str = "--vault-window";
const POPUP_FLAG: &str = "--popup";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonCommand {
    Show,
    Hide,
    Toggle,
    ShowWindow,
    ToggleWindow,
    Quit,
}

struct PopupProcess {
    child: Child,
    stdin: ChildStdin,
}

type PopupChild = Arc<Mutex<Option<PopupProcess>>>;

struct VaultState {
    browser_hub: Option<browser::BrowserHub>,
    browser_handler: Option<Arc<browser_backend::DaemonBrowserBackend>>,
    browser_approvals: browser_approval::BrowserApprovals,
    browser_enabled: bool,
    browser_default_match: uri_match::UriMatchType,
    passkey_verification: config::PasskeyVerification,
    browser_epoch: u64,
    browser_unlock: Option<interaction::Lease>,
    popup: PopupChild,
    /// The full vault window, a second client process next to the popup.
    window: PopupChild,
    clipboard: clipboard::Clipboard,
    auto_lock_warning: Option<String>,
    bw: BwClient,
    pending_two_factor: Option<TwoFactorChallenge>,
    ssh_agent: Option<SshAgentHandle>,
    ssh_agent_status: SshAgentStatus,
    ssh_approvals: SshApprovalService,
    ssh_key_store: SshKeyStore,
}

pub fn run() -> eframe::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V" | "version") => {
            println!("{}", version::summary());
            return Ok(());
        }
        Some("native-host") => {
            if let Err(error) = browser::native_host::run_native_host() {
                eprintln!("native host: {error}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("uninstall-browser") => {
            let args = std::iter::once("--uninstall".to_string()).chain(std::env::args().skip(2));
            if let Err(error) = browser::install::run(args) {
                eprintln!("uninstall-browser: {error}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("install-browser") => {
            if let Err(error) = browser::install::run(std::env::args().skip(2)) {
                eprintln!("install-browser: {error}");
                std::process::exit(1);
            }
            return Ok(());
        }
        _ => {}
    }
    if std::env::args().any(|arg| arg == "--popup") {
        return run_popup();
    }
    if std::env::args().any(|arg| arg == WINDOW_FLAG) {
        return run_window();
    }

    let launch_command = LaunchCommand::from_args(std::env::args().skip(1));
    let show_on_start = launch_command != LaunchCommand::Daemon;
    let listener = match instance::prepare(launch_command) {
        instance::Instance::ActivatedExisting => return Ok(()),
        instance::Instance::Primary(listener) => listener,
        instance::Instance::Failed(message) => {
            return Err(eframe::Error::AppCreation(message.into()));
        }
    };

    run_daemon(listener, show_on_start)
}

fn run_daemon(listener: Option<UnixListener>, show_on_start: bool) -> eframe::Result<()> {
    #[cfg(unix)]
    std::thread::spawn(|| {
        if let Err(error) = browser::install::repair_launcher() {
            eprintln!("browser integration repair: {error}");
        }
    });
    let (tx, rx) = mpsc::channel();
    let (shortcut_tx, shortcut_rx) = mpsc::channel();
    shortcut::start(shortcut_tx);
    let shortcut_daemon = tx.clone();
    std::thread::spawn(move || {
        while shortcut_rx.recv().is_ok() {
            if shortcut_daemon.send(DaemonCommand::Toggle).is_err() {
                break;
            }
        }
    });
    let (approval_show_tx, approval_show_rx) = mpsc::channel();
    let (unlock_show_tx, unlock_show_rx) = mpsc::channel();
    let (browser_approval_tx, browser_approval_rx) = mpsc::channel();
    let popup = Arc::new(Mutex::new(None));
    let window: PopupChild = Arc::new(Mutex::new(None));
    let ssh_approvals = SshApprovalService::new(approval_show_tx);
    let ssh_key_store = SshKeyStore::new(unlock_show_tx.clone());
    let vault = Arc::new(Mutex::new(VaultState {
        browser_hub: None,
        browser_handler: None,
        browser_approvals: browser_approval::BrowserApprovals::new(browser_approval_tx),
        browser_enabled: false,
        browser_default_match: uri_match::UriMatchType::Host,
        passkey_verification: config::PasskeyVerification::default(),
        browser_epoch: 0,
        browser_unlock: None,
        clipboard: clipboard::Clipboard::default(),
        popup: popup.clone(),
        window: window.clone(),
        auto_lock_warning: None,
        bw: BwClient::new(),
        pending_two_factor: None,
        ssh_agent: None,
        ssh_agent_status: ssh_agent::disabled_status(),
        ssh_approvals: ssh_approvals.clone(),
        ssh_key_store,
    }));
    let rpc_socket = start_vault_rpc_listener(vault.clone(), ssh_approvals.clone(), tx.clone());

    start_tray(tx.clone());
    start_activation_listener(listener, tx.clone());
    start_approval_popup_listener(approval_show_rx, popup.clone(), rpc_socket.clone());
    start_unlock_popup_listener(unlock_show_rx, popup.clone(), rpc_socket.clone());
    {
        let popup = popup.clone();
        let rpc_socket = rpc_socket.clone();
        std::thread::spawn(move || {
            while browser_approval_rx.recv().is_ok() {
                show_popup_with_command(
                    &popup,
                    rpc_socket.as_ref(),
                    "browser-approval return\n",
                    "browser-approval auto\n",
                );
            }
        });
    }
    start_auto_lock_monitor(vault.clone());
    let _daemon_tx_keepalive = tx;

    if let Ok(mut state) = vault.lock() {
        state.browser_handler = Some(Arc::new(browser_backend::DaemonBrowserBackend {
            vault: Arc::downgrade(&vault),
            unlock: unlock_show_tx,
        }));
        if let Err(error) = apply_browser_settings(&mut state) {
            eprintln!("browser integration: {error}");
        }
        apply_ssh_agent_settings(&mut state);
    }

    if show_on_start {
        show_popup(&popup, rpc_socket.as_ref());
    }
    while let Ok(command) = next_daemon_command(&rx) {
        match command {
            DaemonCommand::Show => show_popup(&popup, rpc_socket.as_ref()),
            DaemonCommand::Hide => hide_popup(&popup),
            DaemonCommand::Toggle => toggle_popup(&popup, rpc_socket.as_ref()),
            DaemonCommand::ShowWindow => show_window(&window, rpc_socket.as_ref()),
            DaemonCommand::ToggleWindow => toggle_window(&window, rpc_socket.as_ref()),
            DaemonCommand::Quit => {
                quit_popup(&popup);
                quit_popup(&window);
                if let Ok(mut state) = vault.lock() {
                    invalidate_browser(&mut state, false);
                    if let Some(hub) = state.browser_hub.take() {
                        hub.shutdown();
                    }
                    state.clipboard.clear();
                    stop_ssh_agent(&mut state);
                    state.ssh_approvals.clear_all("daemon quit");
                }
                break;
            }
        }
    }

    Ok(())
}

/// macOS delivers menu bar clicks and hotkeys on the main thread, so it keeps handling them while waiting.
fn next_daemon_command(
    rx: &mpsc::Receiver<DaemonCommand>,
) -> Result<DaemonCommand, mpsc::RecvError> {
    #[cfg(target_os = "macos")]
    {
        platform::main_thread::recv(rx)
    }
    #[cfg(not(target_os = "macos"))]
    {
        rx.recv()
    }
}

fn start_auto_lock_monitor(vault: Arc<Mutex<VaultState>>) {
    let events = auto_lock::subscribe();
    std::thread::spawn(move || {
        let mut idle_seen_at: Option<Instant> = None;
        loop {
            let event = match events.recv_timeout(Duration::from_secs(20)) {
                Ok(event) => event,
                Err(_) => {
                    // Keep enforcing a lock after worker failure without a busy loop.
                    std::thread::sleep(Duration::from_secs(1));
                    auto_lock::Event::Unavailable("Session monitor stopped responding".into())
                }
            };
            let settings = config::load_settings();
            let Ok(mut state) = vault.lock() else {
                break;
            };
            let enabled = settings.lock_on_system_lock || settings.lock_after_idle_timeout;
            if !enabled {
                if state.auto_lock_warning.take().is_some() {
                    notify_clients(&state, "lock-warning\n");
                }
                idle_seen_at = None;
                continue;
            }
            let reason = match event {
                auto_lock::Event::Unavailable(error) => {
                    idle_seen_at = None;
                    let message = format!(
                        "Automatic locking unavailable: {error}. Vault locked for safety. Restore the desktop session service or disable automatic locking in Settings."
                    );
                    if state.auto_lock_warning.as_ref() != Some(&message) {
                        eprintln!("{message}");
                        state.auto_lock_warning = Some(message);
                        notify_clients(&state, "lock-warning\n");
                    }
                    Some("session monitoring unavailable")
                }
                auto_lock::Event::LockRequested(reason) => {
                    settings.lock_on_system_lock.then_some(reason)
                }
                auto_lock::Event::State(session) => {
                    if state.auto_lock_warning.take().is_some() {
                        notify_clients(&state, "lock-warning\n");
                    }
                    if settings.lock_on_system_lock && session.locked {
                        idle_seen_at = None;
                        Some("screen locked")
                    } else if settings.lock_after_idle_timeout && session.idle {
                        let seen = idle_seen_at.get_or_insert_with(Instant::now);
                        let idle_for = session.idle_for.unwrap_or_else(|| seen.elapsed());
                        (idle_for >= idle_lock_timeout(&settings)).then_some("idle timeout")
                    } else {
                        idle_seen_at = None;
                        None
                    }
                }
            };
            if let Some(reason) = reason {
                if state.bw.has_session() || state.pending_two_factor.is_some() {
                    lock_vault_state(&mut state, reason);
                }
            }
        }
    });
}

fn run_popup() -> eframe::Result<()> {
    debug_log("starting popup");
    // Read the token before the stdin listener thread starts consuming lines.
    let backend = if demo::enabled() {
        AppBackend::demo()
    } else {
        let Some(path) = popup_rpc_socket_arg() else {
            eprintln!("--popup is internal. Run boltwarden without --popup.");
            return Ok(());
        };
        AppBackend::remote(rpc::RpcClient::new(path, read_popup_token()))
    };
    let (popup_tx, popup_rx) = mpsc::channel();
    start_popup_stdin_listener(popup_tx);
    let result = eframe::run_native(
        "boltwarden",
        popup_options(),
        Box::new(|cc| {
            #[cfg(target_os = "macos")]
            platform::macos::join_all_spaces(cc);
            ui::theme::theme().install(&cc.egui_ctx);
            Ok(Box::new(App::new(backend, popup_rx)))
        }),
    );
    debug_log("popup event loop exited");
    result
}

fn run_window() -> eframe::Result<()> {
    debug_log("starting vault window");
    let backend = if demo::enabled() {
        AppBackend::demo()
    } else {
        let Some(path) = popup_rpc_socket_arg() else {
            eprintln!("{WINDOW_FLAG} is internal. Run `boltwarden window` instead.");
            return Ok(());
        };
        AppBackend::remote(rpc::RpcClient::new(path, read_popup_token()))
    };
    let (popup_tx, popup_rx) = mpsc::channel();
    start_popup_stdin_listener(popup_tx);
    eframe::run_native(
        "boltwarden",
        window::options(),
        Box::new(|cc| {
            ui::theme::theme().install(&cc.egui_ctx);
            Ok(Box::new(window::WindowApp::new(backend, popup_rx)))
        }),
    )
}

fn start_tray(tx: mpsc::Sender<DaemonCommand>) {
    let (tray_tx, tray_rx) = mpsc::channel();
    match tray::spawn(tray_tx) {
        Ok(handle) => {
            std::thread::spawn(move || {
                let _handle = handle;
                while let Ok(command) = tray_rx.recv() {
                    let daemon_command = match command {
                        TrayCommand::Show => DaemonCommand::Show,
                        TrayCommand::Hide => DaemonCommand::Hide,
                        TrayCommand::Toggle => DaemonCommand::Toggle,
                        TrayCommand::Window => DaemonCommand::ShowWindow,
                        TrayCommand::Quit => DaemonCommand::Quit,
                    };
                    let should_quit = daemon_command == DaemonCommand::Quit;
                    let _ = tx.send(daemon_command);
                    if should_quit {
                        break;
                    }
                }
            });
        }
        Err(e) => {
            eprintln!("could not start tray icon: {e}");
        }
    }
}

fn start_activation_listener(listener: Option<UnixListener>, tx: mpsc::Sender<DaemonCommand>) {
    let Some(listener) = listener else {
        return;
    };

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut message = String::new();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            use std::io::BufRead;
            if std::io::BufReader::new((&stream).take(128))
                .read_line(&mut message)
                .is_err()
            {
                continue;
            }
            if !message.ends_with('\n') {
                continue;
            }
            #[cfg(windows)]
            {
                let _ = (&stream).write_all(&[1]);
            }
            let command = match LaunchCommand::parse(&message) {
                LaunchCommand::Show => DaemonCommand::Show,
                LaunchCommand::Toggle => DaemonCommand::Toggle,
                LaunchCommand::Window => DaemonCommand::ShowWindow,
                LaunchCommand::ToggleWindow => DaemonCommand::ToggleWindow,
                LaunchCommand::Daemon => continue,
                LaunchCommand::Quit => DaemonCommand::Quit,
            };
            let _ = tx.send(command);
        }
    });
}

fn start_approval_popup_listener(
    rx: mpsc::Receiver<()>,
    popup: PopupChild,
    rpc_socket: Option<RpcEndpoint>,
) {
    std::thread::spawn(move || {
        while rx.recv().is_ok() {
            show_approval_popup(&popup, rpc_socket.as_ref());
        }
    });
}

fn start_unlock_popup_listener(
    rx: mpsc::Receiver<()>,
    popup: PopupChild,
    rpc_socket: Option<RpcEndpoint>,
) {
    std::thread::spawn(move || {
        while rx.recv().is_ok() {
            show_unlock_popup(&popup, rpc_socket.as_ref());
        }
    });
}

fn start_vault_rpc_listener(
    vault: Arc<Mutex<VaultState>>,
    ssh_approvals: SshApprovalService,
    daemon: mpsc::Sender<DaemonCommand>,
) -> Option<RpcEndpoint> {
    match rpc::prepare_listener() {
        Ok((endpoint, listener)) => {
            let token = Arc::new(endpoint.token.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let vault = vault.clone();
                    let ssh_approvals = ssh_approvals.clone();
                    let token = token.clone();
                    let daemon = daemon.clone();
                    std::thread::spawn(move || {
                        handle_rpc_stream(stream, &token, vault, ssh_approvals, daemon)
                    });
                }
            });
            Some(endpoint)
        }
        Err(e) => {
            eprintln!("could not start vault RPC socket: {e}");
            None
        }
    }
}

fn handle_rpc_stream(
    mut stream: UnixStream,
    token: &str,
    vault: Arc<Mutex<VaultState>>,
    ssh_approvals: SshApprovalService,
    daemon: mpsc::Sender<DaemonCommand>,
) {
    let response = match read_authenticated_request(&mut stream, token) {
        Ok(request) => handle_rpc_request(request, &vault, &ssh_approvals, &daemon),
        Err(message) => {
            debug_log(&format!("rejected RPC request: {message}"));
            RpcResponse::Error(message)
        }
    };

    if let Ok(payload) = serde_json::to_vec(&response) {
        let payload = zeroize::Zeroizing::new(payload);
        #[cfg(windows)]
        {
            let _ = stream.write_all(&(payload.len() as u32).to_be_bytes());
        }
        let _ = stream.write_all(&payload);
        #[cfg(windows)]
        {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.read_exact(&mut [0u8; 1]);
        }
    }
}

/// Reads one request and checks it comes from our own uid and carries the daemon token.
/// Only popups spawned by this daemon know the token.
fn read_authenticated_request(stream: &mut UnixStream, token: &str) -> Result<RpcRequest, String> {
    match platform::ipc::peer_uid(stream) {
        Ok(uid) if uid == platform::ipc::current_uid() => {}
        Ok(uid) => return Err(format!("peer uid {uid} is not allowed")),
        Err(e) => return Err(format!("could not inspect peer credentials: {e}")),
    }
    // A client that never finishes writing must not pin a thread forever.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut body = zeroize::Zeroizing::new(Vec::new());
    #[cfg(not(windows))]
    (&mut *stream)
        .take(rpc::MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|e| format!("could not read daemon request: {e}"))?;
    #[cfg(windows)]
    {
        let mut length = [0u8; 4];
        stream.read_exact(&mut length).map_err(|e| e.to_string())?;
        let length = u32::from_be_bytes(length) as usize;
        if length as u64 > rpc::MAX_REQUEST_BYTES {
            return Err("daemon request is too large".into());
        }
        body.resize(length, 0);
        stream.read_exact(&mut body).map_err(|e| e.to_string())?;
    }
    if body.len() as u64 > rpc::MAX_REQUEST_BYTES {
        return Err("daemon request is too large".into());
    }
    let envelope: RpcEnvelope = serde_json::from_slice(&body)
        .map_err(|e| format!("could not decode daemon request: {e}"))?;
    if !rpc::token_matches(token, &envelope.token) {
        return Err("daemon request is not authorized".into());
    }
    Ok(envelope.request)
}

fn handle_rpc_request(
    request: RpcRequest,
    vault: &Arc<Mutex<VaultState>>,
    ssh_approvals: &SshApprovalService,
    daemon: &mpsc::Sender<DaemonCommand>,
) -> RpcResponse {
    match request {
        RpcRequest::GetShortcut => return RpcResponse::Shortcut(Ok(shortcut::status())),
        RpcRequest::SetShortcut(value) => return RpcResponse::Shortcut(shortcut::set(value)),
        RpcRequest::ShortcutBinding(value) => {
            return RpcResponse::ShortcutBinding(shortcut::binding(&value));
        }
        RpcRequest::OpenWindow => {
            return RpcResponse::WindowOpened(
                daemon
                    .send(DaemonCommand::ShowWindow)
                    .map_err(|_| "daemon is shutting down".to_string()),
            );
        }
        RpcRequest::VaultHealth => {
            // The directory download can take seconds; don't hold the vault lock for it.
            let directory = health::directory();
            let Ok(mut state) = vault.lock() else {
                return RpcResponse::Health(Err(RpcError::Message(
                    "vault state lock poisoned".into(),
                )));
            };
            return RpcResponse::Health(
                state
                    .bw
                    .health_report(&directory)
                    .map_err(rpc_error_from_bw),
            );
        }
        RpcRequest::Sync => return RpcResponse::Synced(sync_vault(vault)),
        RpcRequest::GetSshApproval => {
            return RpcResponse::SshApproval(ssh_approvals.active_request());
        }
        RpcRequest::DecideSshApproval(decision) => {
            return RpcResponse::SshApprovalDecided(ssh_approvals.decide(decision));
        }
        RpcRequest::GetSshApprovalStatus => {
            return RpcResponse::SshApprovalStatus(ssh_approvals.recent_status());
        }
        RpcRequest::GetBrowserApproval => {
            return RpcResponse::BrowserApproval(
                vault
                    .lock()
                    .ok()
                    .and_then(|state| state.browser_approvals.active()),
            );
        }
        RpcRequest::DecideBrowserApproval(decision) => {
            let result = (|| {
                let state = vault.lock().map_err(|_| "Vault unavailable".to_string())?;
                let request = state
                    .browser_approvals
                    .active()
                    .filter(|request| request.id == decision.request_id)
                    .ok_or_else(|| "Browser request is no longer pending".to_string())?;
                if decision.approved {
                    if decision.use_other_device {
                        return Err("Invalid approval decision".into());
                    }
                    if !state.browser_enabled || !state.bw.has_session() {
                        return Err("Vault is locked or browser integration disabled".into());
                    }
                    if request.requires_password_for(decision.selected_id.as_deref())? {
                        state
                            .bw
                            .verify_master_password(&decision.password)
                            .map_err(|e| e.to_string())?;
                    }
                }
                state.browser_approvals.resolve(
                    &decision.request_id,
                    if decision.approved {
                        Ok(decision.selected_id.clone())
                    } else {
                        Err(if decision.use_other_device && request.allow_fallback {
                            "FallbackRequested".into()
                        } else {
                            "Denied".into()
                        })
                    },
                )
            })();
            return RpcResponse::BrowserApprovalDecided(result);
        }
        request => {
            return handle_vault_rpc_request(request, vault);
        }
    }
}

fn handle_vault_rpc_request(request: RpcRequest, vault: &Arc<Mutex<VaultState>>) -> RpcResponse {
    let Ok(mut state) = vault.lock() else {
        return RpcResponse::ClearSavedSession(Err("vault state lock poisoned".into()));
    };

    let was_unlocked = state.bw.has_session();
    let explicit_lock = matches!(
        request,
        RpcRequest::LockVault | RpcRequest::ClearSavedSession
    );
    let response = match request {
        RpcRequest::HasSession => RpcResponse::HasSession(state.bw.has_session()),
        RpcRequest::CopyField { id, index, version } => {
            let result = state
                .bw
                .get_item(&id)
                .map_err(|e| e.to_string())
                .and_then(|item| zeroize::Zeroizing::new(item).copy_value_checked(index, &version))
                .and_then(|value| {
                    let value = zeroize::Zeroizing::new(value);
                    if value.is_empty() {
                        return Err("This field is empty".into());
                    }
                    state.clipboard.copy(&value)
                });
            RpcResponse::Copied(result)
        }
        RpcRequest::SecurityWarning => {
            RpcResponse::SecurityWarning(state.auto_lock_warning.clone())
        }
        RpcRequest::AuthorizeItem { id, mut password } => {
            use zeroize::Zeroize;
            let result = state
                .bw
                .authorize_item(&id, &password)
                .map_err(rpc_error_from_bw);
            password.zeroize();
            RpcResponse::Detail(result)
        }
        RpcRequest::RevokeItemGrants => {
            state.bw.revoke_item_grants();
            RpcResponse::LockVault(Ok(()))
        }
        RpcRequest::Login {
            server_url,
            email,
            password,
            remember,
        } => {
            let password = zeroize::Zeroizing::new(password);
            RpcResponse::Login(login_vault(
                &mut state,
                &server_url,
                &email,
                &password,
                remember,
            ))
        }
        RpcRequest::CompleteTwoFactor {
            provider,
            token,
            remember,
        } => RpcResponse::TwoFactor(complete_vault_two_factor(
            &mut state, provider, &token, remember,
        )),
        RpcRequest::ListItems {
            query,
            state: item_state,
        } => {
            // Answer from memory; windows request a background sync when they open.
            refresh_ssh_key_store_from_vault(&mut state);
            let result = state
                .bw
                .list_items_in(item_state, &query)
                .map(|items| SearchPayload {
                    items,
                    warning: state.bw.sync_warning(),
                    status: state.bw.sync_status(),
                    icons_url: Some(state.bw.icons_url()),
                });
            RpcResponse::Search(result.map_err(rpc_error_from_bw))
        }
        RpcRequest::GetItem { id } => {
            RpcResponse::Detail(state.bw.get_item(&id).map_err(rpc_error_from_bw))
        }
        RpcRequest::GetTotp { id } => {
            RpcResponse::Totp(state.bw.get_totp(&id).map_err(rpc_error_from_bw))
        }
        RpcRequest::ItemAction { id, action } => {
            let result = state
                .bw
                .apply_action(&id, action)
                .map_err(rpc_error_from_bw);
            // Archived and trashed SSH keys must leave the agent, restored ones come back.
            refresh_ssh_key_store_from_vault(&mut state);
            notify_browser_matches(&state);
            RpcResponse::ItemAction(result)
        }
        RpcRequest::GetEditDraft { id } => {
            RpcResponse::EditDraft(state.bw.edit_draft(&id).map_err(rpc_error_from_bw))
        }
        RpcRequest::SaveItem { id, draft } => {
            let draft = zeroize::Zeroizing::new(draft);
            let result = state.bw.save_item(&id, &draft).map_err(rpc_error_from_bw);
            refresh_ssh_key_store_from_vault(&mut state);
            notify_browser_matches(&state);
            RpcResponse::Saved(result)
        }
        RpcRequest::CreateItem { draft } => {
            let draft = zeroize::Zeroizing::new(draft);
            let result = state.bw.create_item(&draft).map_err(rpc_error_from_bw);
            notify_browser_matches(&state);
            RpcResponse::Created(result)
        }
        RpcRequest::ListFolders => {
            RpcResponse::Folders(state.bw.folders().map_err(rpc_error_from_bw))
        }
        RpcRequest::MoveItem { id, folder_id } => {
            let result = state
                .bw
                .move_item(&id, folder_id.as_deref())
                .map_err(rpc_error_from_bw);
            notify_browser_matches(&state);
            RpcResponse::ItemMoved(result)
        }
        RpcRequest::CreateFolder { name } => {
            RpcResponse::FolderCreated(state.bw.create_folder(&name).map_err(rpc_error_from_bw))
        }
        RpcRequest::RenameFolders { renames } => {
            let result = state.bw.rename_folders(&renames).map_err(rpc_error_from_bw);
            refresh_ssh_key_store_from_vault(&mut state);
            RpcResponse::FoldersChanged(result)
        }
        RpcRequest::DeleteFolders { ids } => {
            let result = state.bw.delete_folders(&ids).map_err(rpc_error_from_bw);
            refresh_ssh_key_store_from_vault(&mut state);
            RpcResponse::FoldersChanged(result)
        }
        RpcRequest::ApplySettings(settings) => {
            let result = config::save_settings(&settings)
                .map_err(|e| e.to_string())
                .and_then(|_| apply_browser_settings(&mut state))
                .and_then(|_| state.bw.apply_offline_setting().map_err(|e| e.to_string()))
                .map(|_| apply_ssh_agent_settings(&mut state));
            RpcResponse::SettingsApplied(result)
        }
        RpcRequest::GetSshAgentStatus => {
            let status = apply_ssh_agent_settings(&mut state);
            RpcResponse::SshAgentStatus(status)
        }
        RpcRequest::LockVault => {
            lock_vault_state(&mut state, "vault locked");
            RpcResponse::LockVault(Ok(()))
        }
        RpcRequest::ClearSavedSession => {
            let result = config::clear_saved_session().map_err(|e| e.to_string());
            if result.is_ok() {
                lock_vault_state(&mut state, "saved session cleared");
            }
            RpcResponse::ClearSavedSession(result)
        }
        RpcRequest::ListPairedBrowsers => RpcResponse::PairedBrowsers(
            state
                .browser_hub
                .as_ref()
                .map(|hub| hub.list_pairings())
                .unwrap_or_else(|| {
                    browser::pairing::PairingStore::load()
                        .map(|store| store.list())
                        .map_err(|error| format!("Could not load paired browsers: {error}"))
                }),
        ),
        RpcRequest::RevokePairedBrowser { id } => {
            RpcResponse::BrowserRevoked(match &state.browser_hub {
                Some(hub) => hub.revoke(&id),
                None => browser::pairing::PairingStore::load()
                    .and_then(|mut store| store.revoke(&id))
                    .map_err(|error| error.to_string()),
            })
        }
        RpcRequest::CancelUnlock => {
            state.browser_unlock = None;
            interaction::global().cancel(interaction::Kind::Unlock);
            state.ssh_key_store.cancel_unlock();
            RpcResponse::LockVault(Ok(()))
        }
        RpcRequest::GetSshApproval
        | RpcRequest::DecideSshApproval(_)
        | RpcRequest::GetSshApprovalStatus
        | RpcRequest::GetBrowserApproval
        | RpcRequest::DecideBrowserApproval(_)
        | RpcRequest::GetShortcut
        | RpcRequest::SetShortcut(_)
        | RpcRequest::ShortcutBinding(_)
        | RpcRequest::OpenWindow
        | RpcRequest::Sync
        | RpcRequest::VaultHealth => unreachable!("handled before taking the vault lock"),
    };
    if was_unlocked && !state.bw.has_session() && !explicit_lock {
        lock_vault_state(&mut state, "session revoked");
    }
    response
}

fn login_vault(
    state: &mut VaultState,
    server_url: &str,
    email: &str,
    password: &str,
    remember: bool,
) -> Result<(), RpcError> {
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
            invalidate_browser(state, true);
            state.bw = candidate;
            state.pending_two_factor = None;
            refresh_ssh_key_store_from_vault(state);
            apply_ssh_agent_settings(state);
            Ok(())
        }
        Err(BwError::TwoFactorRequired(challenge)) => {
            let providers = challenge.providers().to_vec();
            state.pending_two_factor = Some(challenge);
            Err(RpcError::TwoFactorRequired { providers })
        }
        Err(e) => Err(rpc_error_from_bw(e)),
    }
}

fn complete_vault_two_factor(
    state: &mut VaultState,
    provider: bw::TwoFactorProvider,
    token: &str,
    remember: bool,
) -> Result<(), RpcError> {
    let Some(challenge) = state.pending_two_factor.clone() else {
        return Err(RpcError::Message("missing two factor challenge".into()));
    };
    let mut candidate = BwClient::new();
    match candidate.complete_two_factor(&challenge, provider, token, remember) {
        Ok(()) => {
            invalidate_browser(state, true);
            state.bw = candidate;
            state.pending_two_factor = None;
            refresh_ssh_key_store_from_vault(state);
            apply_ssh_agent_settings(state);
            Ok(())
        }
        Err(e) => Err(rpc_error_from_bw(e)),
    }
}

fn apply_ssh_agent_settings(state: &mut VaultState) -> SshAgentStatus {
    let settings = config::load_settings();
    if cfg!(windows) || !settings.ssh_agent_enabled {
        stop_ssh_agent(state);
        state.ssh_key_store.set_locked();
        state.ssh_approvals.clear_all("SSH agent disabled");
        state.ssh_agent_status = ssh_agent::disabled_status();
        return state.ssh_agent_status.clone();
    }

    let desired_path = match config::expand_ssh_agent_socket_path(&settings.ssh_agent_socket_path) {
        Ok(path) => path,
        Err(e) => {
            stop_ssh_agent(state);
            state.ssh_key_store.set_locked();
            state
                .ssh_approvals
                .clear_all("invalid SSH agent socket path");
            state.ssh_agent_status = ssh_agent::error_status(&settings, e);
            return state.ssh_agent_status.clone();
        }
    };

    if state.bw.has_session() {
        refresh_ssh_key_store_from_vault(state);
    } else {
        state.ssh_key_store.set_locked();
    }

    if state
        .ssh_agent
        .as_ref()
        .is_some_and(|agent| agent.path() == desired_path)
    {
        state.ssh_agent_status = ssh_agent_status_for_state(&settings, state);
        return state.ssh_agent_status.clone();
    }

    stop_ssh_agent(state);
    match ssh_agent::start(
        &settings,
        state.ssh_key_store.clone(),
        state.ssh_approvals.clone(),
    ) {
        Ok(agent) => {
            state.ssh_agent = Some(agent);
            state.ssh_agent_status = ssh_agent_status_for_state(&settings, state);
        }
        Err(e) => {
            state.ssh_agent_status = ssh_agent::error_status(&settings, e);
        }
    }
    state.ssh_agent_status.clone()
}

fn stop_ssh_agent(state: &mut VaultState) {
    if let Some(agent) = state.ssh_agent.take() {
        agent.stop();
    }
    state.ssh_approvals.clear_all("SSH agent stopped");
}

fn invalidate_browser(state: &mut VaultState, unlocked: bool) {
    state.browser_epoch = state.browser_epoch.wrapping_add(1);
    state.browser_approvals.clear();
    state.browser_unlock = None;
    if let Some(hub) = &state.browser_hub {
        hub.invalidate(if unlocked {
            browser::BrowserEvent::Unlocked {
                epoch: state.browser_epoch,
            }
        } else {
            browser::BrowserEvent::Locked {
                epoch: state.browser_epoch,
            }
        });
    }
}

fn apply_browser_settings(state: &mut VaultState) -> Result<(), String> {
    let settings = config::load_settings();
    apply_browser_request_preferences(state, &settings);
    if !settings.browser_integration_enabled {
        state.browser_enabled = false;
        state.browser_approvals.clear();
        state.browser_unlock = None;
        if let Some(hub) = state.browser_hub.take() {
            state.browser_epoch = state.browser_epoch.wrapping_add(1);
            hub.invalidate(browser::BrowserEvent::Disabled);
            hub.shutdown();
        }
    } else if state.browser_hub.is_none() {
        register_detected_browsers();
        let handler = state
            .browser_handler
            .clone()
            .ok_or("Browser integration is unavailable")?;
        state.browser_hub = Some(browser::BrowserHub::start(handler).map_err(|e| e.to_string())?);
        state.browser_enabled = true;
    }
    Ok(())
}

/// Turning on browser integration registers the detected browsers, unless the user already
/// chose browsers in Browser setup. Failures are logged and retried on the next start.
fn register_detected_browsers() {
    let result = config::load_browser_setup()
        .map_err(|e| e.to_string())
        .and_then(|mut preferences| {
            if preferences.configured {
                return Ok(());
            }
            let rows = browser::install::discover().map_err(|e| e.to_string())?;
            let errors = auto_register_browsers(&mut preferences, rows, |row| {
                browser::install::register(row.executable, row.family, row.native_host_dir)
                    .map_err(|e| e.to_string())
            });
            if preferences.configured {
                config::save_browser_setup(&preferences).map_err(|e| e.to_string())?;
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        });
    if let Err(error) = result {
        eprintln!("browser registration: {error}");
    }
}

/// Registers the unregistered `rows` while browser setup is unconfigured, and marks it
/// configured once all succeeded. Returns the failures.
fn auto_register_browsers(
    preferences: &mut config::BrowserSetupPreferences,
    rows: Vec<browser::install::BrowserRegistration>,
    mut register: impl FnMut(browser::install::BrowserRegistration) -> Result<(), String>,
) -> Vec<String> {
    if preferences.configured {
        return Vec::new();
    }
    let errors: Vec<String> = rows
        .into_iter()
        .filter(|row| !row.registered)
        .filter_map(|row| {
            let label = row.label.clone();
            register(row).err().map(|error| format!("{label}: {error}"))
        })
        .collect();
    preferences.configured = errors.is_empty();
    errors
}

fn apply_browser_request_preferences(state: &mut VaultState, settings: &config::AppSettings) {
    if settings.default_uri_match != state.browser_default_match
        || settings.passkey_verification != state.passkey_verification
    {
        state.browser_default_match = settings.default_uri_match;
        state.passkey_verification = settings.passkey_verification;
        invalidate_browser(state, state.bw.has_session());
    }
}

fn lock_vault_state(state: &mut VaultState, reason: &str) {
    invalidate_browser(state, false);
    state.clipboard.clear();
    notify_clients(state, "vault-locked\n");
    state.bw = BwClient::new();
    state.pending_two_factor = None;
    state.ssh_key_store.set_locked();
    state.ssh_approvals.clear_all(reason);
    apply_ssh_agent_settings(state);
    let _ = config::clear_recent_item();
}

/// Syncs with the server while other requests keep using the cached vault: the
/// vault lock is released for the network round trip.
fn sync_vault(vault: &Arc<Mutex<VaultState>>) -> Result<crate::model::SyncStatus, RpcError> {
    let poisoned = || RpcError::Message("vault state lock poisoned".into());
    let fetch = vault
        .lock()
        .map_err(|_| poisoned())?
        .bw
        .begin_sync()
        .map_err(rpc_error_from_bw)?;
    let fetched = fetch.run();
    let mut state = vault.lock().map_err(|_| poisoned())?;
    let was_unlocked = state.bw.has_session();
    let result = state.bw.finish_sync(fetched).map_err(rpc_error_from_bw);
    refresh_ssh_key_store_from_vault(&mut state);
    if was_unlocked && !state.bw.has_session() {
        lock_vault_state(&mut state, "session revoked");
    } else if result.is_ok() {
        notify_browser_matches(&state);
    }
    result
}

fn refresh_ssh_key_store_from_vault(state: &mut VaultState) {
    match state.bw.ssh_keys() {
        Ok(keys) => state.ssh_key_store.set_unlocked(keys),
        Err(_) => state.ssh_key_store.set_locked(),
    }
}

fn notify_browser_matches(state: &VaultState) {
    if let Some(hub) = &state.browser_hub {
        hub.notify(browser::BrowserEvent::MatchesChanged {
            epoch: state.browser_epoch,
        });
    }
}

fn ssh_agent_status_for_state(
    settings: &config::AppSettings,
    state: &VaultState,
) -> SshAgentStatus {
    let Some(agent) = state.ssh_agent.as_ref() else {
        return ssh_agent::disabled_status();
    };
    if !state.bw.has_session() {
        return ssh_agent::waiting_for_unlock_status(settings);
    }
    match state.bw.ssh_keys() {
        Ok(keys) => {
            let (identity_count, skipped_count) = ssh_agent::prepared_key_counts(&keys);
            let mut status = agent.status();
            status.identity_count = identity_count;
            status.skipped_count = skipped_count;
            status.message = if skipped_count == 0 {
                format!(
                    "Listening at {}; approval required for signing",
                    status.socket_path
                )
            } else {
                format!(
                    "Listening at {}; approval required for signing; skipped {skipped_count} unsupported key(s)",
                    status.socket_path
                )
            };
            status
        }
        Err(e) => ssh_agent::error_status(settings, e.to_string()),
    }
}

fn idle_lock_timeout(settings: &config::AppSettings) -> Duration {
    Duration::from_secs(settings.idle_lock_timeout_minutes.max(1).saturating_mul(60))
}

fn rpc_error_from_bw(error: BwError) -> RpcError {
    match error {
        BwError::Network(message) => RpcError::Network(message),
        BwError::RepromptRequired => RpcError::RepromptRequired,
        BwError::TwoFactorRequired(challenge) => RpcError::TwoFactorRequired {
            providers: challenge.providers().to_vec(),
        },
        other => RpcError::Message(other.to_string()),
    }
}

/// First stdin line of a popup started by the daemon; see show_popup_with_command.
fn read_popup_token() -> String {
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return String::new();
    }
    line.trim_end()
        .strip_prefix(POPUP_TOKEN_PREFIX)
        .unwrap_or_default()
        .to_string()
}

fn popup_rpc_socket_arg() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--rpc-socket" {
            return args.next().map(PathBuf::from);
        }
    }
    None
}

fn show_popup(popup: &PopupChild, rpc_socket: Option<&RpcEndpoint>) {
    show_popup_with_command(popup, rpc_socket, "show\n", "show\n");
}

fn show_approval_popup(popup: &PopupChild, rpc_socket: Option<&RpcEndpoint>) {
    show_popup_with_command(
        popup,
        rpc_socket,
        "ssh-approval return\n",
        "ssh-approval auto\n",
    );
}

fn show_unlock_popup(popup: &PopupChild, rpc_socket: Option<&RpcEndpoint>) {
    show_popup_with_command(popup, rpc_socket, "unlock ssh\n", "unlock ssh\n");
}

fn show_popup_with_command(
    popup: &PopupChild,
    rpc_socket: Option<&RpcEndpoint>,
    existing_command: &str,
    new_command: &str,
) {
    show_client(popup, rpc_socket, POPUP_FLAG, existing_command, new_command);
}

fn show_window(window: &PopupChild, rpc_socket: Option<&RpcEndpoint>) {
    show_client(window, rpc_socket, WINDOW_FLAG, "show\n", "show\n");
}

/// Closes the vault window when it is open, opens it otherwise.
fn toggle_window(window: &PopupChild, rpc_socket: Option<&RpcEndpoint>) {
    let running = window.lock().is_ok_and(|mut slot| {
        slot.as_mut()
            .is_some_and(|process| matches!(process.child.try_wait(), Ok(None)))
    });
    if running {
        hide_popup(window);
    } else {
        show_window(window, rpc_socket);
    }
}

/// Starts a client process (`--popup` or the vault window) or sends a command to the
/// running one.
fn show_client(
    popup: &PopupChild,
    rpc_socket: Option<&RpcEndpoint>,
    flag: &str,
    existing_command: &str,
    new_command: &str,
) {
    let Ok(mut child_slot) = popup.lock() else {
        return;
    };

    if let Some(process) = child_slot.as_mut() {
        match process.child.try_wait() {
            Ok(Some(_)) => {
                *child_slot = None;
            }
            Ok(None) => match send_popup_command(process, existing_command) {
                Ok(()) => return,
                Err(e) => {
                    debug_log(&format!("discarding stale popup process: {e}"));
                    let _ = process.child.kill();
                    let _ = process.child.wait();
                    *child_slot = None;
                }
            },
            Err(_) => {
                *child_slot = None;
            }
        }
    }

    match popup_exe().and_then(|exe| {
        let mut command = Command::new(exe);
        command
            .arg(flag)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(rpc_socket) = rpc_socket {
            command.arg("--rpc-socket").arg(&rpc_socket.path);
        }
        command.spawn()
    }) {
        Ok(mut child) => {
            if let Some(stdin) = child.stdin.take() {
                let mut process = PopupProcess { child, stdin };
                // The token must be the first stdin line: run_popup reads it before
                // anything else touches the RPC socket.
                let token_line = rpc_socket
                    .map(|endpoint| format!("{POPUP_TOKEN_PREFIX}{}\n", endpoint.token))
                    .unwrap_or_default();
                match send_popup_command(&mut process, &token_line)
                    .and_then(|()| send_popup_command(&mut process, new_command))
                {
                    Ok(()) => {
                        *child_slot = Some(process);
                    }
                    Err(e) => {
                        let _ = process.child.kill();
                        let _ = process.child.wait();
                        eprintln!("could not send popup command: {e}");
                    }
                }
            } else {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("could not start popup: child stdin unavailable");
            }
        }
        Err(e) => {
            eprintln!("could not start popup: {e}");
        }
    }
}

/// Binary to spawn the popup from. After the installed binary is replaced (for example
/// by `make install`), `current_exe()` resolves to "<path> (deleted)" and spawning it
/// fails with ENOENT. `/proc/self/exe` still opens the running daemon's own binary, which
/// also keeps the popup on the same RPC protocol version as the daemon.
fn popup_exe() -> std::io::Result<PathBuf> {
    let proc_exe = PathBuf::from("/proc/self/exe");
    if proc_exe.exists() {
        return Ok(proc_exe);
    }
    std::env::current_exe()
}

fn hide_popup(popup: &PopupChild) {
    let Ok(mut child_slot) = popup.lock() else {
        return;
    };

    if let Some(process) = child_slot.as_mut() {
        match process.child.try_wait() {
            Ok(Some(_)) => {
                *child_slot = None;
            }
            Ok(None) => {
                let _ = send_popup_command(process, "hide\n");
            }
            Err(_) => {
                *child_slot = None;
            }
        }
    }
}

fn toggle_popup(popup: &PopupChild, rpc_socket: Option<&RpcEndpoint>) {
    let Ok(mut child_slot) = popup.lock() else {
        return;
    };

    let handled_existing = match child_slot.as_mut() {
        Some(process) => match process.child.try_wait() {
            Ok(Some(_)) | Err(_) => {
                *child_slot = None;
                false
            }
            Ok(None) => {
                let _ = send_popup_command(process, "hide\n");
                true
            }
        },
        None => false,
    };
    drop(child_slot);

    if !handled_existing {
        show_popup(popup, rpc_socket);
    }
}

fn quit_popup(popup: &PopupChild) {
    let Ok(mut child_slot) = popup.lock() else {
        return;
    };

    if let Some(process) = child_slot.as_mut() {
        let _ = process.stdin.write_all(b"quit\n");
        let _ = process.stdin.flush();
        match process.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = process.child.kill();
                let _ = process.child.wait();
            }
            Err(_) => {}
        }
    }
    *child_slot = None;
}

fn notify_clients(state: &VaultState, command: &str) {
    notify_popup(&state.popup, command);
    notify_popup(&state.window, command);
}

fn notify_popup(popup: &PopupChild, command: &str) {
    if let Ok(mut slot) = popup.lock() {
        if let Some(process) = slot.as_mut() {
            let _ = send_popup_command(process, command);
        }
    }
}

fn send_popup_command(process: &mut PopupProcess, command: &str) -> std::io::Result<()> {
    process.stdin.write_all(command.as_bytes())?;
    process.stdin.flush()
}

fn start_popup_stdin_listener(tx: mpsc::Sender<PopupCommand>) {
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        loop {
            line.clear();
            match stdin.read_line(&mut line) {
                Ok(0) | Err(_) => {
                    if popup_rpc_socket_arg().is_some() {
                        let _ = tx.send(PopupCommand::VaultLocked);
                    }
                    break;
                }
                Ok(_) => {
                    let command = match line.trim() {
                        "vault-locked" => Some(PopupCommand::VaultLocked),
                        "lock-warning" => Some(PopupCommand::LockWarning),
                        "show" => Some(PopupCommand::Show),
                        "hide" => Some(PopupCommand::Hide),
                        "toggle" => Some(PopupCommand::Toggle),
                        "ssh-approval auto" => Some(PopupCommand::SshApproval { auto_hide: true }),
                        "ssh-approval return" => {
                            Some(PopupCommand::SshApproval { auto_hide: false })
                        }
                        "browser-approval auto" => {
                            Some(PopupCommand::BrowserApproval { auto_hide: true })
                        }
                        "browser-approval return" => {
                            Some(PopupCommand::BrowserApproval { auto_hide: false })
                        }
                        "unlock auto" => Some(PopupCommand::Unlock {
                            auto_hide: true,
                            inhibit_focus_hide: true,
                        }),
                        "unlock return" => Some(PopupCommand::Unlock {
                            auto_hide: false,
                            inhibit_focus_hide: false,
                        }),
                        "unlock ssh" => Some(PopupCommand::Unlock {
                            auto_hide: false,
                            inhibit_focus_hide: true,
                        }),
                        "quit" => Some(PopupCommand::Quit),
                        _ => None,
                    };
                    if let Some(command) = command {
                        let _ = tx.send(command);
                    }
                }
            }
        }
    });
}

fn popup_options() -> eframe::NativeOptions {
    #[allow(unused_mut)]
    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(ui::widgets::WINDOW_SIZE)
            .with_min_inner_size(ui::widgets::WINDOW_SIZE)
            .with_max_inner_size(ui::widgets::WINDOW_SIZE)
            .with_title("boltwarden")
            // Wayland app_id / X11 class, so compositor window rules can match the popup.
            // Demo mode shows no real secrets, so it gets its own id and escapes rules
            // such as no_screen_share (handy for screenshots).
            .with_app_id(if demo::enabled() {
                "boltwarden-demo"
            } else {
                "boltwarden"
            })
            .with_decorations(false)
            .with_resizable(false)
            .with_always_on_top()
            .with_active(true),
        run_and_return: true,
        ..platform::native_options()
    };
    #[cfg(target_os = "macos")]
    platform::macos::accessory_app(&mut options);
    options
}

fn debug_log(message: &str) {
    if std::env::var_os("BOLTWARDEN_DEBUG").is_some() {
        eprintln!("[boltwarden] {message}");
    }
}

/// Browser-launched stdio entry point. Never write diagnostics to stdout.
pub fn native_host_main() -> std::io::Result<()> {
    browser::native_host::run_native_host()
}

#[cfg(test)]
mod tests {
    use super::*;
    use browser::install::{BrowserFamily, BrowserRegistration};

    fn row(id: &str, registered: bool) -> BrowserRegistration {
        BrowserRegistration {
            id: id.into(),
            label: id.into(),
            executable: PathBuf::from(format!("/apps/{id}")),
            family: BrowserFamily::Chromium,
            native_host_dir: PathBuf::from(format!("/hosts/{id}")),
            registered,
        }
    }

    #[test]
    fn enabling_registers_unregistered_browsers_once() {
        let mut preferences = config::BrowserSetupPreferences::default();
        let mut registered = Vec::new();
        let errors = auto_register_browsers(
            &mut preferences,
            vec![row("chrome", false), row("firefox", true)],
            |row| {
                registered.push(row.id);
                Ok(())
            },
        );
        assert!(errors.is_empty());
        assert_eq!(registered, ["chrome"]);
        assert!(preferences.configured);
        let errors = auto_register_browsers(&mut preferences, vec![row("vivaldi", false)], |_| {
            panic!("a configured setup must not be changed")
        });
        assert!(errors.is_empty());
    }

    #[test]
    fn failed_registration_is_reported_and_retried() {
        let mut preferences = config::BrowserSetupPreferences::default();
        let errors = auto_register_browsers(
            &mut preferences,
            vec![row("chrome", false), row("vivaldi", false)],
            |row| {
                if row.id == "chrome" {
                    Err("read-only folder".into())
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(errors, ["chrome: read-only folder"]);
        assert!(!preferences.configured, "the next start should try again");
    }
}
