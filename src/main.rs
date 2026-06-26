mod backend;
mod app;
mod bw;
mod clipboard;
mod config;
mod instance;
mod model;
mod rpc;
mod ssh_agent;
mod tray;
mod ui;

use app::{App, PopupCommand};
use backend::AppBackend;
use bw::{BwClient, BwError, TwoFactorChallenge};
use eframe::egui;
use instance::LaunchCommand;
use model::SshAgentStatus;
use rpc::{RpcError, RpcRequest, RpcResponse, SearchPayload};
use ssh_agent::{SshAgentHandle, SshApprovalService};
use ui::search::{search_window_height, SEARCH_WIDTH};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use tray::TrayCommand;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonCommand {
    Show,
    Hide,
    Toggle,
    Quit,
}

struct PopupProcess {
    child: Child,
    stdin: ChildStdin,
}

type PopupChild = Arc<Mutex<Option<PopupProcess>>>;

struct VaultState {
    bw: BwClient,
    pending_two_factor: Option<TwoFactorChallenge>,
    ssh_agent: Option<SshAgentHandle>,
    ssh_agent_status: SshAgentStatus,
    ssh_approvals: SshApprovalService,
}

fn main() -> eframe::Result<()> {
    if std::env::args().any(|arg| arg == "--popup") {
        return run_popup();
    }

    let launch_command = LaunchCommand::from_args(std::env::args().skip(1));
    let show_on_start = launch_command != LaunchCommand::Daemon;
    let listener = match instance::prepare(launch_command) {
        instance::Instance::ActivatedExisting => return Ok(()),
        instance::Instance::Primary(listener) => listener,
    };

    run_daemon(listener, show_on_start)
}

fn run_daemon(listener: Option<UnixListener>, show_on_start: bool) -> eframe::Result<()> {
    let (tx, rx) = mpsc::channel();
    let (approval_show_tx, approval_show_rx) = mpsc::channel();
    let popup = Arc::new(Mutex::new(None));
    let ssh_approvals = SshApprovalService::new(approval_show_tx);
    let vault = Arc::new(Mutex::new(VaultState {
        bw: BwClient::new(),
        pending_two_factor: None,
        ssh_agent: None,
        ssh_agent_status: ssh_agent::disabled_status(),
        ssh_approvals: ssh_approvals.clone(),
    }));
    let rpc_socket = start_vault_rpc_listener(vault.clone(), ssh_approvals.clone());

    start_tray(tx.clone());
    start_activation_listener(listener, tx.clone());
    start_approval_popup_listener(approval_show_rx, popup.clone(), rpc_socket.clone());
    let _daemon_tx_keepalive = tx;

    if show_on_start {
        show_popup(&popup, rpc_socket.as_deref());
    }
    while let Ok(command) = rx.recv() {
        match command {
            DaemonCommand::Show => show_popup(&popup, rpc_socket.as_deref()),
            DaemonCommand::Hide => hide_popup(&popup),
            DaemonCommand::Toggle => toggle_popup(&popup, rpc_socket.as_deref()),
            DaemonCommand::Quit => {
                quit_popup(&popup);
                if let Ok(mut state) = vault.lock() {
                    stop_ssh_agent(&mut state);
                    state.ssh_approvals.clear_all("daemon quit");
                }
                break;
            }
        }
    }

    Ok(())
}

fn run_popup() -> eframe::Result<()> {
    debug_log("starting popup");
    let (popup_tx, popup_rx) = mpsc::channel();
    start_popup_stdin_listener(popup_tx);

    let backend = popup_rpc_socket_arg()
        .map(|path| AppBackend::remote(rpc::RpcClient::new(path)))
        .unwrap_or_else(AppBackend::local);
    let starts_in_search = backend.has_session();
    let result = eframe::run_native(
        "bw-quick-access",
        popup_options(starts_in_search),
        Box::new(|_cc| Ok(Box::new(App::new(backend, popup_rx)))),
    );
    debug_log("popup event loop exited");
    result
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
            if (&stream).read_to_string(&mut message).is_err() {
                continue;
            }
            let command = match LaunchCommand::parse(&message) {
                LaunchCommand::Show => DaemonCommand::Show,
                LaunchCommand::Toggle => DaemonCommand::Toggle,
                LaunchCommand::Daemon => continue,
            };
            let _ = tx.send(command);
        }
    });
}

fn start_approval_popup_listener(
    rx: mpsc::Receiver<()>,
    popup: PopupChild,
    rpc_socket: Option<PathBuf>,
) {
    std::thread::spawn(move || {
        while rx.recv().is_ok() {
            show_approval_popup(&popup, rpc_socket.as_deref());
        }
    });
}

fn start_vault_rpc_listener(
    vault: Arc<Mutex<VaultState>>,
    ssh_approvals: SshApprovalService,
) -> Option<PathBuf> {
    match rpc::prepare_listener() {
        Ok((path, listener)) => {
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let vault = vault.clone();
                    let ssh_approvals = ssh_approvals.clone();
                    std::thread::spawn(move || handle_rpc_stream(stream, vault, ssh_approvals));
                }
            });
            Some(path)
        }
        Err(e) => {
            eprintln!("could not start vault RPC socket: {e}");
            None
        }
    }
}

fn handle_rpc_stream(
    mut stream: UnixStream,
    vault: Arc<Mutex<VaultState>>,
    ssh_approvals: SshApprovalService,
) {
    let mut request_body = String::new();
    let response = if stream.read_to_string(&mut request_body).is_err() {
        RpcResponse::ClearSavedSession(Err("could not read daemon request".into()))
    } else {
        match serde_json::from_str::<RpcRequest>(&request_body) {
            Ok(request) => handle_rpc_request(request, &vault, &ssh_approvals),
            Err(e) => RpcResponse::ClearSavedSession(Err(format!(
                "could not decode daemon request: {e}"
            ))),
        }
    };

    if let Ok(payload) = serde_json::to_vec(&response) {
        let _ = stream.write_all(&payload);
    }
}

fn handle_rpc_request(
    request: RpcRequest,
    vault: &Arc<Mutex<VaultState>>,
    ssh_approvals: &SshApprovalService,
) -> RpcResponse {
    match request {
        RpcRequest::GetSshApproval => return RpcResponse::SshApproval(ssh_approvals.active_request()),
        RpcRequest::DecideSshApproval(decision) => {
            return RpcResponse::SshApprovalDecided(ssh_approvals.decide(decision));
        }
        RpcRequest::GetSshApprovalStatus => {
            return RpcResponse::SshApprovalStatus(ssh_approvals.recent_status());
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

    match request {
        RpcRequest::HasSession => RpcResponse::HasSession(state.bw.has_session()),
        RpcRequest::Login {
            server_url,
            email,
            password,
            remember,
        } => RpcResponse::Login(login_vault(
            &mut state,
            &server_url,
            &email,
            &password,
            remember,
        )),
        RpcRequest::CompleteTwoFactor {
            provider,
            token,
            remember,
        } => RpcResponse::TwoFactor(complete_vault_two_factor(
            &mut state, provider, &token, remember,
        )),
        RpcRequest::ListItems { query } => {
            let result = state.bw.list_items(&query).map(|items| SearchPayload {
                items,
                warning: state.bw.sync_warning(),
                status: state.bw.sync_status(),
            });
            RpcResponse::Search(result.map_err(rpc_error_from_bw))
        }
        RpcRequest::GetItem { id } => {
            RpcResponse::Detail(state.bw.get_item(&id).map_err(rpc_error_from_bw))
        }
        RpcRequest::GetTotp { id } => {
            RpcResponse::Totp(state.bw.get_totp(&id).map_err(rpc_error_from_bw))
        }
        RpcRequest::ApplySettings(settings) => {
            let result = config::save_settings(&settings)
                .map_err(|e| e.to_string())
                .map(|_| apply_ssh_agent_settings(&mut state));
            RpcResponse::SettingsApplied(result)
        }
        RpcRequest::GetSshAgentStatus => {
            let status = apply_ssh_agent_settings(&mut state);
            RpcResponse::SshAgentStatus(status)
        }
        RpcRequest::LockVault => {
            state.bw = BwClient::new();
            state.pending_two_factor = None;
            stop_ssh_agent(&mut state);
            state.ssh_approvals.clear_all("vault locked");
            let _ = config::clear_recent_item();
            RpcResponse::LockVault(Ok(()))
        }
        RpcRequest::ClearSavedSession => {
            let result = config::clear_saved_session().map_err(|e| e.to_string());
            if result.is_ok() {
                state.bw = BwClient::new();
                state.pending_two_factor = None;
                stop_ssh_agent(&mut state);
                state.ssh_approvals.clear_all("saved session cleared");
                let _ = config::clear_recent_item();
            }
            RpcResponse::ClearSavedSession(result)
        }
        RpcRequest::GetSshApproval
        | RpcRequest::DecideSshApproval(_)
        | RpcRequest::GetSshApprovalStatus => unreachable!("SSH approval RPC bypasses vault lock"),
    }
}

fn login_vault(
    state: &mut VaultState,
    server_url: &str,
    email: &str,
    password: &str,
    remember: bool,
) -> Result<(), RpcError> {
    let saved = config::load_saved_session();
    let result = if let Some(saved) = saved.filter(|saved| {
        saved.server_url.trim_end_matches('/') == server_url.trim_end_matches('/')
            && saved.email.eq_ignore_ascii_case(email.trim())
    }) {
        state.bw.unlock_saved_session(&saved, password)
    } else {
        state.bw.login(server_url, email, password, remember)
    };

    match result {
        Ok(()) => {
            state.pending_two_factor = None;
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
    match state
        .bw
        .complete_two_factor(&challenge, provider, token, remember)
    {
        Ok(()) => {
            state.pending_two_factor = None;
            apply_ssh_agent_settings(state);
            Ok(())
        }
        Err(e) => Err(rpc_error_from_bw(e)),
    }
}

fn apply_ssh_agent_settings(state: &mut VaultState) -> SshAgentStatus {
    let settings = config::load_settings();
    if !settings.ssh_agent_enabled {
        stop_ssh_agent(state);
        state.ssh_approvals.clear_all("SSH agent disabled");
        state.ssh_agent_status = ssh_agent::disabled_status();
        return state.ssh_agent_status.clone();
    }

    if !state.bw.has_session() {
        stop_ssh_agent(state);
        state.ssh_approvals.clear_all("waiting for vault unlock");
        state.ssh_agent_status = ssh_agent::waiting_for_unlock_status(&settings);
        return state.ssh_agent_status.clone();
    }

    let desired_path = match config::expand_ssh_agent_socket_path(&settings.ssh_agent_socket_path) {
        Ok(path) => path,
        Err(e) => {
            stop_ssh_agent(state);
            state.ssh_approvals.clear_all("invalid SSH agent socket path");
            state.ssh_agent_status = ssh_agent::error_status(&settings, e);
            return state.ssh_agent_status.clone();
        }
    };

    if state
        .ssh_agent
        .as_ref()
        .is_some_and(|agent| agent.path() == desired_path)
    {
        state.ssh_agent_status = state
            .ssh_agent
            .as_ref()
            .map(|agent| agent.status())
            .unwrap_or_else(ssh_agent::disabled_status);
        return state.ssh_agent_status.clone();
    }

    stop_ssh_agent(state);
    match state.bw.ssh_keys() {
        Ok(keys) => match ssh_agent::start(&settings, &keys, state.ssh_approvals.clone()) {
            Ok(agent) => {
                state.ssh_agent_status = agent.status();
                state.ssh_agent = Some(agent);
            }
            Err(e) => {
                state.ssh_agent_status = ssh_agent::error_status(&settings, e);
            }
        },
        Err(e) => {
            state.ssh_agent_status = ssh_agent::error_status(&settings, e.to_string());
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

fn rpc_error_from_bw(error: BwError) -> RpcError {
    match error {
        BwError::TwoFactorRequired(challenge) => RpcError::TwoFactorRequired {
            providers: challenge.providers().to_vec(),
        },
        other => RpcError::Message(other.to_string()),
    }
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

fn show_popup(popup: &PopupChild, rpc_socket: Option<&Path>) {
    show_popup_with_command(popup, rpc_socket, "show\n", "show\n");
}

fn show_approval_popup(popup: &PopupChild, rpc_socket: Option<&Path>) {
    show_popup_with_command(popup, rpc_socket, "ssh-approval return\n", "ssh-approval auto\n");
}

fn show_popup_with_command(
    popup: &PopupChild,
    rpc_socket: Option<&Path>,
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
            Ok(None) => {
                send_popup_command(process, existing_command);
                return;
            }
            Err(_) => {
                *child_slot = None;
            }
        }
    }

    match std::env::current_exe().and_then(|exe| {
        let mut command = Command::new(exe);
        command
            .arg("--popup")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(rpc_socket) = rpc_socket {
            command.arg("--rpc-socket").arg(rpc_socket);
        }
        command.spawn()
    }) {
        Ok(mut child) => {
            if let Some(stdin) = child.stdin.take() {
                let mut process = PopupProcess { child, stdin };
                send_popup_command(&mut process, new_command);
                *child_slot = Some(process);
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
                send_popup_command(process, "hide\n");
                wait_or_kill_popup(process);
                *child_slot = None;
            }
            Err(_) => {
                *child_slot = None;
            }
        }
    }
}

fn toggle_popup(popup: &PopupChild, rpc_socket: Option<&Path>) {
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
                send_popup_command(process, "hide\n");
                wait_or_kill_popup(process);
                *child_slot = None;
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

fn send_popup_command(process: &mut PopupProcess, command: &str) {
    let _ = process.stdin.write_all(command.as_bytes());
    let _ = process.stdin.flush();
}

fn wait_or_kill_popup(process: &mut PopupProcess) {
    for _ in 0..20 {
        match process.child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(25)),
            Err(_) => return,
        }
    }
    let _ = process.child.kill();
    let _ = process.child.wait();
}

fn start_popup_stdin_listener(tx: mpsc::Sender<PopupCommand>) {
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        loop {
            line.clear();
            match stdin.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let command = match line.trim() {
                        "show" => Some(PopupCommand::Show),
                        "hide" => Some(PopupCommand::Hide),
                        "toggle" => Some(PopupCommand::Toggle),
                        "ssh-approval auto" => Some(PopupCommand::SshApproval { auto_hide: true }),
                        "ssh-approval return" => {
                            Some(PopupCommand::SshApproval { auto_hide: false })
                        }
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

fn popup_options(starts_in_search: bool) -> eframe::NativeOptions {
    let settings = config::load_settings();
    let initial_size = if starts_in_search {
        [
            SEARCH_WIDTH,
            search_window_height(settings.show_keyboard_shortcuts),
        ]
    } else {
        [SEARCH_WIDTH, 540.0]
    };

    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(initial_size)
            .with_min_inner_size([620.0, 72.0])
            .with_title("bw-quick-access")
            .with_decorations(false)
            .with_resizable(false)
            .with_transparent(true)
            .with_clamp_size_to_monitor_size(true)
            .with_always_on_top()
            .with_active(true),
        run_and_return: true,
        ..Default::default()
    }
}

fn debug_log(message: &str) {
    if std::env::var_os("BWQA_DEBUG").is_some() {
        eprintln!("[bw-quick-access] {message}");
    }
}
