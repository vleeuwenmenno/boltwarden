//! Vault policy for the browser transport; no browser operation uses desktop grants.
use crate::browser::{
    BrowserHandler, BrowserRequest, BrowserResponse, FillInteraction, MatchSummary, PairingRequest,
    RequestContext,
};
use crate::browser_approval::{BrowserApprovalChoice, BrowserApprovalRequest};
use crate::{VaultState, interaction, uri_match};
use std::sync::{Mutex, Weak, mpsc};

pub struct DaemonBrowserBackend {
    pub vault: Weak<Mutex<VaultState>>,
    pub unlock: mpsc::Sender<()>,
}

fn error(code: &str) -> BrowserResponse {
    let message = match code {
        "Locked" => "Unlock Boltwarden from the desktop to continue.",
        "Disabled" => "Enable browser integration in Boltwarden settings.",
        "Busy" => "Another desktop approval is open. Finish it and try again.",
        "StaleRequest" => "The page or vault item changed. Try filling again.",
        "ConfirmationRequired" => {
            "Select this login in the extension popup and confirm its destination."
        }
        "RepromptRequired" => {
            "Select this login in the extension popup to verify your master password."
        }
        "NoMatch" => "This login does not match the destination page.",
        "Cancelled" => "The browser request was cancelled.",
        _ => "The browser request could not be completed.",
    };
    BrowserResponse::error(code, message)
}

fn map_error(e: crate::bw::BwError) -> BrowserResponse {
    match e {
        crate::bw::BwError::NotUnlocked => error("Locked"),
        crate::bw::BwError::RepromptRequired => error("RepromptRequired"),
        crate::bw::BwError::NotFound => error("NoMatch"),
        other => BrowserResponse::error("StaleRequest", other.to_string()),
    }
}

fn context(top: &str, frame: &str, document: &str) -> Option<bool> {
    if document.is_empty() || document.len() > 256 {
        return None;
    }
    let top = uri_match::page_url(top)?;
    let frame = uri_match::page_url(frame)?;
    Some(top.origin() != frame.origin())
}

fn sync_browser_vault(state: &mut VaultState) {
    let was_unlocked = state.bw.has_session();
    state.bw.sync_if_stale();
    // A rejected refresh token can revoke an online or offline session. Browser
    // requests bypass the desktop RPC wrapper, so run the same daemon cleanup.
    if was_unlocked && !state.bw.has_session() {
        crate::lock_vault_state(state, "session revoked");
    }
}

fn passkey_requires_password(state: &VaultState, site_requires_verification: bool) -> bool {
    use crate::config::PasskeyVerification;
    match state.passkey_verification {
        PasskeyVerification::Always => true,
        PasskeyVerification::WhenRequired => site_requires_verification,
        PasskeyVerification::VaultUnlock => !state.bw.has_verified_unlock(),
    }
}

fn passkey_verification(
    state: &VaultState,
    policy: crate::config::PasskeyVerification,
    password_verified: bool,
) -> Option<crate::bw::PasskeyVerificationEvidence> {
    use crate::bw::PasskeyVerificationEvidence;
    use crate::config::PasskeyVerification;
    if state.passkey_verification != policy {
        return None;
    }
    // The immutable prompt and selected choice determine whether the RPC checked
    // a fresh password. Merely typing one into an optional prompt is not evidence.
    if password_verified {
        return Some(PasskeyVerificationEvidence::FreshPassword);
    }
    match policy {
        PasskeyVerification::VaultUnlock if state.bw.has_verified_unlock() => {
            Some(PasskeyVerificationEvidence::VaultUnlock)
        }
        PasskeyVerification::WhenRequired => Some(PasskeyVerificationEvidence::None),
        _ => None,
    }
}

/// Process metadata helps identify an unexpected pairing prompt, but only the
/// approved public key authenticates the extension profile.
#[cfg(windows)]
fn browser_process_description(host_pid: u32) -> String {
    crate::platform::windows::browser_description(host_pid)
}

#[cfg(target_os = "macos")]
fn browser_process_description(host_pid: u32) -> String {
    use crate::platform::process;
    if let Some(pid) = process::ppid(host_pid)
        && let Some(executable) = process::executable(pid)
    {
        return format!("Browser process: {executable} (PID {pid})");
    }
    format!("Native host PID: {host_pid}")
}

#[cfg(target_os = "linux")]
fn browser_process_description(host_pid: u32) -> String {
    let parent = std::fs::read_to_string(format!("/proc/{host_pid}/status"))
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("PPid:")
                    .and_then(|value| value.trim().parse::<u32>().ok())
            })
        });
    if let Some(pid) = parent
        && let Ok(executable) = std::fs::read_link(format!("/proc/{pid}/exe"))
    {
        return format!("Browser process: {} (PID {pid})", executable.display());
    }
    format!("Native host PID: {host_pid}")
}

fn write_choices(targets: &[crate::bw::BrowserMatchSummary]) -> Vec<BrowserApprovalChoice> {
    std::iter::once(BrowserApprovalChoice {
        id: uuid::Uuid::new_v4().to_string(),
        label: "Create new login".into(),
        description: "Personal vault".into(),
        requires_password: false,
    })
    .chain(targets.iter().map(|target| BrowserApprovalChoice {
        id: uuid::Uuid::new_v4().to_string(),
        label: target.name.clone(),
        description: target.username.clone().unwrap_or_default(),
        requires_password: target.reprompt,
    }))
    .collect()
}

impl BrowserHandler for DaemonBrowserBackend {
    fn handle(&self, ctx: &RequestContext, request: BrowserRequest) -> BrowserResponse {
        if ctx.is_cancelled() {
            return error("Cancelled");
        }
        let request = match request {
            BrowserRequest::SaveLogin {
                top_url,
                frame_url,
                document_id,
                login,
            } => {
                return self.save_login(ctx, top_url, frame_url, document_id, login);
            }
            BrowserRequest::PasskeyGet {
                top_url,
                frame_url,
                document_id,
                options,
            } => {
                return self.passkey_get(ctx, top_url, frame_url, document_id, options);
            }
            BrowserRequest::PasskeyCreate {
                top_url,
                frame_url,
                document_id,
                options,
            } => {
                return self.passkey_create(ctx, top_url, frame_url, document_id, options);
            }
            request => request,
        };
        let card = matches!(
            request,
            BrowserRequest::ListCards { .. } | BrowserRequest::FillCard { .. }
        );
        let totp = matches!(
            request,
            BrowserRequest::ListTotpMatches { .. } | BrowserRequest::FillTotp { .. }
        );
        let Some(vault) = self.vault.upgrade() else {
            return error("DaemonUnavailable");
        };
        let Ok(mut state) = vault.lock() else {
            return error("DaemonUnavailable");
        };
        if !state.browser_enabled {
            return error("Disabled");
        }
        match request {
            BrowserRequest::Status => BrowserResponse::Status {
                enabled: true,
                unlocked: state.bw.has_session(),
                epoch: state.browser_epoch,
            },
            BrowserRequest::RequestUnlock => {
                if !state.bw.has_session() {
                    let needs_prompt = state
                        .browser_unlock
                        .as_ref()
                        .is_none_or(|lease| lease.expired());
                    if needs_prompt {
                        let Ok(lease) = interaction::global().acquire(interaction::Kind::Unlock)
                        else {
                            return error("Busy");
                        };
                        let shared = lease.shared();
                        state.browser_unlock = Some(lease);
                        if !shared && self.unlock.send(()).is_err() {
                            state.browser_unlock = None;
                            return error("DaemonUnavailable");
                        }
                    }
                }
                BrowserResponse::UnlockRequested
            }
            BrowserRequest::ListMatches {
                top_url,
                frame_url,
                document_id,
                offset,
            }
            | BrowserRequest::ListCards {
                top_url,
                frame_url,
                document_id,
                offset,
            }
            | BrowserRequest::ListTotpMatches {
                top_url,
                frame_url,
                document_id,
                offset,
            } => {
                let Some(_) = context(&top_url, &frame_url, &document_id) else {
                    return error("InvalidContext");
                };
                if card && (!top_url.starts_with("https://") || !frame_url.starts_with("https://"))
                {
                    return error("InvalidContext");
                }
                sync_browser_vault(&mut state);
                match if card {
                    state.bw.browser_cards()
                } else if totp {
                    state
                        .bw
                        .browser_totp_matches(&frame_url, state.browser_default_match)
                } else {
                    state
                        .bw
                        .browser_matches(&frame_url, state.browser_default_match)
                } {
                    Ok(items) => {
                        if ctx.is_cancelled() {
                            return error("Cancelled");
                        }
                        let end = offset.saturating_add(50).min(items.len());
                        let next_offset = (end < items.len()).then_some(end);
                        BrowserResponse::Matches {
                            items: items
                                .into_iter()
                                .skip(offset)
                                .take(50)
                                .map(|item| MatchSummary {
                                    id: item.id,
                                    name: item.name,
                                    username: item.username,
                                    revision: item.revision,
                                    reprompt: item.reprompt,
                                    requires_confirmation: item.insecure_downgrade,
                                })
                                .collect(),
                            epoch: state.browser_epoch,
                            next_offset,
                            warning: state.bw.sync_warning(),
                        }
                    }
                    Err(e) => map_error(e),
                }
            }
            BrowserRequest::FillLogin {
                item_id,
                revision,
                top_url,
                frame_url,
                document_id,
                interaction,
                confirm_insecure,
                confirm_cross_origin,
            }
            | BrowserRequest::FillCard {
                item_id,
                revision,
                top_url,
                frame_url,
                document_id,
                interaction,
                confirm_insecure,
                confirm_cross_origin,
            }
            | BrowserRequest::FillTotp {
                item_id,
                revision,
                top_url,
                frame_url,
                document_id,
                interaction,
                confirm_insecure,
                confirm_cross_origin,
            } => {
                let Some(cross_origin) = context(&top_url, &frame_url, &document_id) else {
                    return error("InvalidContext");
                };
                if card && (!top_url.starts_with("https://") || !frame_url.starts_with("https://"))
                {
                    return error("InvalidContext");
                }
                sync_browser_vault(&mut state);
                let matches = match if card {
                    state.bw.browser_cards()
                } else if totp {
                    state
                        .bw
                        .browser_totp_matches(&frame_url, state.browser_default_match)
                } else {
                    state
                        .bw
                        .browser_matches(&frame_url, state.browser_default_match)
                } {
                    Ok(items) => items,
                    Err(e) => return map_error(e),
                };
                let Some(item) = matches.iter().find(|item| item.id == item_id) else {
                    return error("NoMatch");
                };
                if item.revision != revision {
                    return error("StaleRequest");
                }
                if cross_origin && (interaction != FillInteraction::Popup || !confirm_cross_origin)
                    || item.insecure_downgrade
                        && (interaction != FillInteraction::Popup || !confirm_insecure)
                {
                    return error("ConfirmationRequired");
                }
                if interaction == FillInteraction::Shortcut && (card || matches.len() != 1) {
                    return error("ConfirmationRequired");
                }
                if item.reprompt && interaction != FillInteraction::Popup {
                    return error("RepromptRequired");
                }
                let protected = item.reprompt;
                let epoch = state.browser_epoch;
                if protected {
                    let request = BrowserApprovalRequest {
                        id: String::new(),
                        title: if totp {
                            "Verify browser 2FA code"
                        } else {
                            "Verify browser fill"
                        }
                        .into(),
                        description: format!(
                            "Fill {} ({})\nDestination: {}\nTop-level page: {}",
                            item.name,
                            item.username.as_deref().unwrap_or("no username"),
                            frame_url,
                            top_url
                        ),
                        fingerprint: None,
                        requires_password: true,
                        choices: Vec::new(),
                        action_label: None,
                        allow_fallback: false,
                    };
                    let approvals = state.browser_approvals.clone();
                    drop(state);
                    if let Err(reason) = approvals.request(request, || ctx.is_cancelled()) {
                        return error(if reason == "Busy" {
                            "Busy"
                        } else {
                            "Cancelled"
                        });
                    }
                    state = match vault.lock() {
                        Ok(state) => state,
                        Err(_) => return error("DaemonUnavailable"),
                    };
                }
                if !state.browser_enabled || epoch != state.browser_epoch || ctx.is_cancelled() {
                    return error("StaleRequest");
                }
                if card {
                    return match state.bw.browser_card(&item_id, &revision, protected) {
                        Ok(card) if !ctx.is_cancelled() => BrowserResponse::Card {
                            card,
                            document_id,
                            epoch,
                        },
                        Ok(_) => error("Cancelled"),
                        Err(e) => map_error(e),
                    };
                }
                if totp {
                    return match state.bw.browser_totp(
                        &item_id,
                        &revision,
                        &frame_url,
                        state.browser_default_match,
                        protected,
                    ) {
                        Ok(code) if !ctx.is_cancelled() => BrowserResponse::Totp {
                            expires_at: code.step.saturating_add(1).saturating_mul(code.period),
                            code: code.code,
                            document_id,
                            epoch,
                        },
                        Ok(_) => error("Cancelled"),
                        Err(e) => map_error(e),
                    };
                }
                match state.bw.browser_credentials(
                    &item_id,
                    &revision,
                    &frame_url,
                    state.browser_default_match,
                    protected,
                ) {
                    Ok(mut credentials) => {
                        if ctx.is_cancelled() {
                            return error("Cancelled");
                        }
                        BrowserResponse::Credentials {
                            username: credentials.username.take().unwrap_or_default(),
                            password: credentials.password.take().unwrap_or_default(),
                            document_id,
                            epoch,
                        }
                    }
                    Err(e) => map_error(e),
                }
            }
            _ => error("InvalidRequest"),
        }
    }

    fn approve_pairing(
        &self,
        ctx: &RequestContext,
        pending: &PairingRequest,
    ) -> Result<(), String> {
        let vault = self.vault.upgrade().ok_or("DaemonUnavailable")?;
        let state = vault.lock().map_err(|_| "DaemonUnavailable")?;
        if !state.browser_enabled {
            return Err("Disabled".into());
        }
        if !state.bw.has_session() {
            return Err("Locked".into());
        }
        let epoch = state.browser_epoch;
        let approvals = state.browser_approvals.clone();
        drop(state);
        approvals.request(BrowserApprovalRequest {
            id: String::new(), title: "Pair browser with Boltwarden".into(),
            description: format!("{}\n{}\nPairing permits this browser profile to request vault logins while unlocked.", pending.label, browser_process_description(ctx.peer_pid)),
            fingerprint: Some(pending.fingerprint.clone()), requires_password: false,
            choices: Vec::new(), action_label: None, allow_fallback: false,
        }, || ctx.is_cancelled())?;
        let state = vault.lock().map_err(|_| "DaemonUnavailable")?;
        if ctx.is_cancelled()
            || !state.browser_enabled
            || !state.bw.has_session()
            || state.browser_epoch != epoch
        {
            return Err("Cancelled".into());
        }
        Ok(())
    }
}

fn passkey_error(code: &str, message: impl Into<String>) -> BrowserResponse {
    BrowserResponse::error(code, message)
}

fn passkey_approval_error(reason: &str) -> BrowserResponse {
    match reason {
        "Busy" => error("Busy"),
        "FallbackRequested" => passkey_error("FallbackRequested", "Use another authenticator."),
        _ => passkey_error(
            "NotAllowedError",
            "The passkey request was denied or expired.",
        ),
    }
}

fn passkey_unavailable(failure: crate::bw::BwError) -> BrowserResponse {
    match failure {
        crate::bw::BwError::NotUnlocked => error("Locked"),
        other => passkey_error("Unavailable", other.to_string()),
    }
}

impl DaemonBrowserBackend {
    fn passkey_get(
        &self,
        ctx: &RequestContext,
        top_url: String,
        frame_url: String,
        document_id: String,
        options: crate::passkeys::GetOptions,
    ) -> BrowserResponse {
        use crate::browser_approval::BrowserApprovalChoice;
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let started = std::time::Instant::now();
        if document_id.is_empty() || document_id.len() > 256 {
            return passkey_error("NotAllowedError", "The requesting document is invalid.");
        }
        let validated = match crate::passkeys::validate_get(&top_url, &frame_url, &options) {
            Ok(context) => context,
            Err(e) => return passkey_error(e.name, e.message),
        };
        let deadline = started + std::time::Duration::from_millis(validated.timeout_ms.min(60_000));
        let cancelled = || ctx.is_cancelled() || std::time::Instant::now() >= deadline;
        if cancelled() {
            return passkey_approval_error("Cancelled");
        }
        let Some(vault) = self.vault.upgrade() else {
            return error("DaemonUnavailable");
        };
        let Ok(mut state) = vault.lock() else {
            return error("DaemonUnavailable");
        };
        if !state.browser_enabled {
            return error("Disabled");
        }
        sync_browser_vault(&mut state);
        let allow_ids: Vec<Vec<u8>> = match options
            .allow_credentials
            .iter()
            .map(|descriptor| URL_SAFE_NO_PAD.decode(&descriptor.id))
            .collect()
        {
            Ok(ids) => ids,
            Err(_) => return passkey_error("NotAllowedError", "Invalid credential identifier."),
        };
        let candidates = match state
            .bw
            .browser_passkey_candidates(&validated.rp_id, &allow_ids)
        {
            Ok(candidates) => candidates,
            Err(e) => return passkey_unavailable(e),
        };
        if candidates.is_empty() {
            return passkey_error(
                "Unavailable",
                "No compatible passkey is available in Boltwarden.",
            );
        }
        if candidates.len() > 128 {
            return passkey_error(
                "Unavailable",
                "Too many matching passkeys. Use another authenticator.",
            );
        }
        // Choice identifiers are random and scoped to this prompt, not trusted vault IDs.
        let choices: Vec<_> = candidates
            .iter()
            .map(|candidate| BrowserApprovalChoice {
                id: uuid::Uuid::new_v4().to_string(),
                label: candidate
                    .user_display_name
                    .clone()
                    .or_else(|| candidate.user_name.clone())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| candidate.name.clone()),
                requires_password: candidate.requires_password,
                description: candidate
                    .user_name
                    .clone()
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| candidate.name.clone()),
            })
            .collect();
        let policy = state.passkey_verification;
        let requires_password =
            passkey_requires_password(&state, validated.requires_user_verification);
        let epoch = state.browser_epoch;
        let approvals = state.browser_approvals.clone();
        drop(state);
        let selected = match approvals.request(
            BrowserApprovalRequest {
                id: String::new(),
                title: "Sign in with a passkey".into(),
                description: format!(
                    "Website: {}\nPasskey for: {}",
                    validated.origin, validated.rp_id
                ),
                fingerprint: None,
                requires_password,
                choices: choices.clone(),
                action_label: Some("Sign in".into()),
                allow_fallback: true,
            },
            cancelled,
        ) {
            Ok(Some(id)) => id,
            Ok(None) => return passkey_approval_error("Cancelled"),
            Err(reason) => return passkey_approval_error(&reason),
        };
        let Some(index) = choices.iter().position(|choice| choice.id == selected) else {
            return passkey_approval_error("Cancelled");
        };
        let password_verified = requires_password || candidates[index].requires_password;
        let Ok(mut state) = vault.lock() else {
            return error("DaemonUnavailable");
        };
        if !state.browser_enabled || state.browser_epoch != epoch || cancelled() {
            return passkey_approval_error("Cancelled");
        }
        sync_browser_vault(&mut state);
        if !state.bw.has_session() || state.browser_epoch != epoch || cancelled() {
            return passkey_approval_error("Cancelled");
        }
        // Recheck reusable evidence after consent and sync, under the vault lock.
        let Some(verification) = passkey_verification(&state, policy, password_verified) else {
            return passkey_approval_error("Cancelled");
        };
        match state.bw.browser_passkey_assert(
            &candidates[index],
            &validated,
            &options,
            verification,
        ) {
            Ok(mut result) => {
                if cancelled() || state.browser_epoch != epoch {
                    return passkey_approval_error("Cancelled");
                }
                result.document_id = document_id;
                result.epoch = epoch;
                BrowserResponse::PasskeyResult { result }
            }
            Err(e) => passkey_error("NotAllowedError", e.to_string()),
        }
    }

    fn save_login(
        &self,
        ctx: &RequestContext,
        top_url: String,
        frame_url: String,
        document_id: String,
        login: crate::browser::protocol::CapturedLogin,
    ) -> BrowserResponse {
        if top_url != frame_url
            || context(&top_url, &frame_url, &document_id) != Some(false)
            || !frame_url.starts_with("https://")
            || login.password.is_empty()
            || login.password.len() > 4096
            || login.username.len() > 1024
        {
            return error("InvalidRequest");
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let cancelled = || ctx.is_cancelled() || std::time::Instant::now() >= deadline;
        let Some(vault) = self.vault.upgrade() else {
            return error("DaemonUnavailable");
        };
        let Ok(mut state) = vault.lock() else {
            return error("DaemonUnavailable");
        };
        if !state.browser_enabled {
            return error("Disabled");
        }
        sync_browser_vault(&mut state);
        let targets = match state
            .bw
            .browser_write_targets(&frame_url, state.browser_default_match)
        {
            Ok(targets) => targets,
            Err(e) => return passkey_unavailable(e),
        };
        if state
            .bw
            .browser_password_already_saved(&targets, &login.username, &login.password)
        {
            return BrowserResponse::LoginSaved { saved: false };
        }
        let choices = write_choices(&targets);
        let epoch = state.browser_epoch;
        let approvals = state.browser_approvals.clone();
        drop(state);
        let selected = match approvals.request(BrowserApprovalRequest {
            id: String::new(), title: "Save submitted password".into(),
            description: format!("Website: {}\nUsername: {}\nCreate a login or select an existing login to update its username and password. This does not confirm the website accepted them.",
                uri_match::page_url(&frame_url).unwrap().origin().ascii_serialization(), login.username),
            fingerprint: None, requires_password: false, choices: choices.clone(), action_label: Some("Save password".into()), allow_fallback: false,
        }, cancelled) { Ok(Some(id)) => id, _ => return error("Cancelled") };
        let Some(index) = choices.iter().position(|choice| choice.id == selected) else {
            return error("Cancelled");
        };
        let target = index.checked_sub(1).and_then(|index| targets.get(index));
        let Ok(mut state) = vault.lock() else {
            return error("DaemonUnavailable");
        };
        if !state.browser_enabled || state.browser_epoch != epoch || cancelled() {
            return error("Cancelled");
        }
        sync_browser_vault(&mut state);
        if state.browser_epoch != epoch || cancelled() {
            return error("Cancelled");
        }
        let result = state.bw.browser_save_password(
            &frame_url,
            &login.username,
            &login.password,
            target,
            target.is_some_and(|item| item.reprompt),
        );
        if !state.bw.has_session() {
            crate::lock_vault_state(&mut state, "session revoked");
            return error("Locked");
        }
        match result {
            Ok(()) => {
                crate::notify_browser_matches(&state);
                BrowserResponse::LoginSaved { saved: true }
            }
            Err(e) => BrowserResponse::error("SaveFailed", &e.to_string()),
        }
    }

    fn passkey_create(
        &self,
        ctx: &RequestContext,
        top_url: String,
        frame_url: String,
        document_id: String,
        options: crate::passkeys::CreateOptions,
    ) -> BrowserResponse {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let started = std::time::Instant::now();
        if document_id.is_empty() || document_id.len() > 256 {
            return passkey_error("NotAllowedError", "The requesting document is invalid.");
        }
        let validated = match crate::passkeys::validate_create(&top_url, &frame_url, &options) {
            Ok(context) => context,
            Err(e) => return passkey_error(e.name, e.message),
        };
        let deadline = started + std::time::Duration::from_millis(validated.timeout_ms.min(60_000));
        let cancelled = || ctx.is_cancelled() || std::time::Instant::now() >= deadline;
        if cancelled() {
            return passkey_approval_error("Cancelled");
        }
        let Some(vault) = self.vault.upgrade() else {
            return error("DaemonUnavailable");
        };
        let Ok(mut state) = vault.lock() else {
            return error("DaemonUnavailable");
        };
        if !state.browser_enabled {
            return error("Disabled");
        }
        sync_browser_vault(&mut state);
        if let Err(e) = state.bw.browser_passkey_can_create() {
            return passkey_unavailable(e);
        }
        let exclude_ids: Vec<Vec<u8>> = match options
            .exclude_credentials
            .iter()
            .map(|descriptor| URL_SAFE_NO_PAD.decode(&descriptor.id))
            .collect()
        {
            Ok(ids) => ids,
            Err(_) => return passkey_error("NotAllowedError", "Invalid credential identifier."),
        };
        let targets = match state
            .bw
            .browser_write_targets(&frame_url, state.browser_default_match)
        {
            Ok(targets) => targets,
            Err(e) => return passkey_unavailable(e),
        };
        let choices = write_choices(&targets);
        let policy = state.passkey_verification;
        let requires_password =
            passkey_requires_password(&state, validated.requires_user_verification);
        let epoch = state.browser_epoch;
        let approvals = state.browser_approvals.clone();
        drop(state);
        let selected = match approvals.request(BrowserApprovalRequest {
            id: String::new(), title: "Create a passkey".into(),
            description: format!("Website: {}\nPasskey for: {}\nAccount: {} ({})\nCreate a login or add this passkey to an existing login. Its password and other fields will be kept.",
                validated.origin, validated.rp_id, options.user.display_name, options.user.name),
            fingerprint: None, requires_password, choices: choices.clone(),
            action_label: Some("Create passkey".into()), allow_fallback: true,
        }, cancelled) { Ok(Some(id)) => id, Err(reason) => return passkey_approval_error(&reason), _ => return passkey_approval_error("Cancelled") };
        let Some(index) = choices.iter().position(|choice| choice.id == selected) else {
            return passkey_approval_error("Cancelled");
        };
        let target = index.checked_sub(1).and_then(|index| targets.get(index));
        let requires_password = requires_password || target.is_some_and(|target| target.reprompt);
        let Ok(mut state) = vault.lock() else {
            return error("DaemonUnavailable");
        };
        if !state.browser_enabled || state.browser_epoch != epoch || cancelled() {
            return passkey_approval_error("Cancelled");
        }
        sync_browser_vault(&mut state);
        if !state.bw.has_session() || state.browser_epoch != epoch || cancelled() {
            return passkey_approval_error("Cancelled");
        }
        let Some(verification) = passkey_verification(&state, policy, requires_password) else {
            return passkey_approval_error("Cancelled");
        };
        // Checking the exclusion list only after consent avoids a credential-existence oracle.
        match state
            .bw
            .browser_passkey_excluded(&validated.rp_id, &exclude_ids)
        {
            Ok(true) => {
                return passkey_error(
                    "InvalidStateError",
                    "A passkey for this account already exists.",
                );
            }
            Ok(false) => {}
            Err(e) => return passkey_error("NotAllowedError", e.to_string()),
        }
        if cancelled() {
            return passkey_approval_error("Cancelled");
        }
        let created =
            state
                .bw
                .browser_passkey_create_on(&validated, &options, verification, target);
        if !state.bw.has_session() {
            crate::lock_vault_state(&mut state, "session revoked");
            return error("Locked");
        }
        match created {
            Ok(mut result) => {
                crate::notify_browser_matches(&state);
                // A successful save remains durable if the page disappears during the HTTP request.
                if cancelled() || state.browser_epoch != epoch {
                    return passkey_approval_error("Cancelled");
                }
                result.document_id = document_id;
                result.epoch = epoch;
                BrowserResponse::PasskeyResult { result }
            }
            Err(e) => passkey_error("NotAllowedError", e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_destination_and_origin_including_port() {
        assert_eq!(
            context("https://git.mvl.sh", "https://git.mvl.sh/login", "doc"),
            Some(false)
        );
        assert_eq!(
            context("https://git.mvl.sh", "https://vault.mvl.sh", "doc"),
            Some(true)
        );
        assert_eq!(
            context("https://git.mvl.sh", "https://git.mvl.sh:8443", "doc"),
            Some(true)
        );
        assert_eq!(context("https://git.mvl.sh", "about:blank", "doc"), None);
        assert_eq!(
            context("https://git.mvl.sh", "https://git.mvl.sh", ""),
            None
        );
    }
}
