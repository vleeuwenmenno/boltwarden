//! Browser approvals authorize exactly one pending request, never a desktop item grant.
use crate::interaction::{self, Kind};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BrowserApprovalChoice {
    pub id: String,
    pub label: String,
    pub description: String,
    #[serde(default)]
    pub requires_password: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BrowserApprovalRequest {
    pub id: String,
    pub title: String,
    pub description: String,
    pub fingerprint: Option<String>,
    pub requires_password: bool,
    #[serde(default)]
    pub choices: Vec<BrowserApprovalChoice>,
    #[serde(default)]
    pub action_label: Option<String>,
    #[serde(default)]
    pub allow_fallback: bool,
}

impl BrowserApprovalRequest {
    /// Selection is validated even when the whole request requires verification.
    pub fn requires_password_for(&self, selected: Option<&str>) -> Result<bool, String> {
        validate_selection(self, selected)?;
        Ok(self.requires_password
            || self
                .choices
                .iter()
                .any(|choice| Some(choice.id.as_str()) == selected && choice.requires_password))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BrowserApprovalDecision {
    pub request_id: String,
    pub approved: bool,
    #[serde(default)]
    pub selected_id: Option<String>,
    #[serde(default)]
    pub use_other_device: bool,
    #[serde(default)]
    pub password: String,
}

impl std::fmt::Debug for BrowserApprovalDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserApprovalDecision")
            .field("request_id", &self.request_id)
            .field("approved", &self.approved)
            .finish_non_exhaustive()
    }
}

impl Drop for BrowserApprovalDecision {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

struct Pending {
    request: BrowserApprovalRequest,
    result: Option<Result<Option<String>, String>>,
}

struct Inner {
    pending: Mutex<Option<Pending>>,
    changed: Condvar,
    notify: mpsc::Sender<()>,
}

#[derive(Clone)]
pub struct BrowserApprovals(Arc<Inner>);

impl BrowserApprovals {
    pub fn new(notify: mpsc::Sender<()>) -> Self {
        Self(Arc::new(Inner {
            pending: Mutex::new(None),
            changed: Condvar::new(),
            notify,
        }))
    }

    pub fn active(&self) -> Option<BrowserApprovalRequest> {
        self.0
            .pending
            .lock()
            .ok()?
            .as_ref()
            .map(|p| p.request.clone())
    }

    pub fn resolve(&self, id: &str, result: Result<Option<String>, String>) -> Result<(), String> {
        let mut pending = self.0.pending.lock().map_err(|_| "Approval unavailable")?;
        let current = pending
            .as_mut()
            .filter(|p| p.request.id == id)
            .ok_or("Approval is no longer pending")?;
        if current.result.is_some() {
            return Err("Approval is already resolved".into());
        }
        if let Ok(selected) = &result {
            validate_selection(&current.request, selected.as_deref())?;
        }
        current.result = Some(result);
        self.0.changed.notify_all();
        Ok(())
    }

    pub fn clear(&self) {
        if let Ok(mut pending) = self.0.pending.lock() {
            *pending = None;
            self.0.changed.notify_all();
        }
    }

    pub fn request(
        &self,
        mut request: BrowserApprovalRequest,
        cancelled: impl Fn() -> bool,
    ) -> Result<Option<String>, String> {
        let _lease = interaction::global().acquire(Kind::Browser)?;
        request.id = uuid::Uuid::new_v4().to_string();
        let id = request.id.clone();
        let mut pending = self.0.pending.lock().map_err(|_| "Approval unavailable")?;
        if pending.is_some() {
            return Err("Busy".into());
        }
        if cancelled() {
            return Err("Cancelled".into());
        }
        *pending = Some(Pending {
            request,
            result: None,
        });
        if self.0.notify.send(()).is_err() {
            *pending = None;
            return Err("Desktop approval unavailable".into());
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if cancelled() || Instant::now() >= deadline {
                if pending.as_ref().is_some_and(|p| p.request.id == id) {
                    *pending = None;
                }
                return Err("Cancelled".into());
            }
            let current = pending
                .as_mut()
                .filter(|p| p.request.id == id)
                .ok_or("Cancelled")?;
            if let Some(result) = current.result.take() {
                *pending = None;
                return result;
            }
            pending = self
                .0
                .changed
                .wait_timeout(pending, Duration::from_millis(100))
                .map_err(|_| "Approval unavailable")?
                .0;
        }
    }
}

/// The selected identifier is scoped to this exact prompt. Never accept a caller's
/// arbitrary vault item identifier, even after successful password verification.
pub fn validate_selection(
    request: &BrowserApprovalRequest,
    selected: Option<&str>,
) -> Result<(), String> {
    if request.choices.is_empty() {
        if selected.is_none() {
            return Ok(());
        }
    } else if selected.is_some_and(|id| request.choices.iter().any(|choice| choice.id == id)) {
        return Ok(());
    }
    Err("Select an account from this request".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_account_can_require_verification_but_never_remove_request_requirement() {
        let mut request = BrowserApprovalRequest {
            id: "request".into(),
            title: "Sign in".into(),
            description: String::new(),
            fingerprint: None,
            requires_password: false,
            action_label: None,
            allow_fallback: false,
            choices: vec![
                BrowserApprovalChoice {
                    id: "plain".into(),
                    label: "Plain".into(),
                    description: String::new(),
                    requires_password: false,
                },
                BrowserApprovalChoice {
                    id: "protected".into(),
                    label: "Protected".into(),
                    description: String::new(),
                    requires_password: true,
                },
            ],
        };
        assert_eq!(request.requires_password_for(Some("plain")), Ok(false));
        assert_eq!(request.requires_password_for(Some("protected")), Ok(true));
        assert!(request.requires_password_for(None).is_err());
        assert!(
            request
                .requires_password_for(Some("other-request-choice"))
                .is_err()
        );
        request.requires_password = true;
        assert_eq!(request.requires_password_for(Some("plain")), Ok(true));
        assert_eq!(request.requires_password_for(Some("protected")), Ok(true));
        assert!(
            request
                .requires_password_for(Some("other-request-choice"))
                .is_err()
        );
        request.choices.clear();
        assert_eq!(request.requires_password_for(None), Ok(true));
        request.requires_password = false;
        assert_eq!(request.requires_password_for(None), Ok(false));
        let old_choice: BrowserApprovalChoice =
            serde_json::from_str(r#"{"id":"old","label":"Old","description":""}"#).unwrap();
        assert!(!old_choice.requires_password);
    }

    #[test]
    fn account_selection_is_bound_to_the_current_choices() {
        let mut request = BrowserApprovalRequest {
            id: "request-1".into(),
            title: "Sign in".into(),
            description: String::new(),
            fingerprint: None,
            requires_password: true,
            choices: vec![BrowserApprovalChoice {
                id: "choice-1".into(),
                label: "Account".into(),
                description: String::new(),
                requires_password: false,
            }],
            action_label: Some("Sign in".into()),
            allow_fallback: true,
        };
        assert!(validate_selection(&request, None).is_err());
        assert!(validate_selection(&request, Some("vault-item-id")).is_err());
        assert!(validate_selection(&request, Some("choice-1")).is_ok());
        request.choices.clear();
        assert!(validate_selection(&request, Some("choice-1")).is_err());
        assert!(validate_selection(&request, None).is_ok());
    }

    #[test]
    fn stale_decision_cannot_authorize_another_operation() {
        let (tx, rx) = mpsc::channel();
        let approvals = BrowserApprovals::new(tx);
        let waiting = approvals.clone();
        let join = std::thread::spawn(move || {
            waiting.request(
                BrowserApprovalRequest {
                    id: String::new(),
                    title: "Pair".into(),
                    description: String::new(),
                    fingerprint: None,
                    requires_password: false,
                    choices: Vec::new(),
                    action_label: None,
                    allow_fallback: false,
                },
                || false,
            )
        });
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(approvals.resolve("wrong-request", Ok(None)).is_err());
        let request = approvals.active().unwrap();
        approvals
            .resolve(&request.id, Err("Denied".into()))
            .unwrap();
        assert_eq!(join.join().unwrap(), Err("Denied".into()));
    }
}
