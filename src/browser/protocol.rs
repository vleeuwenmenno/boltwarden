//! Versioned native-messaging contract. All payloads are JSON with snake_case fields.
use crate::passkeys::{CreateOptions, GetOptions, PasskeyResult};
use serde::{Deserialize, Serialize};

pub const VERSION: u8 = 1;
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
#[derive(Deserialize)]
pub struct BrowserIdentities {
    pub host_name: String,
    pub firefox_id: String,
    pub chrome_id: String,
}

pub fn identities() -> &'static BrowserIdentities {
    static IDENTITIES: std::sync::OnceLock<BrowserIdentities> = std::sync::OnceLock::new();
    IDENTITIES.get_or_init(|| {
        serde_json::from_str(include_str!("../../extension/lib/browser-identities.json"))
            .expect("Bundled browser identities must be valid JSON")
    })
}

#[derive(Clone, Deserialize, Serialize)]
pub struct CapturedLogin {
    pub username: String,
    pub password: String,
}
impl std::fmt::Debug for CapturedLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CapturedLogin([redacted])")
    }
}
impl Drop for CapturedLogin {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct CardDetails {
    pub cardholder: String,
    pub number: String,
    pub code: String,
    pub exp_month: String,
    pub exp_year: String,
    pub brand: String,
}
impl std::fmt::Debug for CardDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CardDetails([redacted])")
    }
}
impl Drop for CardDetails {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.cardholder.zeroize();
        self.number.zeroize();
        self.code.zeroize();
        self.exp_month.zeroize();
        self.exp_year.zeroize();
        self.brand.zeroize();
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestEnvelope {
    pub version: u8,
    pub id: String,
    #[serde(flatten)]
    pub request: BrowserRequest,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum BrowserRequest {
    Hello {
        #[serde(default)]
        pairing_id: Option<String>,
    },
    Authenticate {
        pairing_id: String,
        sig: String,
        host_pid: u32,
    },
    RequestPairing {
        pairing_id: String,
        public_key_spki: String,
        label: String,
        sig: String,
        host_pid: u32,
    },
    Status,
    RequestUnlock,
    Cancel {
        request_id: String,
    },
    ListMatches {
        top_url: String,
        frame_url: String,
        document_id: String,
        #[serde(default)]
        offset: usize,
    },
    ListCards {
        top_url: String,
        frame_url: String,
        document_id: String,
        #[serde(default)]
        offset: usize,
    },
    ListTotpMatches {
        top_url: String,
        frame_url: String,
        document_id: String,
        #[serde(default)]
        offset: usize,
    },
    PasskeyGet {
        top_url: String,
        frame_url: String,
        document_id: String,
        options: GetOptions,
    },
    PasskeyCreate {
        top_url: String,
        frame_url: String,
        document_id: String,
        options: CreateOptions,
    },
    SaveLogin {
        top_url: String,
        frame_url: String,
        document_id: String,
        login: CapturedLogin,
    },
    FillLogin {
        item_id: String,
        revision: String,
        top_url: String,
        frame_url: String,
        document_id: String,
        interaction: FillInteraction,
        #[serde(default)]
        confirm_insecure: bool,
        #[serde(default)]
        confirm_cross_origin: bool,
    },
    FillCard {
        item_id: String,
        revision: String,
        top_url: String,
        frame_url: String,
        document_id: String,
        interaction: FillInteraction,
        #[serde(default)]
        confirm_insecure: bool,
        #[serde(default)]
        confirm_cross_origin: bool,
    },
    FillTotp {
        item_id: String,
        revision: String,
        top_url: String,
        frame_url: String,
        document_id: String,
        interaction: FillInteraction,
        #[serde(default)]
        confirm_insecure: bool,
        #[serde(default)]
        confirm_cross_origin: bool,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FillInteraction {
    Shortcut,
    Popup,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MatchSummary {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub reprompt: bool,
    pub requires_confirmation: bool,
    pub revision: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum BrowserResponse {
    Challenge {
        nonce: String,
        pairing_id: String,
        paired: bool,
    },
    Authenticated {
        pairing_id: String,
    },
    Paired {
        pairing_id: String,
    },
    Status {
        enabled: bool,
        unlocked: bool,
        epoch: u64,
    },
    UnlockRequested,
    LoginSaved {
        saved: bool,
    },
    Cancelled {
        request_id: String,
    },
    Matches {
        items: Vec<MatchSummary>,
        epoch: u64,
        next_offset: Option<usize>,
        #[serde(default)]
        warning: Option<String>,
    },
    Card {
        card: CardDetails,
        document_id: String,
        epoch: u64,
    },
    Credentials {
        username: String,
        password: String,
        document_id: String,
        epoch: u64,
    },
    Totp {
        code: String,
        expires_at: u64,
        document_id: String,
        epoch: u64,
    },
    PasskeyResult {
        #[serde(flatten)]
        result: PasskeyResult,
    },
    Error {
        code: String,
        message: String,
    },
}

impl std::fmt::Debug for BrowserResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Credentials {
                document_id, epoch, ..
            }
            | Self::Card {
                document_id, epoch, ..
            }
            | Self::Totp {
                document_id, epoch, ..
            } => formatter
                .debug_struct("Credentials")
                .field("document_id", document_id)
                .field("epoch", epoch)
                .field("secrets", &"<redacted>")
                .finish(),
            Self::PasskeyResult { result } => formatter
                .debug_struct("PasskeyResult")
                .field("document_id", &result.document_id)
                .field("epoch", &result.epoch)
                .field("payload", &"<redacted>")
                .finish(),
            _ => formatter.write_str(&serde_json::to_string(self).unwrap_or_default()),
        }
    }
}

impl BrowserResponse {
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Error {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl Drop for BrowserResponse {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            Self::Credentials {
                username, password, ..
            } => {
                username.zeroize();
                password.zeroize();
            }
            Self::Totp { code, .. } => code.zeroize(),
            Self::PasskeyResult { result } => {
                result.credential_id.zeroize();
                result.client_data_json.zeroize();
                result.authenticator_data.zeroize();
                result.signature.zeroize();
                result.user_handle.zeroize();
                result.attestation_object.zeroize();
                result.public_key.zeroize();
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseEnvelope {
    pub version: u8,
    pub id: String,
    #[serde(flatten)]
    pub response: BrowserResponse,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum BrowserEvent {
    Locked { epoch: u64 },
    Unlocked { epoch: u64 },
    MatchesChanged { epoch: u64 },
    Disabled,
    PairingRevoked,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventEnvelope {
    pub version: u8,
    #[serde(flatten)]
    pub event: BrowserEvent,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn passkey_result_has_flat_wire_fields_and_redacted_debug() {
        let response = BrowserResponse::PasskeyResult {
            result: PasskeyResult {
                kind: "get".into(),
                credential_id: "credential-id".into(),
                signature: Some("sensitive-assertion".into()),
                document_id: "document-1".into(),
                epoch: 8,
                ..Default::default()
            },
        };
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["type"], "PasskeyResult");
        assert_eq!(value["kind"], "get");
        assert_eq!(value["signature"], "sensitive-assertion");
        assert_eq!(value["document_id"], "document-1");
        assert!(value.get("result").is_none());
        assert!(!format!("{response:?}").contains("sensitive-assertion"));
        let decoded: BrowserResponse = serde_json::from_value(value).unwrap();
        assert!(matches!(decoded, BrowserResponse::PasskeyResult { .. }));
    }

    #[test]
    fn shared_request_fixture_round_trips() {
        let input = include_str!("../../extension/protocol/fixtures/list-matches.json");
        let request: RequestEnvelope = serde_json::from_str(input).unwrap();
        assert_eq!(request.version, VERSION);
        assert!(matches!(
            request.request,
            BrowserRequest::ListMatches { offset: 0, .. }
        ));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(input).unwrap(),
            serde_json::to_value(request).unwrap()
        );
    }
}
