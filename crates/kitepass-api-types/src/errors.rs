use serde::{Deserialize, Serialize};

/// Unified API error envelope.
///
/// All error responses from Passport Gateway follow this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: ApiErrorBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidArgument,
    Unauthorized,
    Forbidden,
    NotFound,
    NotImplemented,
    Conflict,
    RateLimited,
    PolicyDenied,
    ReservationFailed,
    WalletSelectionFailed,
    AgentProofInvalid,
    AttestationInvalid,
    TeeUnavailable,
    PermitInvalid,
    DigestMismatch,
    SigningFailed,
    SubmissionFailed,
    TemporaryUnavailable,
    /// Forward-compatibility: unknown error codes from newer servers
    /// deserialize to this variant instead of failing.
    #[serde(other)]
    Unknown,
}

impl ErrorCode {
    /// Returns `true` for error codes that represent transient failures
    /// where a retry may succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ErrorCode::TemporaryUnavailable | ErrorCode::TeeUnavailable | ErrorCode::RateLimited
        )
    }
}
