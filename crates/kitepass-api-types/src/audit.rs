use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Tamper-evident audit event.
///
/// **Note:** The audit ledger API (`/internal/events`, `/internal/events/verify`)
/// is provisional and subject to breaking changes. Production deployments should
/// not depend on the current schema or verification endpoint without coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub action: String,
    pub trace_id: String,
    pub request_id: String,
    pub wallet_id: String,
    pub agent_passport_id: String,
    pub chain_id: String,
    pub payload_hash: String,
    pub outcome: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub permit_id: String,
    pub enclave_receipt: Option<String>,
    pub previous_event_hash: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyAuditResponse {
    pub valid: bool,
    pub event_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_event_id: Option<String>,
}
