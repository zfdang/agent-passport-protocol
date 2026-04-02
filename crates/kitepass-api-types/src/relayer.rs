use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTxRequest {
    pub request_id: String,
    pub wallet_id: String,
    pub chain_id: String,
    pub signed_payload: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclave_receipt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTxResponse {
    pub operation_id: String,
    pub tx_hash: String,
    pub status: String,
    pub submitted_at: DateTime<Utc>,
}
