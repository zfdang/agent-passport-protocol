use serde::{Deserialize, Serialize};

/// Canonical sign intent from the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignIntent {
    pub intent_type: String,
    pub intent_version: u32,
    pub request_id: String,
    pub wallet_id: String,
    pub access_key_id: String,
    pub chain_id: String,
    pub signing_type: String,
    pub payload_hash: String,
    pub destination: String,
    pub value: String,
    pub session_nonce: String,
    pub mode: SigningMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SigningMode {
    SignatureOnly,
    SignAndSubmit,
}

/// Agent proof-of-possession.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProof {
    pub access_key_id: String,
    pub session_nonce: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateAgentProof {
    pub signature: String,
}

/// Sign request body (POST /v1/signatures).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub request_id: String,
    pub idempotency_key: String,
    pub wallet_id: String,
    pub access_key_id: String,
    pub chain_id: String,
    pub signing_type: String,
    pub mode: SigningMode,
    pub payload: String,
    pub destination: String,
    pub value: String,
    pub agent_proof: AgentProof,
}

/// Sign response for synchronous success.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub request_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permit_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclave_receipt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservation_id: Option<String>,
}

/// Validate-only request body (POST /v1/sign-intents:validate).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ValidateSignIntentRequest {
    pub request_id: String,
    pub wallet_id: Option<String>,
    pub wallet_selector: Option<String>,
    pub access_key_id: String,
    pub chain_id: String,
    pub signing_type: String,
    pub payload: String,
    pub destination: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_proof: Option<ValidateAgentProof>,
}

/// Validate-only response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateSignIntentResponse {
    pub request_id: String,
    pub valid: bool,
    pub resolved_wallet_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub normalized: NormalizedIntent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedIntent {
    pub wallet_id: String,
    pub chain_id: String,
    pub payload_hash: String,
    pub destination: String,
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::SignRequest;

    #[test]
    fn sign_request_requires_destination_and_value() {
        let error = serde_json::from_value::<SignRequest>(serde_json::json!({
            "request_id": "req_123",
            "idempotency_key": "idem_123",
            "wallet_id": "wal_123",
            "access_key_id": "aak_123",
            "chain_id": "eip155:8453",
            "signing_type": "transaction",
            "mode": "signature_only",
            "payload": "0xdeadbeef",
            "agent_proof": {
                "access_key_id": "aak_123",
                "session_nonce": "nonce_123",
                "signature": "0xsig"
            }
        }))
        .unwrap_err()
        .to_string();

        assert!(error.contains("destination"));
    }
}
