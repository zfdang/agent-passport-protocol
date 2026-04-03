use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::chains::ChainFamily;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionChallengeRequest {
    pub access_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionChallengeResponse {
    pub challenge_id: String,
    pub access_key_id: String,
    pub challenge_nonce: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub access_key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    pub session_id: String,
    pub access_key_id: String,
    pub session_nonce: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContextResponse {
    pub access_key_id: String,
    pub key_status: String,
    pub expires_at: DateTime<Utc>,
    pub wallets: Vec<AgentAuthorizedWallet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAuthorizedWallet {
    pub wallet_id: String,
    pub binding_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub is_default: bool,
    pub selection_priority: u32,
    pub allowed_actions: Vec<String>,
    pub allowed_chains: Vec<String>,
    pub max_single_amount: String,
    pub remaining_quota_headroom: String,
    pub binding_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_family: Option<ChainFamily>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentWalletUsageResponse {
    pub wallet_id: String,
    pub access_key_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub lifetime_spent: String,
    pub daily_spent: String,
    pub rolling_spent: String,
    pub remaining_quota_headroom: String,
    pub updated_at: DateTime<Utc>,
}
