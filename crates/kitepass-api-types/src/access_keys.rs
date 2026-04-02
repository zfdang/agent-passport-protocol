use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Agent Access Key metadata (control-plane view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAccessKey {
    pub access_key_id: String,
    pub owner_id: String,
    pub public_key: String,
    pub key_alg: String,
    pub key_address: String,
    pub status: AccessKeyStatus,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessKeyStatus {
    Active,
    Frozen,
    Revoked,
    Expired,
}

/// Explicit access-key mutation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum MutateAccessKeyRequest {
    Freeze,
    Revoke,
}

/// Wallet Access Binding — authorizes one agent key to one wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccessBinding {
    pub binding_id: String,
    pub access_key_id: String,
    pub wallet_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub status: BindingStatus,
    pub is_default: bool,
    pub selection_priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BindingStatus {
    Active,
    Suspended,
    Revoked,
}

/// Request to create an agent access key with wallet bindings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccessKeyRequest {
    pub public_key: String,
    pub key_address: String,
    pub expires_at: DateTime<Utc>,
    pub bindings: Vec<BindingInput>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingInput {
    pub wallet_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub is_default: bool,
    pub selection_priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBindingRequest {
    pub wallet_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub is_default: bool,
    pub selection_priority: u32,
}

/// Response from creating an agent access key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccessKeyResponse {
    pub access_key_id: String,
    pub status: String,
    pub bindings: Vec<BindingResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingResult {
    pub binding_id: String,
    pub wallet_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub tee_mirror_status: String,
}
