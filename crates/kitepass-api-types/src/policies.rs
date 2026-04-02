use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Policy definition governing agent actions on a wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub policy_id: String,
    pub binding_id: String,
    pub wallet_id: String,
    pub access_key_id: String,
    pub allowed_chains: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub max_single_amount: String,
    pub max_daily_amount: String,
    pub allowed_destinations: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub state: PolicyState,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicyRequest {
    pub binding_id: Option<String>,
    pub wallet_id: String,
    pub access_key_id: String,
    pub allowed_chains: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub max_single_amount: String,
    pub max_daily_amount: String,
    pub allowed_destinations: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePolicyRequest {
    pub binding_id: Option<String>,
    pub wallet_id: String,
    pub access_key_id: String,
    pub allowed_chains: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub max_single_amount: String,
    pub max_daily_amount: String,
    pub allowed_destinations: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySimulationRequest {
    pub chain_id: String,
    pub signing_type: String,
    pub destination: String,
    pub value: String,
}

/// Explicit policy mutation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum MutatePolicyRequest {
    Update {
        binding_id: Option<String>,
        wallet_id: String,
        access_key_id: String,
        allowed_chains: Vec<String>,
        allowed_actions: Vec<String>,
        max_single_amount: String,
        max_daily_amount: String,
        allowed_destinations: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },
    Activate,
    Deactivate,
    Simulate {
        chain_id: String,
        signing_type: String,
        destination: String,
        value: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySimulationResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub policy_id: String,
    pub policy_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    Draft,
    Active,
    Deactivated,
    Archived,
}

/// Signed policy config record for TEE mirror provisioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfigRecord {
    pub record_type: String,
    pub record_version: u32,
    pub binding_id: String,
    pub access_key_id: String,
    pub wallet_id: String,
    pub public_key: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub policy_id: String,
    pub policy_version: u64,
    pub provisioning_intent_id: String,
    pub provisioning_intent_hash: String,
    pub owner_approval_id: String,
    pub owner_approval_hash: String,
    pub issued_at: DateTime<Utc>,
    pub policy_config_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfigRecordPayload {
    pub record_type: String,
    pub record_version: u32,
    pub binding_id: String,
    pub access_key_id: String,
    pub wallet_id: String,
    pub public_key: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub policy_id: String,
    pub policy_version: u64,
    pub provisioning_intent_id: String,
    pub provisioning_intent_hash: String,
    pub owner_approval_id: String,
    pub owner_approval_hash: String,
    pub issued_at: DateTime<Utc>,
}

/// Dynamic policy usage state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyUsageState {
    pub binding_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub wallet_id: String,
    pub access_key_id: String,
    pub lifetime_spent: String,
    pub daily_window_started_at: DateTime<Utc>,
    pub daily_spent: String,
    pub rolling_window_started_at: DateTime<Utc>,
    pub rolling_spent: String,
    pub last_consumed_request_id: String,
    pub updated_at: DateTime<Utc>,
}

/// Short-lived reservation for concurrency and replay control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyReservation {
    pub reservation_id: String,
    pub binding_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub wallet_id: String,
    pub access_key_id: String,
    pub request_id: String,
    pub reserved_amount: String,
    pub status: ReservationStatus,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub signing_started_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub rolled_back_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Pending,
    Reserved,
    SigningStarted,
    Consumed,
    RolledBack,
}

/// Payload for signing a Policy Permit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPermitPayload {
    pub record_type: String,
    pub record_version: u32,
    pub permit_id: String,
    pub request_id: String,
    pub wallet_id: String,
    pub access_key_id: String,
    pub chain_id: String,
    pub signing_type: String,
    pub payload_hash: String,
    pub destination: String,
    pub value: String,
    pub reservation_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Short-lived Policy Permit issued by Policy Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPermit {
    pub record_type: String,
    pub record_version: u32,
    pub permit_id: String,
    pub request_id: String,
    pub wallet_id: String,
    pub access_key_id: String,
    pub chain_id: String,
    pub signing_type: String,
    pub payload_hash: String,
    pub destination: String,
    pub value: String,
    pub reservation_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

impl From<&PolicyConfigRecord> for PolicyConfigRecordPayload {
    fn from(record: &PolicyConfigRecord) -> Self {
        Self {
            record_type: record.record_type.clone(),
            record_version: record.record_version,
            binding_id: record.binding_id.clone(),
            access_key_id: record.access_key_id.clone(),
            wallet_id: record.wallet_id.clone(),
            public_key: record.public_key.clone(),
            status: record.status.clone(),
            expires_at: record.expires_at,
            policy_id: record.policy_id.clone(),
            policy_version: record.policy_version,
            provisioning_intent_id: record.provisioning_intent_id.clone(),
            provisioning_intent_hash: record.provisioning_intent_hash.clone(),
            owner_approval_id: record.owner_approval_id.clone(),
            owner_approval_hash: record.owner_approval_hash.clone(),
            issued_at: record.issued_at,
        }
    }
}

impl From<&PolicyPermit> for PolicyPermitPayload {
    fn from(permit: &PolicyPermit) -> Self {
        Self {
            record_type: permit.record_type.clone(),
            record_version: permit.record_version,
            permit_id: permit.permit_id.clone(),
            request_id: permit.request_id.clone(),
            wallet_id: permit.wallet_id.clone(),
            access_key_id: permit.access_key_id.clone(),
            chain_id: permit.chain_id.clone(),
            signing_type: permit.signing_type.clone(),
            payload_hash: permit.payload_hash.clone(),
            destination: permit.destination.clone(),
            value: permit.value.clone(),
            reservation_id: permit.reservation_id.clone(),
            policy_id: permit.policy_id.clone(),
            policy_version: permit.policy_version,
            issued_at: permit.issued_at,
            expires_at: permit.expires_at,
        }
    }
}
