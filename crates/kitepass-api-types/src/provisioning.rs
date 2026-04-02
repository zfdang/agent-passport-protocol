use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::access_keys::{BindingInput, BindingResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningOperation {
    CreateAgentAccessKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningApprovalStatus {
    PendingOwnerStepUp,
    Approved,
    Consumed,
    Expired,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningIntentPayload {
    pub owner_id: String,
    pub operation: ProvisioningOperation,
    pub public_key: String,
    pub key_address: String,
    pub expires_at: DateTime<Utc>,
    pub bindings: Vec<BindingInput>,
    pub issued_at: DateTime<Utc>,
    pub intent_expires_at: DateTime<Utc>,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningIntent {
    pub intent_id: String,
    pub owner_id: String,
    pub operation: ProvisioningOperation,
    pub public_key: String,
    pub key_address: String,
    pub expires_at: DateTime<Utc>,
    pub bindings: Vec<BindingInput>,
    pub issued_at: DateTime<Utc>,
    pub intent_expires_at: DateTime<Utc>,
    pub nonce: String,
    pub intent_hash: String,
    pub approval_status: ProvisioningApprovalStatus,
    pub owner_approval_id: Option<String>,
    pub owner_approval_expires_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareAccessKeyRequest {
    pub public_key: String,
    pub key_address: String,
    pub expires_at: DateTime<Utc>,
    pub bindings: Vec<BindingInput>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareAccessKeyResponse {
    pub intent_id: String,
    pub intent_hash: String,
    pub approval_url: String,
    pub approval_status: ProvisioningApprovalStatus,
    pub approval_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetProvisioningIntentResponse {
    pub intent_id: String,
    pub intent_hash: String,
    pub approval_status: ProvisioningApprovalStatus,
    pub owner_approval_id: Option<String>,
    pub owner_approval_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListProvisioningIntentsResponse {
    pub provisioning_intents: Vec<ProvisioningIntent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListOwnerApprovalsResponse {
    pub owner_approvals: Vec<OwnerApprovalRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeAccessKeyRequest {
    pub intent_id: String,
    pub owner_approval_id: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerApprovalRecord {
    pub owner_approval_id: String,
    pub record_type: String,
    pub record_version: u32,
    pub owner_id: String,
    pub intent_id: String,
    pub intent_hash: String,
    pub operation: ProvisioningOperation,
    pub approval_method: String,
    pub approved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approver_key_ref: String,
    pub owner_approval_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerApprovalPayload {
    pub owner_approval_id: String,
    pub record_type: String,
    pub record_version: u32,
    pub owner_id: String,
    pub intent_id: String,
    pub intent_hash: String,
    pub operation: ProvisioningOperation,
    pub approval_method: String,
    pub approved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approver_key_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeAccessKeyResponse {
    pub access_key_id: String,
    pub status: String,
    pub owner_approval_status: String,
    pub bindings: Vec<BindingResult>,
}

impl From<&ProvisioningIntent> for ProvisioningIntentPayload {
    fn from(intent: &ProvisioningIntent) -> Self {
        Self {
            owner_id: intent.owner_id.clone(),
            operation: intent.operation.clone(),
            public_key: intent.public_key.clone(),
            key_address: intent.key_address.clone(),
            expires_at: intent.expires_at,
            bindings: intent.bindings.clone(),
            issued_at: intent.issued_at,
            intent_expires_at: intent.intent_expires_at,
            nonce: intent.nonce.clone(),
        }
    }
}

impl From<&OwnerApprovalRecord> for OwnerApprovalPayload {
    fn from(approval: &OwnerApprovalRecord) -> Self {
        Self {
            owner_approval_id: approval.owner_approval_id.clone(),
            record_type: approval.record_type.clone(),
            record_version: approval.record_version,
            owner_id: approval.owner_id.clone(),
            intent_id: approval.intent_id.clone(),
            intent_hash: approval.intent_hash.clone(),
            operation: approval.operation.clone(),
            approval_method: approval.approval_method.clone(),
            approved_at: approval.approved_at,
            expires_at: approval.expires_at,
            approver_key_ref: approval.approver_key_ref.clone(),
        }
    }
}
