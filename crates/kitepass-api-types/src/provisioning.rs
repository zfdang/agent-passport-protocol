use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::passports::{BindingInput, BindingResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningOperation {
    CreatePassport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningApprovalStatus {
    PendingPrincipalStepUp,
    Approved,
    Consumed,
    Expired,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningIntentPayload {
    pub principal_account_id: String,
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
    pub principal_account_id: String,
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
    pub principal_approval_id: Option<String>,
    pub principal_approval_expires_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparePassportRequest {
    pub public_key: String,
    pub key_address: String,
    pub expires_at: DateTime<Utc>,
    pub bindings: Vec<BindingInput>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparePassportResponse {
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
    pub principal_approval_id: Option<String>,
    pub principal_approval_expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListProvisioningIntentsResponse {
    pub provisioning_intents: Vec<ProvisioningIntent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListPrincipalApprovalsResponse {
    pub principal_approvals: Vec<PrincipalApprovalRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizePassportRequest {
    pub intent_id: String,
    pub principal_approval_id: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalApprovalRecord {
    pub principal_approval_id: String,
    pub record_type: String,
    pub record_version: u32,
    pub principal_account_id: String,
    pub intent_id: String,
    pub intent_hash: String,
    pub operation: ProvisioningOperation,
    pub approval_method: String,
    pub approved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approver_key_ref: String,
    pub principal_approval_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalApprovalPayload {
    pub principal_approval_id: String,
    pub record_type: String,
    pub record_version: u32,
    pub principal_account_id: String,
    pub intent_id: String,
    pub intent_hash: String,
    pub operation: ProvisioningOperation,
    pub approval_method: String,
    pub approved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approver_key_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizePassportResponse {
    pub passport_id: String,
    pub status: String,
    pub principal_approval_status: String,
    pub bindings: Vec<BindingResult>,
}

impl From<&ProvisioningIntent> for ProvisioningIntentPayload {
    fn from(intent: &ProvisioningIntent) -> Self {
        Self {
            principal_account_id: intent.principal_account_id.clone(),
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

impl From<&PrincipalApprovalRecord> for PrincipalApprovalPayload {
    fn from(approval: &PrincipalApprovalRecord) -> Self {
        Self {
            principal_approval_id: approval.principal_approval_id.clone(),
            record_type: approval.record_type.clone(),
            record_version: approval.record_version,
            principal_account_id: approval.principal_account_id.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn provisioning_intent_roundtrip() {
        let now = Utc::now();
        let intent = ProvisioningIntent {
            intent_id: "intent-001".into(),
            principal_account_id: "pa-001".into(),
            operation: ProvisioningOperation::CreatePassport,
            public_key: "0xpub".into(),
            key_address: "0xaddr".into(),
            expires_at: now,
            bindings: vec![BindingInput {
                wallet_id: "w-001".into(),
                passport_policy_id: "pp-001".into(),
                passport_policy_version: 1,
                is_default: true,
                selection_priority: 5,
            }],
            issued_at: now,
            intent_expires_at: now,
            nonce: "nonce-abc".into(),
            intent_hash: "hash-intent".into(),
            approval_status: ProvisioningApprovalStatus::Approved,
            principal_approval_id: Some("approval-001".into()),
            principal_approval_expires_at: Some(now),
            consumed_at: None,
        };
        let json = serde_json::to_string(&intent).unwrap();
        let decoded: ProvisioningIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.intent_id, "intent-001");
        assert_eq!(decoded.operation, ProvisioningOperation::CreatePassport);
        assert_eq!(
            decoded.approval_status,
            ProvisioningApprovalStatus::Approved
        );
        assert_eq!(decoded.principal_approval_id, Some("approval-001".into()));
        assert_eq!(decoded.consumed_at, None);
        assert_eq!(decoded.bindings.len(), 1);
    }

    #[test]
    fn provisioning_operation_serialization() {
        assert_eq!(
            serde_json::to_string(&ProvisioningOperation::CreatePassport).unwrap(),
            "\"create_passport\""
        );
    }

    #[test]
    fn provisioning_approval_status_serialization() {
        assert_eq!(
            serde_json::to_string(&ProvisioningApprovalStatus::PendingPrincipalStepUp).unwrap(),
            "\"pending_principal_step_up\""
        );
        assert_eq!(
            serde_json::to_string(&ProvisioningApprovalStatus::Approved).unwrap(),
            "\"approved\""
        );
        assert_eq!(
            serde_json::to_string(&ProvisioningApprovalStatus::Consumed).unwrap(),
            "\"consumed\""
        );
        assert_eq!(
            serde_json::to_string(&ProvisioningApprovalStatus::Expired).unwrap(),
            "\"expired\""
        );
        assert_eq!(
            serde_json::to_string(&ProvisioningApprovalStatus::Rejected).unwrap(),
            "\"rejected\""
        );
    }

    #[test]
    fn principal_approval_record_roundtrip() {
        let now = Utc::now();
        let record = PrincipalApprovalRecord {
            principal_approval_id: "approval-001".into(),
            record_type: "principal_approval".into(),
            record_version: 1,
            principal_account_id: "pa-001".into(),
            intent_id: "intent-001".into(),
            intent_hash: "hash-intent".into(),
            operation: ProvisioningOperation::CreatePassport,
            approval_method: "passkey".into(),
            approved_at: now,
            expires_at: now,
            approver_key_ref: "key-ref-001".into(),
            principal_approval_signature: "sig-approval".into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let decoded: PrincipalApprovalRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.principal_approval_id, "approval-001");
        assert_eq!(decoded.record_type, "principal_approval");
        assert_eq!(decoded.record_version, 1);
        assert_eq!(decoded.operation, ProvisioningOperation::CreatePassport);
        assert_eq!(decoded.approval_method, "passkey");
        assert_eq!(decoded.principal_approval_signature, "sig-approval");
    }
}
