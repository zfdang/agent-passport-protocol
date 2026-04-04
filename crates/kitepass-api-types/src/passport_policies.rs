use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// PassportPolicy definition governing agent actions on a wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportPolicy {
    pub passport_policy_id: String,
    pub binding_id: String,
    pub wallet_id: String,
    /// Agent Passport associated with this policy. Empty string if created without
    /// an agent passport binding (the binding is established later during provisioning).
    #[serde(default)]
    pub agent_passport_id: String,
    pub allowed_chains: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub max_single_amount: String,
    pub max_daily_amount: String,
    pub allowed_destinations: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub state: PassportPolicyState,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePassportPolicyRequest {
    pub binding_id: Option<String>,
    pub wallet_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_passport_id: Option<String>,
    pub allowed_chains: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub max_single_amount: String,
    pub max_daily_amount: String,
    pub allowed_destinations: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePassportPolicyRequest {
    pub binding_id: Option<String>,
    pub wallet_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_passport_id: Option<String>,
    pub allowed_chains: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub max_single_amount: String,
    pub max_daily_amount: String,
    pub allowed_destinations: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportPolicySimulationRequest {
    pub chain_id: String,
    pub signing_type: String,
    pub destination: String,
    pub value: String,
}

/// Explicit policy mutation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum MutatePassportPolicyRequest {
    Update {
        binding_id: Option<String>,
        wallet_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_passport_id: Option<String>,
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
pub struct PassportPolicySimulationResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PassportPolicyState {
    Draft,
    Active,
    Deactivated,
    Archived,
}

/// Signed policy config record for TEE mirror provisioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportPolicyConfigRecord {
    pub record_type: String,
    pub record_version: u32,
    pub binding_id: String,
    pub agent_passport_id: String,
    pub wallet_id: String,
    pub public_key: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub provisioning_intent_id: String,
    pub provisioning_intent_hash: String,
    pub principal_approval_id: String,
    pub principal_approval_hash: String,
    pub issued_at: DateTime<Utc>,
    pub policy_config_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportPolicyConfigRecordPayload {
    pub record_type: String,
    pub record_version: u32,
    pub binding_id: String,
    pub agent_passport_id: String,
    pub wallet_id: String,
    pub public_key: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub provisioning_intent_id: String,
    pub provisioning_intent_hash: String,
    pub principal_approval_id: String,
    pub principal_approval_hash: String,
    pub issued_at: DateTime<Utc>,
}

/// Dynamic policy usage state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportPolicyUsageState {
    pub binding_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub wallet_id: String,
    pub agent_passport_id: String,
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
pub struct PassportPolicyReservation {
    pub reservation_id: String,
    pub binding_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub wallet_id: String,
    pub agent_passport_id: String,
    pub request_id: String,
    pub reserved_amount: String,
    pub status: PassportPolicyReservationStatus,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub signing_started_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub rolled_back_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PassportPolicyReservationStatus {
    Pending,
    Reserved,
    SigningStarted,
    Consumed,
    RolledBack,
}

/// Payload for signing a PassportPolicy Permit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportPolicyPermitPayload {
    pub record_type: String,
    pub record_version: u32,
    pub permit_id: String,
    pub request_id: String,
    pub wallet_id: String,
    pub agent_passport_id: String,
    pub chain_id: String,
    pub signing_type: String,
    pub payload_hash: String,
    pub destination: String,
    pub value: String,
    pub reservation_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Short-lived PassportPolicy Permit issued by PassportPolicy Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportPolicyPermit {
    pub record_type: String,
    pub record_version: u32,
    pub permit_id: String,
    pub request_id: String,
    pub wallet_id: String,
    pub agent_passport_id: String,
    pub chain_id: String,
    pub signing_type: String,
    pub payload_hash: String,
    pub destination: String,
    pub value: String,
    pub reservation_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

impl From<&PassportPolicyConfigRecord> for PassportPolicyConfigRecordPayload {
    fn from(record: &PassportPolicyConfigRecord) -> Self {
        Self {
            record_type: record.record_type.clone(),
            record_version: record.record_version,
            binding_id: record.binding_id.clone(),
            agent_passport_id: record.agent_passport_id.clone(),
            wallet_id: record.wallet_id.clone(),
            public_key: record.public_key.clone(),
            status: record.status.clone(),
            expires_at: record.expires_at,
            passport_policy_id: record.passport_policy_id.clone(),
            passport_policy_version: record.passport_policy_version,
            provisioning_intent_id: record.provisioning_intent_id.clone(),
            provisioning_intent_hash: record.provisioning_intent_hash.clone(),
            principal_approval_id: record.principal_approval_id.clone(),
            principal_approval_hash: record.principal_approval_hash.clone(),
            issued_at: record.issued_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn passport_policy_config_record_roundtrip() {
        let now = Utc::now();
        let record = PassportPolicyConfigRecord {
            record_type: "policy_config".into(),
            record_version: 1,
            binding_id: "bind-001".into(),
            agent_passport_id: "ap-001".into(),
            wallet_id: "w-001".into(),
            public_key: "0xpub".into(),
            status: "active".into(),
            expires_at: now,
            passport_policy_id: "pp-001".into(),
            passport_policy_version: 2,
            provisioning_intent_id: "pi-001".into(),
            provisioning_intent_hash: "hash-pi".into(),
            principal_approval_id: "approval-001".into(),
            principal_approval_hash: "hash-approval".into(),
            issued_at: now,
            policy_config_signature: "sig-abc".into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let decoded: PassportPolicyConfigRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.record_type, "policy_config");
        assert_eq!(decoded.record_version, 1);
        assert_eq!(decoded.passport_policy_version, 2);
        assert_eq!(decoded.policy_config_signature, "sig-abc");
    }

    #[test]
    fn passport_policy_permit_roundtrip() {
        let now = Utc::now();
        let permit = PassportPolicyPermit {
            record_type: "policy_permit".into(),
            record_version: 1,
            permit_id: "permit-001".into(),
            request_id: "req-001".into(),
            wallet_id: "w-001".into(),
            agent_passport_id: "ap-001".into(),
            chain_id: "eip155:1".into(),
            signing_type: "transaction".into(),
            payload_hash: "0xpayloadhash".into(),
            destination: "0xdest".into(),
            value: "1000000".into(),
            reservation_id: "rsv-001".into(),
            passport_policy_id: "pp-001".into(),
            passport_policy_version: 3,
            issued_at: now,
            expires_at: now,
            signature: "sig-xyz".into(),
        };
        let json = serde_json::to_string(&permit).unwrap();
        let decoded: PassportPolicyPermit = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.permit_id, "permit-001");
        assert_eq!(decoded.chain_id, "eip155:1");
        assert_eq!(decoded.passport_policy_version, 3);
        assert_eq!(decoded.signature, "sig-xyz");
    }

    #[test]
    fn passport_policy_state_serialization() {
        assert_eq!(
            serde_json::to_string(&PassportPolicyState::Draft).unwrap(),
            "\"draft\""
        );
        assert_eq!(
            serde_json::to_string(&PassportPolicyState::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&PassportPolicyState::Deactivated).unwrap(),
            "\"deactivated\""
        );
        assert_eq!(
            serde_json::to_string(&PassportPolicyState::Archived).unwrap(),
            "\"archived\""
        );

        let decoded: PassportPolicyState = serde_json::from_str("\"draft\"").unwrap();
        assert_eq!(decoded, PassportPolicyState::Draft);
    }

    #[test]
    fn passport_policy_reservation_status_serialization() {
        assert_eq!(
            serde_json::to_string(&PassportPolicyReservationStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&PassportPolicyReservationStatus::Reserved).unwrap(),
            "\"reserved\""
        );
        assert_eq!(
            serde_json::to_string(&PassportPolicyReservationStatus::SigningStarted).unwrap(),
            "\"signing_started\""
        );
        assert_eq!(
            serde_json::to_string(&PassportPolicyReservationStatus::Consumed).unwrap(),
            "\"consumed\""
        );
        assert_eq!(
            serde_json::to_string(&PassportPolicyReservationStatus::RolledBack).unwrap(),
            "\"rolled_back\""
        );

        let decoded: PassportPolicyReservationStatus =
            serde_json::from_str("\"signing_started\"").unwrap();
        assert_eq!(decoded, PassportPolicyReservationStatus::SigningStarted);
    }

    #[test]
    fn passport_policy_usage_state_roundtrip() {
        let now = Utc::now();
        let usage = PassportPolicyUsageState {
            binding_id: "bind-001".into(),
            passport_policy_id: "pp-001".into(),
            passport_policy_version: 2,
            wallet_id: "w-001".into(),
            agent_passport_id: "ap-001".into(),
            lifetime_spent: "5000000".into(),
            daily_window_started_at: now,
            daily_spent: "1000000".into(),
            rolling_window_started_at: now,
            rolling_spent: "2000000".into(),
            last_consumed_request_id: "req-099".into(),
            updated_at: now,
        };
        let json = serde_json::to_string(&usage).unwrap();
        let decoded: PassportPolicyUsageState = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.lifetime_spent, "5000000");
        assert_eq!(decoded.daily_spent, "1000000");
        assert_eq!(decoded.passport_policy_version, 2);
        assert_eq!(decoded.last_consumed_request_id, "req-099");
    }
}

impl From<&PassportPolicyPermit> for PassportPolicyPermitPayload {
    fn from(permit: &PassportPolicyPermit) -> Self {
        Self {
            record_type: permit.record_type.clone(),
            record_version: permit.record_version,
            permit_id: permit.permit_id.clone(),
            request_id: permit.request_id.clone(),
            wallet_id: permit.wallet_id.clone(),
            agent_passport_id: permit.agent_passport_id.clone(),
            chain_id: permit.chain_id.clone(),
            signing_type: permit.signing_type.clone(),
            payload_hash: permit.payload_hash.clone(),
            destination: permit.destination.clone(),
            value: permit.value.clone(),
            reservation_id: permit.reservation_id.clone(),
            passport_policy_id: permit.passport_policy_id.clone(),
            passport_policy_version: permit.passport_policy_version,
            issued_at: permit.issued_at,
            expires_at: permit.expires_at,
        }
    }
}
