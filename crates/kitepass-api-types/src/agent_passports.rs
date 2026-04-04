use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Agent Passport metadata (control-plane view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPassport {
    pub agent_passport_id: String,
    pub principal_account_id: String,
    pub public_key: String,
    pub key_alg: String,
    pub key_address: String,
    pub status: AgentPassportStatus,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentPassportStatus {
    Active,
    Frozen,
    Revoked,
    Expired,
}

/// Explicit agent-passport mutation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum MutateAgentPassportRequest {
    Freeze,
    Revoke,
}

/// Wallet Agent Passport Binding — authorizes one agent passport to one wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAgentPassportBinding {
    pub binding_id: String,
    pub agent_passport_id: String,
    pub wallet_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
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

/// Request to create an agent passport with wallet bindings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAgentPassportRequest {
    pub public_key: String,
    pub key_address: String,
    pub expires_at: DateTime<Utc>,
    pub bindings: Vec<BindingInput>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingInput {
    pub wallet_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub is_default: bool,
    pub selection_priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAgentPassportBindingRequest {
    pub wallet_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub is_default: bool,
    pub selection_priority: u32,
}

/// Response from creating an agent passport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAgentPassportResponse {
    pub agent_passport_id: String,
    pub status: String,
    pub bindings: Vec<BindingResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingResult {
    pub binding_id: String,
    pub wallet_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub tee_mirror_status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_passport() -> AgentPassport {
        let now = Utc::now();
        AgentPassport {
            agent_passport_id: "ap-001".into(),
            principal_account_id: "pa-001".into(),
            public_key: "0xabc123".into(),
            key_alg: "ecdsa-secp256k1".into(),
            key_address: "0xdef456".into(),
            status: AgentPassportStatus::Active,
            expires_at: now,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn agent_passport_roundtrip() {
        let original = sample_passport();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: AgentPassport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.agent_passport_id, original.agent_passport_id);
        assert_eq!(decoded.status, original.status);
        assert_eq!(decoded.key_alg, original.key_alg);
    }

    #[test]
    fn agent_passport_status_serialization() {
        assert_eq!(
            serde_json::to_string(&AgentPassportStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&AgentPassportStatus::Frozen).unwrap(),
            "\"frozen\""
        );
        assert_eq!(
            serde_json::to_string(&AgentPassportStatus::Revoked).unwrap(),
            "\"revoked\""
        );
        assert_eq!(
            serde_json::to_string(&AgentPassportStatus::Expired).unwrap(),
            "\"expired\""
        );
    }

    #[test]
    fn binding_status_serialization() {
        assert_eq!(
            serde_json::to_string(&BindingStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&BindingStatus::Suspended).unwrap(),
            "\"suspended\""
        );
        assert_eq!(
            serde_json::to_string(&BindingStatus::Revoked).unwrap(),
            "\"revoked\""
        );
    }

    #[test]
    fn wallet_agent_passport_binding_roundtrip() {
        let binding = WalletAgentPassportBinding {
            binding_id: "bind-001".into(),
            agent_passport_id: "ap-001".into(),
            wallet_id: "w-001".into(),
            passport_policy_id: "pp-001".into(),
            passport_policy_version: 3,
            status: BindingStatus::Active,
            is_default: true,
            selection_priority: 10,
        };
        let json = serde_json::to_string(&binding).unwrap();
        let decoded: WalletAgentPassportBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.binding_id, "bind-001");
        assert_eq!(decoded.passport_policy_version, 3);
        assert!(decoded.is_default);
        assert_eq!(decoded.selection_priority, 10);
        assert_eq!(decoded.status, BindingStatus::Active);
    }

    #[test]
    fn create_agent_passport_request_roundtrip() {
        let req = CreateAgentPassportRequest {
            public_key: "0xpub".into(),
            key_address: "0xaddr".into(),
            expires_at: Utc::now(),
            bindings: vec![BindingInput {
                wallet_id: "w-001".into(),
                passport_policy_id: "pp-001".into(),
                passport_policy_version: 1,
                is_default: true,
                selection_priority: 5,
            }],
            idempotency_key: "idem-123".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: CreateAgentPassportRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.public_key, "0xpub");
        assert_eq!(decoded.bindings.len(), 1);
        assert_eq!(decoded.bindings[0].wallet_id, "w-001");
    }

    #[test]
    fn create_agent_passport_response_roundtrip() {
        let resp = CreateAgentPassportResponse {
            agent_passport_id: "ap-002".into(),
            status: "active".into(),
            bindings: vec![BindingResult {
                binding_id: "bind-002".into(),
                wallet_id: "w-002".into(),
                passport_policy_id: "pp-002".into(),
                passport_policy_version: 1,
                tee_mirror_status: "synced".into(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: CreateAgentPassportResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.agent_passport_id, "ap-002");
        assert_eq!(decoded.bindings[0].tee_mirror_status, "synced");
    }

    #[test]
    fn mutate_agent_passport_request_tagged_enum() {
        let freeze = MutateAgentPassportRequest::Freeze;
        let json = serde_json::to_string(&freeze).unwrap();
        assert!(json.contains("\"operation\":\"freeze\""));
        let decoded: MutateAgentPassportRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, MutateAgentPassportRequest::Freeze));

        let revoke = MutateAgentPassportRequest::Revoke;
        let json = serde_json::to_string(&revoke).unwrap();
        assert!(json.contains("\"operation\":\"revoke\""));
        let decoded: MutateAgentPassportRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, MutateAgentPassportRequest::Revoke));
    }
}
