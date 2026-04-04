use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::chains::ChainFamily;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionChallengeRequest {
    pub agent_passport_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionChallengeResponse {
    pub challenge_id: String,
    pub agent_passport_id: String,
    pub challenge_nonce: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub agent_passport_id: String,
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
    pub agent_passport_id: String,
    pub session_nonce: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContextResponse {
    pub agent_passport_id: String,
    pub key_status: String,
    pub expires_at: DateTime<Utc>,
    pub wallets: Vec<AgentAuthorizedWallet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAuthorizedWallet {
    pub wallet_id: String,
    pub binding_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
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
    pub agent_passport_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub lifetime_spent: String,
    pub daily_spent: String,
    pub rolling_spent: String,
    pub remaining_quota_headroom: String,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn agent_session_roundtrip() {
        let now = Utc::now();
        let session = AgentSession {
            session_id: "sess-001".into(),
            agent_passport_id: "ap-001".into(),
            session_nonce: "nonce-abc".into(),
            status: "active".into(),
            expires_at: now,
        };
        let json = serde_json::to_string(&session).unwrap();
        let decoded: AgentSession = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.session_id, "sess-001");
        assert_eq!(decoded.agent_passport_id, "ap-001");
        assert_eq!(decoded.session_nonce, "nonce-abc");
        assert_eq!(decoded.status, "active");
    }

    #[test]
    fn create_session_challenge_request_roundtrip() {
        let req = CreateSessionChallengeRequest {
            agent_passport_id: "ap-002".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: CreateSessionChallengeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.agent_passport_id, "ap-002");
    }

    #[test]
    fn create_session_challenge_response_roundtrip() {
        let now = Utc::now();
        let resp = CreateSessionChallengeResponse {
            challenge_id: "ch-001".into(),
            agent_passport_id: "ap-001".into(),
            challenge_nonce: "nonce-xyz".into(),
            expires_at: now,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: CreateSessionChallengeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.challenge_id, "ch-001");
        assert_eq!(decoded.challenge_nonce, "nonce-xyz");
    }

    #[test]
    fn agent_context_response_roundtrip() {
        let now = Utc::now();
        let resp = AgentContextResponse {
            agent_passport_id: "ap-001".into(),
            key_status: "active".into(),
            expires_at: now,
            wallets: vec![AgentAuthorizedWallet {
                wallet_id: "w-001".into(),
                binding_id: "bind-001".into(),
                passport_policy_id: "pp-001".into(),
                passport_policy_version: 2,
                is_default: true,
                selection_priority: 10,
                allowed_actions: vec!["transfer".into(), "approve".into()],
                allowed_chains: vec!["eip155:1".into(), "eip155:137".into()],
                max_single_amount: "1000000".into(),
                remaining_quota_headroom: "500000".into(),
                binding_status: "active".into(),
                chain_family: Some(ChainFamily::Evm),
                wallet_status: Some("active".into()),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: AgentContextResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.agent_passport_id, "ap-001");
        assert_eq!(decoded.wallets.len(), 1);
        let w = &decoded.wallets[0];
        assert_eq!(w.wallet_id, "w-001");
        assert_eq!(w.passport_policy_version, 2);
        assert!(w.is_default);
        assert_eq!(w.allowed_actions.len(), 2);
        assert_eq!(w.allowed_chains.len(), 2);
        assert_eq!(w.max_single_amount, "1000000");
    }
}
