use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Passport metadata (control-plane view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passport {
    pub passport_id: String,
    pub principal_account_id: String,
    pub public_key: String,
    pub key_alg: String,
    pub key_address: String,
    pub status: PassportStatus,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PassportStatus {
    Active,
    Frozen,
    Revoked,
    Expired,
}

/// Explicit passport mutation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum MutatePassportRequest {
    Freeze,
    Revoke,
}

/// Wallet Passport Binding — authorizes one passport to one wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletPassportBinding {
    pub binding_id: String,
    pub passport_id: String,
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

/// Request to create a passport with wallet bindings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePassportRequest {
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
pub struct CreatePassportBindingRequest {
    pub wallet_id: String,
    pub passport_policy_id: String,
    pub passport_policy_version: u64,
    pub is_default: bool,
    pub selection_priority: u32,
}

/// Response from creating a passport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePassportResponse {
    pub passport_id: String,
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

    fn sample_passport() -> Passport {
        let now = Utc::now();
        Passport {
            passport_id: "ap-001".into(),
            principal_account_id: "pa-001".into(),
            public_key: "0xabc123".into(),
            key_alg: "ecdsa-secp256k1".into(),
            key_address: "0xdef456".into(),
            status: PassportStatus::Active,
            expires_at: now,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn passport_roundtrip() {
        let original = sample_passport();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Passport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.passport_id, original.passport_id);
        assert_eq!(decoded.status, original.status);
        assert_eq!(decoded.key_alg, original.key_alg);
    }

    #[test]
    fn passport_status_serialization() {
        assert_eq!(
            serde_json::to_string(&PassportStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&PassportStatus::Frozen).unwrap(),
            "\"frozen\""
        );
        assert_eq!(
            serde_json::to_string(&PassportStatus::Revoked).unwrap(),
            "\"revoked\""
        );
        assert_eq!(
            serde_json::to_string(&PassportStatus::Expired).unwrap(),
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
    fn wallet_passport_binding_roundtrip() {
        let binding = WalletPassportBinding {
            binding_id: "bind-001".into(),
            passport_id: "ap-001".into(),
            wallet_id: "w-001".into(),
            passport_policy_id: "pp-001".into(),
            passport_policy_version: 3,
            status: BindingStatus::Active,
            is_default: true,
            selection_priority: 10,
        };
        let json = serde_json::to_string(&binding).unwrap();
        let decoded: WalletPassportBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.binding_id, "bind-001");
        assert_eq!(decoded.passport_policy_version, 3);
        assert!(decoded.is_default);
        assert_eq!(decoded.selection_priority, 10);
        assert_eq!(decoded.status, BindingStatus::Active);
    }

    #[test]
    fn create_passport_request_roundtrip() {
        let req = CreatePassportRequest {
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
        let decoded: CreatePassportRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.public_key, "0xpub");
        assert_eq!(decoded.bindings.len(), 1);
        assert_eq!(decoded.bindings[0].wallet_id, "w-001");
    }

    #[test]
    fn create_passport_response_roundtrip() {
        let resp = CreatePassportResponse {
            passport_id: "ap-002".into(),
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
        let decoded: CreatePassportResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.passport_id, "ap-002");
        assert_eq!(decoded.bindings[0].tee_mirror_status, "synced");
    }

    #[test]
    fn mutate_passport_request_tagged_enum() {
        let freeze = MutatePassportRequest::Freeze;
        let json = serde_json::to_string(&freeze).unwrap();
        assert!(json.contains("\"operation\":\"freeze\""));
        let decoded: MutatePassportRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, MutatePassportRequest::Freeze));

        let revoke = MutatePassportRequest::Revoke;
        let json = serde_json::to_string(&revoke).unwrap();
        assert!(json.contains("\"operation\":\"revoke\""));
        let decoded: MutatePassportRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, MutatePassportRequest::Revoke));
    }
}
