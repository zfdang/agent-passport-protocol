use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::chains::ChainFamily;

/// Wallet metadata (control-plane view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub wallet_id: String,
    pub principal_account_id: String,
    pub chain_family: ChainFamily,
    pub status: WalletStatus,
    pub key_blob_ref: String,
    pub key_version: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletStatus {
    Active,
    Frozen,
    Revoked,
    Archived,
    /// Forward-compatibility: unknown statuses from newer servers.
    #[serde(other)]
    Unknown,
}

/// Explicit wallet mutation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum MutateWalletRequest {
    Freeze,
    Revoke,
}

/// Request to create a wallet import session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateImportSessionRequest {
    pub chain_family: ChainFamily,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub idempotency_key: String,
}

/// Response from creating a wallet import session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateImportSessionResponse {
    pub session_id: String,
    pub status: String,
    pub vault_signer_instance_id: String,
    pub vault_signer_attestation_endpoint: String,
    pub import_encryption_scheme: String,
    pub vault_signer_identity: VaultSignerIdentity,
    pub channel_binding: ChannelBinding,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetImportAttestationResponse {
    pub session_id: String,
    pub vault_signer_instance_id: String,
    pub import_encryption_scheme: String,
    pub attestation_bundle: String,
    pub import_public_key: String,
    pub endpoint_binding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSignerIdentity {
    pub instance_id: String,
    pub tee_type: String,
    pub expected_measurements: ExpectedMeasurements,
    pub measurement_profile: MeasurementProfile,
    pub reviewed_build: ReviewedBuild,
    pub authorization_model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedMeasurements {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementProfile {
    pub profile_id: String,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewedBuild {
    pub build_id: String,
    pub build_digest: String,
    pub build_source: String,
    pub security_model_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationUserData {
    pub document_version: u32,
    pub import_session_id: String,
    pub public_api_scope: String,
    pub authorization_model: String,
    pub import_encryption_scheme: String,
    pub measurement_profile_id: String,
    pub measurement_profile_version: u32,
    pub reviewed_build_id: String,
    pub reviewed_build_digest: String,
    pub build_source: String,
    pub security_model_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBundleDocument {
    pub instance_id: String,
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub endpoint_binding: String,
    pub user_data: AttestationUserData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capsule_attestation_doc_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capsule_eth_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capsule_eth_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capsule_encryption_public_key_der: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelBinding {
    pub principal_account_id: String,
    pub principal_session_id: String,
    pub request_id: String,
}

/// Request to upload encrypted wallet secret.
///
/// The encrypted envelope is produced by P-384 ECDH + AES-256-GCM targeting
/// the Capsule runtime's attestation-bound public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadImportEnvelopeRequest {
    pub vault_signer_instance_id: String,
    pub client_public_key_der_hex: String,
    pub nonce_hex: String,
    pub encrypted_data_hex: String,
    pub aad: ImportAad,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportAad {
    pub principal_account_id: String,
    pub principal_session_id: String,
    pub request_id: String,
    pub vault_signer_instance_id: String,
}

/// Response from uploading encrypted wallet secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadImportEnvelopeResponse {
    pub operation_id: String,
    pub session_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // ── helpers ──────────────────────────────────────────────────────

    fn sample_datetime() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap()
    }

    fn sample_wallet() -> Wallet {
        Wallet {
            wallet_id: "w-001".into(),
            principal_account_id: "acct-abc".into(),
            chain_family: ChainFamily::Evm,
            status: WalletStatus::Active,
            key_blob_ref: "ref-xyz".into(),
            key_version: 3,
            created_at: sample_datetime(),
            updated_at: sample_datetime(),
        }
    }

    fn sample_channel_binding() -> ChannelBinding {
        ChannelBinding {
            principal_account_id: "acct-abc".into(),
            principal_session_id: "sess-001".into(),
            request_id: "req-001".into(),
        }
    }

    fn sample_import_aad() -> ImportAad {
        ImportAad {
            principal_account_id: "acct-abc".into(),
            principal_session_id: "sess-001".into(),
            request_id: "req-001".into(),
            vault_signer_instance_id: "vs-001".into(),
        }
    }

    fn sample_expected_measurements() -> ExpectedMeasurements {
        ExpectedMeasurements {
            pcr0: "aabbcc".into(),
            pcr1: "ddeeff".into(),
            pcr2: "112233".into(),
        }
    }

    fn sample_measurement_profile() -> MeasurementProfile {
        MeasurementProfile {
            profile_id: "profile-1".into(),
            version: 2,
        }
    }

    fn sample_reviewed_build() -> ReviewedBuild {
        ReviewedBuild {
            build_id: "build-001".into(),
            build_digest: "sha256:abc".into(),
            build_source: "https://example.com/build".into(),
            security_model_ref: "sm-001".into(),
        }
    }

    fn sample_vault_signer_identity() -> VaultSignerIdentity {
        VaultSignerIdentity {
            instance_id: "vs-001".into(),
            tee_type: "nitro".into(),
            expected_measurements: sample_expected_measurements(),
            measurement_profile: sample_measurement_profile(),
            reviewed_build: sample_reviewed_build(),
            authorization_model: "strict".into(),
        }
    }

    fn sample_attestation_user_data() -> AttestationUserData {
        AttestationUserData {
            document_version: 1,
            import_session_id: "is-001".into(),
            public_api_scope: "wallets:import".into(),
            authorization_model: "strict".into(),
            import_encryption_scheme: "hpke-x25519".into(),
            measurement_profile_id: "profile-1".into(),
            measurement_profile_version: 2,
            reviewed_build_id: "build-001".into(),
            reviewed_build_digest: "sha256:abc".into(),
            build_source: "https://example.com/build".into(),
            security_model_ref: "sm-001".into(),
        }
    }

    // ── WalletStatus enum ───────────────────────────────────────────

    #[test]
    fn wallet_status_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&WalletStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&WalletStatus::Frozen).unwrap(),
            "\"frozen\""
        );
        assert_eq!(
            serde_json::to_string(&WalletStatus::Revoked).unwrap(),
            "\"revoked\""
        );
        assert_eq!(
            serde_json::to_string(&WalletStatus::Archived).unwrap(),
            "\"archived\""
        );
    }

    #[test]
    fn wallet_status_roundtrip() {
        for status in [
            WalletStatus::Active,
            WalletStatus::Frozen,
            WalletStatus::Revoked,
            WalletStatus::Archived,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: WalletStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn wallet_status_deserializes_unknown_variant() {
        let result: WalletStatus = serde_json::from_str("\"deleted\"").unwrap();
        assert_eq!(result, WalletStatus::Unknown);
    }

    // ── MutateWalletRequest enum (internally tagged) ────────────────

    #[test]
    fn mutate_wallet_request_freeze_roundtrip() {
        let req = MutateWalletRequest::Freeze;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"operation\":\"freeze\""));
        let parsed: MutateWalletRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, MutateWalletRequest::Freeze));
    }

    #[test]
    fn mutate_wallet_request_revoke_roundtrip() {
        let req = MutateWalletRequest::Revoke;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"operation\":\"revoke\""));
        let parsed: MutateWalletRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, MutateWalletRequest::Revoke));
    }

    #[test]
    fn mutate_wallet_request_rejects_unknown_operation() {
        let result = serde_json::from_str::<MutateWalletRequest>(r#"{"operation":"delete"}"#);
        assert!(result.is_err());
    }

    // ── Wallet struct ───────────────────────────────────────────────

    #[test]
    fn wallet_roundtrip() {
        let wallet = sample_wallet();
        let json = serde_json::to_string(&wallet).unwrap();
        let parsed: Wallet = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.wallet_id, "w-001");
        assert_eq!(parsed.principal_account_id, "acct-abc");
        assert!(matches!(parsed.chain_family, ChainFamily::Evm));
        assert_eq!(parsed.status, WalletStatus::Active);
        assert_eq!(parsed.key_blob_ref, "ref-xyz");
        assert_eq!(parsed.key_version, 3);
        assert_eq!(parsed.created_at, sample_datetime());
        assert_eq!(parsed.updated_at, sample_datetime());
    }

    #[test]
    fn wallet_chain_family_serialized_as_lowercase() {
        let wallet = sample_wallet();
        let json = serde_json::to_string(&wallet).unwrap();
        assert!(json.contains("\"chain_family\":\"evm\""));
    }

    // ── CreateImportSessionRequest ──────────────────────────────────

    #[test]
    fn create_import_session_request_roundtrip_with_label() {
        let req = CreateImportSessionRequest {
            chain_family: ChainFamily::Evm,
            label: Some("my-wallet".into()),
            idempotency_key: "idem-001".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: CreateImportSessionRequest = serde_json::from_str(&json).unwrap();

        assert!(matches!(parsed.chain_family, ChainFamily::Evm));
        assert_eq!(parsed.label.as_deref(), Some("my-wallet"));
        assert_eq!(parsed.idempotency_key, "idem-001");
    }

    #[test]
    fn create_import_session_request_omits_none_label() {
        let req = CreateImportSessionRequest {
            chain_family: ChainFamily::Evm,
            label: None,
            idempotency_key: "idem-002".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("\"label\""));

        // Deserializing without the field should yield None
        let parsed: CreateImportSessionRequest = serde_json::from_str(&json).unwrap();
        assert!(parsed.label.is_none());
    }

    // ── CreateImportSessionResponse ─────────────────────────────────

    #[test]
    fn create_import_session_response_roundtrip() {
        let resp = CreateImportSessionResponse {
            session_id: "sess-001".into(),
            status: "pending".into(),
            vault_signer_instance_id: "vs-001".into(),
            vault_signer_attestation_endpoint: "https://attest.example.com".into(),
            import_encryption_scheme: "hpke-x25519".into(),
            vault_signer_identity: sample_vault_signer_identity(),
            channel_binding: sample_channel_binding(),
            expires_at: sample_datetime(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: CreateImportSessionResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.session_id, "sess-001");
        assert_eq!(parsed.status, "pending");
        assert_eq!(parsed.vault_signer_instance_id, "vs-001");
        assert_eq!(
            parsed.vault_signer_attestation_endpoint,
            "https://attest.example.com"
        );
        assert_eq!(parsed.import_encryption_scheme, "hpke-x25519");
        assert_eq!(parsed.expires_at, sample_datetime());
        assert_eq!(parsed.vault_signer_identity.instance_id, "vs-001");
        assert_eq!(parsed.channel_binding.principal_account_id, "acct-abc");
    }

    // ── GetImportAttestationResponse ────────────────────────────────

    #[test]
    fn get_import_attestation_response_roundtrip() {
        let resp = GetImportAttestationResponse {
            session_id: "sess-002".into(),
            vault_signer_instance_id: "vs-002".into(),
            import_encryption_scheme: "hpke-x25519".into(),
            attestation_bundle: "bundle-b64".into(),
            import_public_key: "pubkey-b64".into(),
            endpoint_binding: "binding-001".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: GetImportAttestationResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.session_id, "sess-002");
        assert_eq!(parsed.vault_signer_instance_id, "vs-002");
        assert_eq!(parsed.attestation_bundle, "bundle-b64");
        assert_eq!(parsed.import_public_key, "pubkey-b64");
        assert_eq!(parsed.endpoint_binding, "binding-001");
    }

    // ── VaultSignerIdentity ─────────────────────────────────────────

    #[test]
    fn vault_signer_identity_roundtrip() {
        let ident = sample_vault_signer_identity();
        let json = serde_json::to_string(&ident).unwrap();
        let parsed: VaultSignerIdentity = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.instance_id, "vs-001");
        assert_eq!(parsed.tee_type, "nitro");
        assert_eq!(parsed.expected_measurements.pcr0, "aabbcc");
        assert_eq!(parsed.measurement_profile.profile_id, "profile-1");
        assert_eq!(parsed.reviewed_build.build_id, "build-001");
        assert_eq!(parsed.authorization_model, "strict");
    }

    // ── ExpectedMeasurements ────────────────────────────────────────

    #[test]
    fn expected_measurements_roundtrip() {
        let m = sample_expected_measurements();
        let json = serde_json::to_string(&m).unwrap();
        let parsed: ExpectedMeasurements = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.pcr0, "aabbcc");
        assert_eq!(parsed.pcr1, "ddeeff");
        assert_eq!(parsed.pcr2, "112233");
    }

    // ── MeasurementProfile ──────────────────────────────────────────

    #[test]
    fn measurement_profile_roundtrip() {
        let mp = sample_measurement_profile();
        let json = serde_json::to_string(&mp).unwrap();
        let parsed: MeasurementProfile = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.profile_id, "profile-1");
        assert_eq!(parsed.version, 2);
    }

    // ── ReviewedBuild ───────────────────────────────────────────────

    #[test]
    fn reviewed_build_roundtrip() {
        let rb = sample_reviewed_build();
        let json = serde_json::to_string(&rb).unwrap();
        let parsed: ReviewedBuild = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.build_id, "build-001");
        assert_eq!(parsed.build_digest, "sha256:abc");
        assert_eq!(parsed.build_source, "https://example.com/build");
        assert_eq!(parsed.security_model_ref, "sm-001");
    }

    // ── AttestationUserData ─────────────────────────────────────────

    #[test]
    fn attestation_user_data_roundtrip() {
        let ud = sample_attestation_user_data();
        let json = serde_json::to_string(&ud).unwrap();
        let parsed: AttestationUserData = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.document_version, 1);
        assert_eq!(parsed.import_session_id, "is-001");
        assert_eq!(parsed.public_api_scope, "wallets:import");
        assert_eq!(parsed.authorization_model, "strict");
        assert_eq!(parsed.import_encryption_scheme, "hpke-x25519");
        assert_eq!(parsed.measurement_profile_id, "profile-1");
        assert_eq!(parsed.measurement_profile_version, 2);
        assert_eq!(parsed.reviewed_build_id, "build-001");
        assert_eq!(parsed.reviewed_build_digest, "sha256:abc");
        assert_eq!(parsed.build_source, "https://example.com/build");
        assert_eq!(parsed.security_model_ref, "sm-001");
    }

    // ── AttestationBundleDocument ───────────────────────────────────

    #[test]
    fn attestation_bundle_document_roundtrip_with_optional_fields() {
        let doc = AttestationBundleDocument {
            instance_id: "vs-001".into(),
            pcr0: "aabbcc".into(),
            pcr1: "ddeeff".into(),
            pcr2: "112233".into(),
            endpoint_binding: "binding-001".into(),
            user_data: sample_attestation_user_data(),
            capsule_attestation_doc_b64: Some("capsule-att-b64".into()),
            capsule_eth_address: Some("0xAbCdEf0123456789".into()),
            capsule_eth_public_key: Some("04abcdef".into()),
            capsule_encryption_public_key_der: Some("der-encoded".into()),
        };
        let json = serde_json::to_string(&doc).unwrap();
        let parsed: AttestationBundleDocument = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.instance_id, "vs-001");
        assert_eq!(parsed.pcr0, "aabbcc");
        assert_eq!(
            parsed.capsule_attestation_doc_b64.as_deref(),
            Some("capsule-att-b64")
        );
        assert_eq!(
            parsed.capsule_eth_address.as_deref(),
            Some("0xAbCdEf0123456789")
        );
        assert_eq!(parsed.capsule_eth_public_key.as_deref(), Some("04abcdef"));
        assert_eq!(
            parsed.capsule_encryption_public_key_der.as_deref(),
            Some("der-encoded")
        );
    }

    #[test]
    fn attestation_bundle_document_omits_none_optional_fields() {
        let doc = AttestationBundleDocument {
            instance_id: "vs-001".into(),
            pcr0: "aabbcc".into(),
            pcr1: "ddeeff".into(),
            pcr2: "112233".into(),
            endpoint_binding: "binding-001".into(),
            user_data: sample_attestation_user_data(),
            capsule_attestation_doc_b64: None,
            capsule_eth_address: None,
            capsule_eth_public_key: None,
            capsule_encryption_public_key_der: None,
        };
        let json = serde_json::to_string(&doc).unwrap();

        assert!(!json.contains("capsule_attestation_doc_b64"));
        assert!(!json.contains("capsule_eth_address"));
        assert!(!json.contains("capsule_eth_public_key"));
        assert!(!json.contains("capsule_encryption_public_key_der"));

        // Roundtrip still works
        let parsed: AttestationBundleDocument = serde_json::from_str(&json).unwrap();
        assert!(parsed.capsule_attestation_doc_b64.is_none());
        assert!(parsed.capsule_eth_address.is_none());
    }

    // ── ChannelBinding ──────────────────────────────────────────────

    #[test]
    fn channel_binding_roundtrip() {
        let cb = sample_channel_binding();
        let json = serde_json::to_string(&cb).unwrap();
        let parsed: ChannelBinding = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.principal_account_id, "acct-abc");
        assert_eq!(parsed.principal_session_id, "sess-001");
        assert_eq!(parsed.request_id, "req-001");
    }

    // ── UploadImportEnvelopeRequest ─────────────────────────────────

    #[test]
    fn upload_import_envelope_request_roundtrip() {
        let req = UploadImportEnvelopeRequest {
            vault_signer_instance_id: "vs-001".into(),
            client_public_key_der_hex: "0xclientpub".into(),
            nonce_hex: "0xnonce".into(),
            encrypted_data_hex: "0xencrypted".into(),
            aad: sample_import_aad(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: UploadImportEnvelopeRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.vault_signer_instance_id, "vs-001");
        assert_eq!(parsed.client_public_key_der_hex, "0xclientpub");
        assert_eq!(parsed.nonce_hex, "0xnonce");
        assert_eq!(parsed.encrypted_data_hex, "0xencrypted");
        assert_eq!(parsed.aad.principal_account_id, "acct-abc");
        assert_eq!(parsed.aad.vault_signer_instance_id, "vs-001");
    }

    // ── ImportAad ───────────────────────────────────────────────────

    #[test]
    fn import_aad_roundtrip() {
        let aad = sample_import_aad();
        let json = serde_json::to_string(&aad).unwrap();
        let parsed: ImportAad = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.principal_account_id, "acct-abc");
        assert_eq!(parsed.principal_session_id, "sess-001");
        assert_eq!(parsed.request_id, "req-001");
        assert_eq!(parsed.vault_signer_instance_id, "vs-001");
    }

    // ── UploadImportEnvelopeResponse ────────────────────────────────

    #[test]
    fn upload_import_envelope_response_roundtrip_with_wallet_id() {
        let resp = UploadImportEnvelopeResponse {
            operation_id: "op-001".into(),
            session_id: "sess-001".into(),
            status: "completed".into(),
            wallet_id: Some("w-999".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: UploadImportEnvelopeResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.operation_id, "op-001");
        assert_eq!(parsed.session_id, "sess-001");
        assert_eq!(parsed.status, "completed");
        assert_eq!(parsed.wallet_id.as_deref(), Some("w-999"));
    }

    #[test]
    fn upload_import_envelope_response_omits_none_wallet_id() {
        let resp = UploadImportEnvelopeResponse {
            operation_id: "op-002".into(),
            session_id: "sess-002".into(),
            status: "pending".into(),
            wallet_id: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("wallet_id"));

        let parsed: UploadImportEnvelopeResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.wallet_id.is_none());
    }

    // ── ChainFamily via Wallet context ──────────────────────────────

    #[test]
    fn wallet_rejects_invalid_chain_family() {
        // ChainFamily does NOT have #[serde(other)] since it's a functional
        // type with methods, so unknown chain families still fail.
        let json = serde_json::to_string(&sample_wallet()).unwrap();
        let bad_json = json.replace("\"evm\"", "\"bitcoin\"");
        let result = serde_json::from_str::<Wallet>(&bad_json);
        assert!(result.is_err());
    }

    // ── Deserialization rejects missing required fields ──────────────

    #[test]
    fn wallet_rejects_missing_required_field() {
        // Missing wallet_id
        let json = r#"{
            "principal_account_id": "acct-abc",
            "chain_family": "evm",
            "status": "active",
            "key_blob_ref": "ref-xyz",
            "key_version": 3,
            "created_at": "2025-06-15T12:00:00Z",
            "updated_at": "2025-06-15T12:00:00Z"
        }"#;
        let result = serde_json::from_str::<Wallet>(json);
        assert!(result.is_err());
    }

    #[test]
    fn import_aad_rejects_missing_required_field() {
        // Missing vault_signer_instance_id
        let json = r#"{
            "principal_account_id": "acct-abc",
            "principal_session_id": "sess-001",
            "request_id": "req-001"
        }"#;
        let result = serde_json::from_str::<ImportAad>(json);
        assert!(result.is_err());
    }
}
