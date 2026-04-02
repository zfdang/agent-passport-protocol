use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Wallet metadata (control-plane view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub wallet_id: String,
    pub owner_id: String,
    pub chain_family: String,
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
    pub chain_family: String,
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
    pub owner_id: String,
    pub owner_session_id: String,
    pub request_id: String,
}

/// Request to upload encrypted wallet secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadImportEnvelopeRequest {
    pub vault_signer_instance_id: String,
    pub encapsulated_key: String,
    pub ciphertext: String,
    pub aad: ImportAad,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportAad {
    pub owner_id: String,
    pub owner_session_id: String,
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
