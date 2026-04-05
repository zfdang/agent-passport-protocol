use chrono::{DateTime, Utc};
use kitepass_api_types::passport_policies::{PassportPolicyConfigRecord, PassportPolicyPermit};
use kitepass_api_types::signing::SignIntent;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy has expired")]
    Expired,
    #[error(
        "policy has an invalid time window: issued_at {issued_at} must be before expires_at {expires_at}"
    )]
    InvalidTimeWindow {
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    },
    #[error("policy is not yet active (starts at {starts_at})")]
    NotYetActive { starts_at: DateTime<Utc> },
    #[error("passport mismatch: expected {expected}, got {actual}")]
    PassportMismatch { expected: String, actual: String },
    #[error("wallet mismatch: expected {expected}, got {actual}")]
    WalletMismatch { expected: String, actual: String },
    #[error("policy version mismatch")]
    VersionMismatch,
    #[error("permit has expired")]
    PermitExpired,
    #[error("permit wallet mismatch")]
    PermitWalletMismatch,
    #[error("permit passport mismatch")]
    PermitPassportMismatch,
    #[error("policy config record status is not active: {0}")]
    NotActive(String),
}

/// Validate that a PassportPolicyConfigRecord is currently valid and active.
pub fn validate_policy_config_active(
    record: &PassportPolicyConfigRecord,
    now: &DateTime<Utc>,
) -> Result<(), PolicyError> {
    if record.status != "active" {
        return Err(PolicyError::NotActive(record.status.clone()));
    }
    if record.issued_at >= record.expires_at {
        return Err(PolicyError::InvalidTimeWindow {
            issued_at: record.issued_at,
            expires_at: record.expires_at,
        });
    }
    if *now < record.issued_at {
        return Err(PolicyError::NotYetActive {
            starts_at: record.issued_at,
        });
    }
    if *now > record.expires_at {
        return Err(PolicyError::Expired);
    }
    Ok(())
}

/// Validate that a PassportPolicyConfigRecord matches the given sign intent
/// on the fields that Vault Signer mirrors (passport_id, wallet_id).
pub fn validate_policy_against_intent(
    record: &PassportPolicyConfigRecord,
    intent: &SignIntent,
) -> Result<(), PolicyError> {
    if record.passport_id != intent.passport_id {
        return Err(PolicyError::PassportMismatch {
            expected: record.passport_id.clone(),
            actual: intent.passport_id.clone(),
        });
    }
    if record.wallet_id != intent.wallet_id {
        return Err(PolicyError::WalletMismatch {
            expected: record.wallet_id.clone(),
            actual: intent.wallet_id.clone(),
        });
    }
    Ok(())
}

/// Lightweight check that the permit is still valid for the given intent.
///
/// This validates expiry, wallet_id and passport_id only.  Full field-level
/// validation (chain_id, payload_hash, destination, value, etc.) is performed
/// by the vault-signer when it verifies the cryptographic permit signature.
pub fn validate_permit_basics(
    permit: &PassportPolicyPermit,
    intent: &SignIntent,
    now: &DateTime<Utc>,
) -> Result<(), PolicyError> {
    if *now > permit.expires_at {
        return Err(PolicyError::PermitExpired);
    }
    if permit.wallet_id != intent.wallet_id {
        return Err(PolicyError::PermitWalletMismatch);
    }
    if permit.passport_id != intent.passport_id {
        return Err(PolicyError::PermitPassportMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use kitepass_api_types::signing::SigningMode;

    fn sample_record() -> PassportPolicyConfigRecord {
        let now = Utc::now();
        PassportPolicyConfigRecord {
            record_type: "policy_config_record".into(),
            record_version: 1,
            binding_id: "bind_1".into(),
            passport_id: "agp_1".into(),
            wallet_id: "wal_1".into(),
            public_key: "abcd1234".into(),
            status: "active".into(),
            expires_at: now + Duration::hours(23),
            passport_policy_id: "pol_1".into(),
            passport_policy_version: 1,
            provisioning_intent_id: "pi_1".into(),
            provisioning_intent_hash: "hash_1".into(),
            principal_approval_id: "oa_1".into(),
            principal_approval_hash: "approval_1".into(),
            issued_at: now - Duration::hours(1),
            policy_config_signature: "sig_1".into(),
        }
    }

    fn sample_intent() -> SignIntent {
        SignIntent {
            intent_type: "sign_intent".into(),
            intent_version: 1,
            request_id: "req_1".into(),
            wallet_id: "wal_1".into(),
            passport_id: "agp_1".into(),
            chain_id: "eip155:84532".into(),
            signing_type: "eth_signTransaction".into(),
            payload_hash: "0xdeadbeef".into(),
            destination: "0x1234".into(),
            value: "1000".into(),
            session_nonce: "nonce_1".into(),
            mode: SigningMode::SignatureOnly,
        }
    }

    #[test]
    fn active_policy_passes() {
        let record = sample_record();
        assert!(validate_policy_config_active(&record, &Utc::now()).is_ok());
    }

    #[test]
    fn expired_policy_rejected() {
        let mut record = sample_record();
        record.expires_at = Utc::now() - Duration::hours(1);
        assert!(validate_policy_config_active(&record, &Utc::now()).is_err());
    }

    #[test]
    fn inactive_policy_rejected() {
        let mut record = sample_record();
        record.status = "deactivated".into();
        assert!(validate_policy_config_active(&record, &Utc::now()).is_err());
    }

    #[test]
    fn future_dated_policy_is_not_yet_active() {
        let mut record = sample_record();
        record.issued_at = Utc::now() + Duration::hours(1);
        let err = validate_policy_config_active(&record, &Utc::now()).unwrap_err();
        assert!(matches!(err, PolicyError::NotYetActive { .. }));
    }

    #[test]
    fn invalid_policy_time_window_is_rejected() {
        let mut record = sample_record();
        record.issued_at = Utc::now();
        record.expires_at = record.issued_at;
        let err = validate_policy_config_active(&record, &Utc::now()).unwrap_err();
        assert!(matches!(err, PolicyError::InvalidTimeWindow { .. }));
    }

    #[test]
    fn policy_matches_intent() {
        let record = sample_record();
        let intent = sample_intent();
        assert!(validate_policy_against_intent(&record, &intent).is_ok());
    }

    #[test]
    fn wrong_passport_rejected() {
        let record = sample_record();
        let mut intent = sample_intent();
        intent.passport_id = "agp_wrong".into();
        assert!(validate_policy_against_intent(&record, &intent).is_err());
    }

    fn sample_permit() -> PassportPolicyPermit {
        let now = Utc::now();
        PassportPolicyPermit {
            record_type: "policy_permit".into(),
            record_version: 1,
            permit_id: "permit_1".into(),
            request_id: "req_1".into(),
            wallet_id: "wal_1".into(),
            passport_id: "agp_1".into(),
            chain_id: "eip155:84532".into(),
            signing_type: "eth_signTransaction".into(),
            payload_hash: "0xdeadbeef".into(),
            destination: "0x1234".into(),
            value: "1000".into(),
            reservation_id: "res_1".into(),
            passport_policy_id: "pol_1".into(),
            passport_policy_version: 1,
            issued_at: now,
            expires_at: now + Duration::hours(1),
            signature: "sig_permit".into(),
        }
    }

    #[test]
    fn valid_permit_passes() {
        let permit = sample_permit();
        let intent = sample_intent();
        assert!(validate_permit_basics(&permit, &intent, &Utc::now()).is_ok());
    }

    #[test]
    fn expired_permit_rejected() {
        let mut permit = sample_permit();
        permit.expires_at = Utc::now() - Duration::hours(1);
        let intent = sample_intent();
        let err = validate_permit_basics(&permit, &intent, &Utc::now()).unwrap_err();
        assert!(matches!(err, PolicyError::PermitExpired));
    }

    #[test]
    fn permit_wallet_mismatch_rejected() {
        let mut permit = sample_permit();
        permit.wallet_id = "wal_wrong".into();
        let intent = sample_intent();
        let err = validate_permit_basics(&permit, &intent, &Utc::now()).unwrap_err();
        assert!(matches!(err, PolicyError::PermitWalletMismatch));
    }

    #[test]
    fn permit_passport_mismatch_rejected() {
        let mut permit = sample_permit();
        permit.passport_id = "agp_wrong".into();
        let intent = sample_intent();
        let err = validate_permit_basics(&permit, &intent, &Utc::now()).unwrap_err();
        assert!(matches!(err, PolicyError::PermitPassportMismatch));
    }
}
