use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// TEE attestation verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    pub valid: bool,
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub instance_id: String,
}

/// Expected measurement profile for a reviewed Vault Signer build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementProfile {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("attestation document parsing failed: {0}")]
    ParseError(String),
    #[error("attestation document marked invalid")]
    InvalidDocument,
    #[error("PCR0 mismatch: expected {expected}, got {actual}")]
    Pcr0Mismatch { expected: String, actual: String },
    #[error("PCR1 mismatch: expected {expected}, got {actual}")]
    Pcr1Mismatch { expected: String, actual: String },
    #[error("PCR2 mismatch: expected {expected}, got {actual}")]
    Pcr2Mismatch { expected: String, actual: String },
    #[error("instance ID mismatch")]
    InstanceIdMismatch,
    #[error("attestation expired")]
    Expired,
}

/// Verify that an attestation result matches the expected measurement profile.
pub fn verify_measurements(
    result: &AttestationResult,
    profile: &MeasurementProfile,
) -> Result<(), AttestationError> {
    if !result.valid {
        return Err(AttestationError::InvalidDocument);
    }
    if !bool::from(result.pcr0.as_bytes().ct_eq(profile.pcr0.as_bytes())) {
        return Err(AttestationError::Pcr0Mismatch {
            expected: profile.pcr0.clone(),
            actual: result.pcr0.clone(),
        });
    }
    if !bool::from(result.pcr1.as_bytes().ct_eq(profile.pcr1.as_bytes())) {
        return Err(AttestationError::Pcr1Mismatch {
            expected: profile.pcr1.clone(),
            actual: result.pcr1.clone(),
        });
    }
    if !bool::from(result.pcr2.as_bytes().ct_eq(profile.pcr2.as_bytes())) {
        return Err(AttestationError::Pcr2Mismatch {
            expected: profile.pcr2.clone(),
            actual: result.pcr2.clone(),
        });
    }
    Ok(())
}

/// Parse an attestation document from JSON string.
pub fn parse_attestation(json: &str) -> Result<AttestationResult, AttestationError> {
    serde_json::from_str(json).map_err(|e| AttestationError::ParseError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_measurements_pass() {
        let result = AttestationResult {
            valid: true,
            pcr0: "abc123".into(),
            pcr1: "def456".into(),
            pcr2: "ghi789".into(),
            instance_id: "i-12345".into(),
        };
        let profile = MeasurementProfile {
            pcr0: "abc123".into(),
            pcr1: "def456".into(),
            pcr2: "ghi789".into(),
        };
        assert!(verify_measurements(&result, &profile).is_ok());
    }

    #[test]
    fn mismatched_pcr0_fails() {
        let result = AttestationResult {
            valid: true,
            pcr0: "wrong".into(),
            pcr1: "def456".into(),
            pcr2: "ghi789".into(),
            instance_id: "i-12345".into(),
        };
        let profile = MeasurementProfile {
            pcr0: "abc123".into(),
            pcr1: "def456".into(),
            pcr2: "ghi789".into(),
        };
        assert!(verify_measurements(&result, &profile).is_err());
    }

    #[test]
    fn invalid_flag_fails_even_when_pcrs_match() {
        let result = AttestationResult {
            valid: false,
            pcr0: "abc123".into(),
            pcr1: "def456".into(),
            pcr2: "ghi789".into(),
            instance_id: "i-12345".into(),
        };
        let profile = MeasurementProfile {
            pcr0: "abc123".into(),
            pcr1: "def456".into(),
            pcr2: "ghi789".into(),
        };
        let err = verify_measurements(&result, &profile).unwrap_err();
        assert!(matches!(err, AttestationError::InvalidDocument));
    }

    #[test]
    fn parse_valid_json() {
        let json = r#"{"valid":true,"pcr0":"a","pcr1":"b","pcr2":"c","instance_id":"i-1"}"#;
        let result = parse_attestation(json).unwrap();
        assert!(result.valid);
        assert_eq!(result.pcr0, "a");
    }
}
