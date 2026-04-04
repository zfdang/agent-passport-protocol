use crate::{canonical, signatures::strip_optional_0x_prefix};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("invalid public key encoding")]
    InvalidPublicKey,
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("failed to serialize canonical signing payload")]
    CanonicalSerialization,
    #[error("signature did not verify")]
    SignatureMismatch,
}

#[derive(Debug, Serialize)]
struct CanonicalAgentIntent<'a> {
    #[serde(rename = "type")]
    intent_type: &'a str,
    #[serde(rename = "version")]
    intent_version: u32,
    request_id: &'a str,
    wallet_id: &'a str,
    agent_passport_id: &'a str,
    chain_id: &'a str,
    signing_type: &'a str,
    payload_hash: &'a str,
    destination: &'a str,
    value: &'a str,
    session_nonce: &'a str,
    mode: &'a str,
}

#[derive(Debug, Serialize)]
struct CanonicalValidateIntent<'a> {
    #[serde(rename = "type")]
    intent_type: &'a str,
    #[serde(rename = "version")]
    intent_version: u32,
    request_id: &'a str,
    agent_passport_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_selector: Option<&'a str>,
    chain_id: &'a str,
    signing_type: &'a str,
    payload_hash: &'a str,
    destination: &'a str,
    value: &'a str,
}

#[derive(Debug, Serialize)]
struct CanonicalSessionCreateIntent<'a> {
    #[serde(rename = "type")]
    intent_type: &'a str,
    #[serde(rename = "version")]
    intent_version: u32,
    request_id: &'a str,
    agent_passport_id: &'a str,
    challenge_id: &'a str,
    challenge_nonce: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct CanonicalAgentMessageArgs<'a> {
    pub request_id: &'a str,
    pub wallet_id: &'a str,
    pub agent_passport_id: &'a str,
    pub chain_id: &'a str,
    pub signing_type: &'a str,
    pub payload_hash: &'a str,
    pub destination: &'a str,
    pub value: &'a str,
    pub session_nonce: &'a str,
    pub mode: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyAgentProofArgs<'a> {
    pub public_key_hex: &'a str,
    pub signature_hex: &'a str,
    pub intent: CanonicalAgentMessageArgs<'a>,
}

#[derive(Debug, Clone, Copy)]
pub struct CanonicalValidateIntentArgs<'a> {
    pub request_id: &'a str,
    pub agent_passport_id: &'a str,
    pub wallet_id: Option<&'a str>,
    pub wallet_selector: Option<&'a str>,
    pub chain_id: &'a str,
    pub signing_type: &'a str,
    pub payload_hash: &'a str,
    pub destination: &'a str,
    pub value: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyValidateIntentProofArgs<'a> {
    pub public_key_hex: &'a str,
    pub signature_hex: &'a str,
    pub intent: CanonicalValidateIntentArgs<'a>,
}

#[derive(Debug, Clone, Copy)]
pub struct CanonicalSessionCreateArgs<'a> {
    pub request_id: &'a str,
    pub agent_passport_id: &'a str,
    pub challenge_id: &'a str,
    pub challenge_nonce: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifySessionCreateProofArgs<'a> {
    pub public_key_hex: &'a str,
    pub signature_hex: &'a str,
    pub intent: CanonicalSessionCreateArgs<'a>,
}

/// Returns the canonical SHA-256 payload hash used in agent proof messages.
pub fn payload_hash_hex(payload: &str) -> String {
    format!("0x{}", hex::encode(Sha256::digest(payload.as_bytes())))
}

fn verifying_key_from_hex(public_key_hex: &str) -> Result<VerifyingKey, VerificationError> {
    let public_key_bytes = hex::decode(strip_optional_0x_prefix(public_key_hex))
        .map_err(|_| VerificationError::InvalidPublicKey)?;
    let public_key_bytes: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| VerificationError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| VerificationError::InvalidPublicKey)
}

fn signature_from_hex(signature_hex: &str) -> Result<Signature, VerificationError> {
    let signature_bytes = hex::decode(strip_optional_0x_prefix(signature_hex))
        .map_err(|_| VerificationError::InvalidSignature)?;
    Signature::from_slice(&signature_bytes).map_err(|_| VerificationError::InvalidSignature)
}

fn verify_message(
    public_key_hex: &str,
    signature_hex: &str,
    message: &[u8],
) -> Result<(), VerificationError> {
    let verifying_key = verifying_key_from_hex(public_key_hex)?;
    let signature = signature_from_hex(signature_hex)?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| VerificationError::SignatureMismatch)
}

pub fn canonical_agent_message(
    args: &CanonicalAgentMessageArgs<'_>,
) -> Result<Vec<u8>, VerificationError> {
    canonical::to_vec(&CanonicalAgentIntent {
        intent_type: "sign_intent",
        intent_version: 1,
        request_id: args.request_id,
        wallet_id: args.wallet_id,
        agent_passport_id: args.agent_passport_id,
        chain_id: args.chain_id,
        signing_type: args.signing_type,
        payload_hash: args.payload_hash,
        destination: args.destination,
        value: args.value,
        session_nonce: args.session_nonce,
        mode: args.mode,
    })
    .map_err(|_| VerificationError::CanonicalSerialization)
}

pub fn canonical_validate_intent_message(
    args: &CanonicalValidateIntentArgs<'_>,
) -> Result<Vec<u8>, VerificationError> {
    canonical::to_vec(&CanonicalValidateIntent {
        intent_type: "validate_sign_intent",
        intent_version: 1,
        request_id: args.request_id,
        agent_passport_id: args.agent_passport_id,
        wallet_id: args.wallet_id,
        wallet_selector: args.wallet_selector,
        chain_id: args.chain_id,
        signing_type: args.signing_type,
        payload_hash: args.payload_hash,
        destination: args.destination,
        value: args.value,
    })
    .map_err(|_| VerificationError::CanonicalSerialization)
}

pub fn canonical_session_create_message(
    args: &CanonicalSessionCreateArgs<'_>,
) -> Result<Vec<u8>, VerificationError> {
    canonical::to_vec(&CanonicalSessionCreateIntent {
        intent_type: "create_session",
        intent_version: 1,
        request_id: args.request_id,
        agent_passport_id: args.agent_passport_id,
        challenge_id: args.challenge_id,
        challenge_nonce: args.challenge_nonce,
    })
    .map_err(|_| VerificationError::CanonicalSerialization)
}

pub fn verify_agent_proof(args: &VerifyAgentProofArgs<'_>) -> Result<(), VerificationError> {
    let message = canonical_agent_message(&args.intent)?;
    verify_message(args.public_key_hex, args.signature_hex, &message)
}

pub fn verify_validate_intent_proof(
    args: &VerifyValidateIntentProofArgs<'_>,
) -> Result<(), VerificationError> {
    let message = canonical_validate_intent_message(&args.intent)?;
    verify_message(args.public_key_hex, args.signature_hex, &message)
}

pub fn verify_session_create_proof(
    args: &VerifySessionCreateProofArgs<'_>,
) -> Result<(), VerificationError> {
    let message = canonical_session_create_message(&args.intent)?;
    verify_message(args.public_key_hex, args.signature_hex, &message)
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_agent_message, canonical_session_create_message,
        canonical_validate_intent_message, payload_hash_hex, verify_agent_proof,
        verify_session_create_proof, verify_validate_intent_proof, CanonicalAgentMessageArgs,
        CanonicalSessionCreateArgs, CanonicalValidateIntentArgs, VerifyAgentProofArgs,
        VerifySessionCreateProofArgs, VerifyValidateIntentProofArgs,
    };
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn payload_hash_matches_cli_format() {
        assert_eq!(
            payload_hash_hex("0xdeadbeef"),
            "0x4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583"
        );
    }

    #[test]
    fn verify_agent_proof_accepts_matching_signature() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let payload_hash = payload_hash_hex("0xdeadbeef");
        let intent = CanonicalAgentMessageArgs {
            request_id: "req_123",
            wallet_id: "wal_123",
            agent_passport_id: "agp_123",
            chain_id: "eip155:8453",
            signing_type: "transaction",
            payload_hash: &payload_hash,
            destination: "0xabc",
            value: "10",
            session_nonce: "nonce_123",
            mode: "sign_and_submit",
        };
        let message = canonical_agent_message(&intent).expect("canonical message");
        let signature_hex = format!("0x{}", hex::encode(signing_key.sign(&message).to_bytes()));

        verify_agent_proof(&VerifyAgentProofArgs {
            public_key_hex: &public_key_hex,
            signature_hex: &signature_hex,
            intent,
        })
        .expect("signature should verify");
    }

    #[test]
    fn verify_agent_proof_rejects_tampered_payload_hash() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let payload_hash = payload_hash_hex("0xdeadbeef");
        let message = canonical_agent_message(&CanonicalAgentMessageArgs {
            request_id: "req_123",
            wallet_id: "wal_123",
            agent_passport_id: "agp_123",
            chain_id: "eip155:8453",
            signing_type: "transaction",
            payload_hash: &payload_hash,
            destination: "0xabc",
            value: "10",
            session_nonce: "nonce_123",
            mode: "signature_only",
        })
        .expect("canonical message");
        let signature_hex = format!("0x{}", hex::encode(signing_key.sign(&message).to_bytes()));

        let err = verify_agent_proof(&VerifyAgentProofArgs {
            public_key_hex: &public_key_hex,
            signature_hex: &signature_hex,
            intent: CanonicalAgentMessageArgs {
                request_id: "req_123",
                wallet_id: "wal_123",
                agent_passport_id: "agp_123",
                chain_id: "eip155:8453",
                signing_type: "transaction",
                payload_hash: &payload_hash_hex("0xfeedface"),
                destination: "0xabc",
                value: "10",
                session_nonce: "nonce_123",
                mode: "signature_only",
            },
        })
        .expect_err("tampered payload hash should fail");
        assert!(matches!(err, super::VerificationError::SignatureMismatch));
    }

    #[test]
    fn verify_validate_intent_proof_accepts_matching_signature() {
        let signing_key = SigningKey::from_bytes(&[5u8; 32]);
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let payload_hash = payload_hash_hex("0xdeadbeef");
        let intent = CanonicalValidateIntentArgs {
            request_id: "req_validate_123",
            agent_passport_id: "agp_123",
            wallet_id: Some("wal_123"),
            wallet_selector: None,
            chain_id: "eip155:8453",
            signing_type: "transaction",
            payload_hash: &payload_hash,
            destination: "0xabc",
            value: "10",
        };
        let message = canonical_validate_intent_message(&intent).expect("canonical message");
        let signature_hex = format!("0x{}", hex::encode(signing_key.sign(&message).to_bytes()));

        verify_validate_intent_proof(&VerifyValidateIntentProofArgs {
            public_key_hex: &public_key_hex,
            signature_hex: &signature_hex,
            intent,
        })
        .expect("signature should verify");
    }

    #[test]
    fn verify_session_create_proof_accepts_matching_signature() {
        let signing_key = SigningKey::from_bytes(&[6u8; 32]);
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let intent = CanonicalSessionCreateArgs {
            request_id: "req_session_123",
            agent_passport_id: "agp_123",
            challenge_id: "sch_123",
            challenge_nonce: "nonce_123",
        };
        let message = canonical_session_create_message(&intent).expect("canonical message");
        let signature_hex = format!("0x{}", hex::encode(signing_key.sign(&message).to_bytes()));

        verify_session_create_proof(&VerifySessionCreateProofArgs {
            public_key_hex: &public_key_hex,
            signature_hex: &signature_hex,
            intent,
        })
        .expect("signature should verify");
    }
}
