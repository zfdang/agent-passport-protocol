use crate::canonical;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_DEV_SIGNING_PRIVATE_KEY_HEX: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("key material was not valid hex")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("key material had invalid length")]
    InvalidLength,
    #[error("payload serialization failed: {0}")]
    Serialization(String),
    #[error("signature was invalid")]
    InvalidSignature,
}

#[derive(Serialize)]
struct DomainMessage<'a, T> {
    purpose: &'a str,
    payload: &'a T,
}

fn signing_key_from_hex(private_key_hex: &str) -> Result<SigningKey, SignatureError> {
    let private_key = Zeroizing::new(hex::decode(private_key_hex)?);
    let mut key_bytes = [0u8; 32];
    if private_key.len() != key_bytes.len() {
        return Err(SignatureError::InvalidLength);
    }
    key_bytes.copy_from_slice(private_key.as_slice());
    let signing_key = SigningKey::from_bytes(&key_bytes);
    key_bytes.zeroize();
    Ok(signing_key)
}

fn verifying_key_from_hex(public_key_hex: &str) -> Result<VerifyingKey, SignatureError> {
    let public_key = hex::decode(public_key_hex)?;
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| SignatureError::InvalidLength)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| SignatureError::InvalidLength)
}

fn signature_from_hex(signature_hex: &str) -> Result<Signature, SignatureError> {
    let signature = hex::decode(signature_hex.trim_start_matches("0x"))?;
    Signature::from_slice(&signature).map_err(|_| SignatureError::InvalidLength)
}

pub fn public_key_hex_from_private_key_hex(
    private_key_hex: &str,
) -> Result<String, SignatureError> {
    Ok(hex::encode(
        signing_key_from_hex(private_key_hex)?
            .verifying_key()
            .as_bytes(),
    ))
}

pub fn domain_message(purpose: &str, payload: &impl Serialize) -> Result<Vec<u8>, SignatureError> {
    canonical::to_vec(&DomainMessage { purpose, payload })
        .map_err(|error| SignatureError::Serialization(error.to_string()))
}

pub fn sign_domain_message(
    private_key_hex: &str,
    purpose: &str,
    payload: &impl Serialize,
) -> Result<String, SignatureError> {
    let message = domain_message(purpose, payload)?;
    let signing_key = signing_key_from_hex(private_key_hex)?;
    Ok(format!(
        "0x{}",
        hex::encode(signing_key.sign(&message).to_bytes())
    ))
}

pub fn verify_domain_message(
    public_key_hex: &str,
    purpose: &str,
    payload: &impl Serialize,
    signature_hex: &str,
) -> Result<(), SignatureError> {
    let message = domain_message(purpose, payload)?;
    let public_key = verifying_key_from_hex(public_key_hex)?;
    let signature = signature_from_hex(signature_hex)?;
    public_key
        .verify(&message, &signature)
        .map_err(|_| SignatureError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct SamplePayload<'a> {
        value: &'a str,
    }

    #[test]
    fn public_key_derives_from_private_key() {
        let public_key =
            public_key_hex_from_private_key_hex(DEFAULT_DEV_SIGNING_PRIVATE_KEY_HEX).unwrap();
        assert_eq!(public_key.len(), 64);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let public_key =
            public_key_hex_from_private_key_hex(DEFAULT_DEV_SIGNING_PRIVATE_KEY_HEX).unwrap();
        let payload = SamplePayload { value: "hello" };
        let signature =
            sign_domain_message(DEFAULT_DEV_SIGNING_PRIVATE_KEY_HEX, "sample", &payload).unwrap();
        verify_domain_message(&public_key, "sample", &payload, &signature).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let public_key =
            public_key_hex_from_private_key_hex(DEFAULT_DEV_SIGNING_PRIVATE_KEY_HEX).unwrap();
        let signature = sign_domain_message(
            DEFAULT_DEV_SIGNING_PRIVATE_KEY_HEX,
            "sample",
            &SamplePayload { value: "hello" },
        )
        .unwrap();
        let result = verify_domain_message(
            &public_key,
            "sample",
            &SamplePayload { value: "goodbye" },
            &signature,
        );
        assert!(matches!(result, Err(SignatureError::InvalidSignature)));
    }
}
