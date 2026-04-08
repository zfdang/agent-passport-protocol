//! P-384 ECDH + AES-256-GCM encryption targeting a Capsule runtime's public key.
//!
//! This is the client-side encryption used when importing wallet secrets.
//! The Capsule runtime holds the P-384 private key; only it can decrypt via
//! `/v1/encryption/decrypt`. The attestation proves the public key belongs
//! to a specific enclave instance.
//!
//! Wire format matches the Capsule `CapsuleSealedBlob`:
//! ```json
//! {
//!   "scheme": "capsule_p384_ecdh_aes256gcm_v1",
//!   "client_public_key_der_hex": "0x...",
//!   "nonce_hex": "0x...",
//!   "encrypted_data_hex": "0x...",
//!   "encryption_public_key_der_hex": "0x..."
//! }
//! ```

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hkdf::Hkdf;
use p384::{
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    PublicKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Import encryption scheme identifier.
pub const IMPORT_ENCRYPTION_SCHEME: &str = "capsule_p384_ecdh_aes256gcm_v1";

const ECDH_INFO: &[u8] = b"capsule-ecdh-aes256gcm-v1";
const NONCE_LEN: usize = 12;

#[derive(Error, Debug)]
pub enum CapsuleEncryptError {
    #[error("invalid enclave public key: {0}")]
    InvalidPublicKey(String),
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("serialization failed: {0}")]
    Serialization(String),
}

/// Sealed envelope matching the Capsule decrypt API format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleSealedEnvelope {
    pub scheme: String,
    pub client_public_key_der_hex: String,
    pub nonce_hex: String,
    pub encrypted_data_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_public_key_der_hex: Option<String>,
}

/// Encrypt data to a Capsule runtime's P-384 public key.
///
/// - `enclave_public_key_der_hex`: hex-encoded P-384 public key in DER format (from `/v1/encryption/public_key`)
/// - `aad`: additional authenticated data (e.g., channel binding JSON)
/// - `plaintext`: data to encrypt (e.g., wallet secret bytes)
///
/// Returns a `CapsuleSealedEnvelope` that can be sent to Capsule's `/v1/encryption/decrypt`.
pub fn encrypt_to_capsule(
    enclave_public_key_der_hex: &str,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<CapsuleSealedEnvelope, CapsuleEncryptError> {
    let der_hex = strip_0x_prefix(enclave_public_key_der_hex);
    let enclave_public_der =
        hex::decode(der_hex).map_err(|e| CapsuleEncryptError::InvalidPublicKey(e.to_string()))?;
    let enclave_public = PublicKey::from_public_key_der(&enclave_public_der)
        .map_err(|e| CapsuleEncryptError::InvalidPublicKey(e.to_string()))?;
    let enclave_public_sec1 = enclave_public.to_encoded_point(false);

    // Generate ephemeral P-384 keypair
    let client_secret = EphemeralSecret::random(&mut OsRng);
    let client_public = PublicKey::from(&client_secret);
    let client_public_sec1 = client_public.to_encoded_point(false);
    let client_public_der = client_public
        .to_public_key_der()
        .map_err(|e| CapsuleEncryptError::InvalidPublicKey(e.to_string()))?;

    // ECDH shared secret
    let shared_secret = client_secret.diffie_hellman(&enclave_public);

    // Generate random nonce
    let nonce_bytes: [u8; NONCE_LEN] = {
        use rand::RngCore;
        let mut buf = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut buf);
        buf
    };

    // Derive AES key via HKDF
    let aes_key = derive_aes_key(
        client_public_sec1.as_bytes(),
        enclave_public_sec1.as_bytes(),
        shared_secret.raw_secret_bytes().as_ref(),
        &nonce_bytes,
    )?;

    // Build plaintext envelope (Capsule expects this format)
    let envelope_json = serde_json::to_string(&PlaintextEnvelope {
        aad_sha256_hex: aad_sha256_hex(aad),
        plaintext_b64: STANDARD.encode(plaintext),
    })
    .map_err(|e| CapsuleEncryptError::Serialization(e.to_string()))?;

    // AES-256-GCM encrypt
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|_| CapsuleEncryptError::EncryptionFailed)?;
    let encrypted_data = cipher
        .encrypt((&nonce_bytes[..]).into(), envelope_json.as_bytes())
        .map_err(|_| CapsuleEncryptError::EncryptionFailed)?;

    Ok(CapsuleSealedEnvelope {
        scheme: IMPORT_ENCRYPTION_SCHEME.to_string(),
        client_public_key_der_hex: prefixed_hex(client_public_der.as_bytes()),
        nonce_hex: prefixed_hex(&nonce_bytes),
        encrypted_data_hex: prefixed_hex(&encrypted_data),
        encryption_public_key_der_hex: Some(prefixed_hex(&enclave_public_der)),
    })
}

#[derive(Serialize, Deserialize)]
struct PlaintextEnvelope {
    aad_sha256_hex: String,
    plaintext_b64: String,
}

fn aad_sha256_hex(aad: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(aad)))
}

fn derive_aes_key(
    client_public_sec1: &[u8],
    enclave_public_sec1: &[u8],
    shared_secret: &[u8],
    nonce: &[u8],
) -> Result<[u8; 32], CapsuleEncryptError> {
    let (left, right) = if client_public_sec1 <= enclave_public_sec1 {
        (client_public_sec1, enclave_public_sec1)
    } else {
        (enclave_public_sec1, client_public_sec1)
    };
    let mut salt = Vec::with_capacity(left.len() + right.len() + nonce.len());
    salt.extend_from_slice(left);
    salt.extend_from_slice(right);
    salt.extend_from_slice(nonce);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut aes_key = [0u8; 32];
    hkdf.expand(ECDH_INFO, &mut aes_key)
        .map_err(|_| CapsuleEncryptError::KeyDerivation)?;
    Ok(aes_key)
}

fn strip_0x_prefix(hex_str: &str) -> &str {
    hex_str
        .strip_prefix("0x")
        .or_else(|| hex_str.strip_prefix("0X"))
        .unwrap_or(hex_str)
}

fn prefixed_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(data))
}

/// Generate a random P-384 keypair for testing. Returns (private_key_der_hex, public_key_der_hex).
/// Available in all builds so integration tests across repos can use it.
pub fn generate_test_p384_keypair() -> (String, String) {
    use p384::SecretKey;
    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();
    let pub_der = public_key.to_public_key_der().expect("P-384 DER encoding");
    let priv_der = secret_key.to_pkcs8_der().expect("P-384 PKCS8 DER encoding");
    (
        format!("0x{}", hex::encode(priv_der.as_bytes())),
        format!("0x{}", hex::encode(pub_der.as_bytes())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_produces_valid_envelope_structure() {
        // Use a test P-384 keypair
        use p384::SecretKey;
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();
        let pub_der = public_key.to_public_key_der().unwrap();
        let pub_hex = format!("0x{}", hex::encode(pub_der.as_bytes()));

        let aad = b"test-aad";
        let plaintext = b"wallet-secret-hex";
        let envelope = encrypt_to_capsule(&pub_hex, aad, plaintext).unwrap();

        assert_eq!(envelope.scheme, IMPORT_ENCRYPTION_SCHEME);
        assert!(envelope.client_public_key_der_hex.starts_with("0x"));
        assert!(envelope.nonce_hex.starts_with("0x"));
        assert!(envelope.encrypted_data_hex.starts_with("0x"));
        assert!(envelope.encryption_public_key_der_hex.is_some());
    }

    #[test]
    fn envelope_serializes_to_json() {
        use p384::SecretKey;
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();
        let pub_der = public_key.to_public_key_der().unwrap();
        let pub_hex = format!("0x{}", hex::encode(pub_der.as_bytes()));

        let envelope = encrypt_to_capsule(&pub_hex, b"aad", b"data").unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("capsule_p384_ecdh_aes256gcm_v1"));
        assert!(json.contains("client_public_key_der_hex"));
        assert!(json.contains("nonce_hex"));
        assert!(json.contains("encrypted_data_hex"));
    }

    #[test]
    fn different_nonce_each_time() {
        use p384::SecretKey;
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();
        let pub_der = public_key.to_public_key_der().unwrap();
        let pub_hex = format!("0x{}", hex::encode(pub_der.as_bytes()));

        let e1 = encrypt_to_capsule(&pub_hex, b"aad", b"data").unwrap();
        let e2 = encrypt_to_capsule(&pub_hex, b"aad", b"data").unwrap();
        assert_ne!(e1.nonce_hex, e2.nonce_hex);
        assert_ne!(e1.encrypted_data_hex, e2.encrypted_data_hex);
    }

    #[test]
    fn invalid_public_key_returns_error() {
        let result = encrypt_to_capsule("0xdeadbeef", b"aad", b"data");
        assert!(result.is_err());
    }

    #[test]
    fn empty_plaintext_encrypts() {
        use p384::SecretKey;
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();
        let pub_der = public_key.to_public_key_der().unwrap();
        let pub_hex = format!("0x{}", hex::encode(pub_der.as_bytes()));

        let envelope = encrypt_to_capsule(&pub_hex, b"aad", b"").unwrap();
        assert!(!envelope.encrypted_data_hex.is_empty());
    }
}
