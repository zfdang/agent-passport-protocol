use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

// ── Errors ──────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid Agent Passport Token format")]
    InvalidTokenFormat,
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("Unsupported cipher: {0}")]
    UnsupportedCipher(String),
    #[error("Unsupported KDF: {0}")]
    UnsupportedKdf(String),
    #[error("Key derivation failed during {0}")]
    KeyDerivationFailed(&'static str),
}

// ── Agent Passport Token ──────────────────────────────────────

const TOKEN_PREFIX: &str = "kite_apt_";
const TOKEN_DELIMITER: &str = "__";
const MAX_AGENT_PASSPORT_ID_LEN: usize = 255;

/// Parsed representation of `kite_apt_<agent_passport_id>__<secret_key>`.
#[derive(Debug, Clone)]
pub struct AgentPassportToken {
    pub agent_passport_id: String,
    pub secret_key: Zeroizing<String>,
}

impl AgentPassportToken {
    /// Parses a Agent Passport Token string.
    ///
    /// Format: `kite_apt_<agent_passport_id>__<secret_key>`
    /// where `agent_passport_id` starts with `agp_`.
    pub fn parse(token: &str) -> Result<Self, EncryptionError> {
        let rest = token
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(EncryptionError::InvalidTokenFormat)?;

        let (agent_passport_id, secret_key) = rest
            .split_once(TOKEN_DELIMITER)
            .ok_or(EncryptionError::InvalidTokenFormat)?;

        if !agent_passport_id.starts_with("agp_")
            || agent_passport_id.len() < 5
            || agent_passport_id.len() > MAX_AGENT_PASSPORT_ID_LEN
        {
            return Err(EncryptionError::InvalidTokenFormat);
        }

        // Secret key must be 64 hex characters (32 bytes).
        if secret_key.len() != 64 || !secret_key.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(EncryptionError::InvalidTokenFormat);
        }

        Ok(Self {
            agent_passport_id: agent_passport_id.to_string(),
            secret_key: Zeroizing::new(secret_key.to_string()),
        })
    }

    /// Formats a Agent Passport Token from its components.
    pub fn format(agent_passport_id: &str, secret_key: &str) -> String {
        format!("{TOKEN_PREFIX}{agent_passport_id}{TOKEN_DELIMITER}{secret_key}")
    }
}

// ── CryptoEnvelope ──────────────────────────────────────

const CIPHER_AES256GCM: &str = "aes-256-gcm";
const KDF_HKDF_SHA256: &str = "hkdf-sha256";

/// Encrypted private key stored inline in `agents.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoEnvelope {
    pub cipher: String,
    pub kdf: String,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl CryptoEnvelope {
    /// Encrypts a private key (PEM bytes) using the secret from a Agent Passport Token.
    ///
    /// Uses HKDF-SHA256 for key derivation and AES-256-GCM for encryption.
    pub fn encrypt(plaintext: &[u8], secret_key: &str) -> Result<Self, EncryptionError> {
        // Generate random salt (32 bytes)
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        // Derive 256-bit AES key from secret_key + salt via HKDF
        let hk = Hkdf::<Sha256>::new(Some(&salt), secret_key.as_bytes());
        let mut aes_key = Zeroizing::new([0u8; 32]);
        hk.expand(b"kitepass-agent-key-encryption", aes_key.as_mut())
            .map_err(|_| EncryptionError::KeyDerivationFailed("encryption"))?;

        // Generate random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = Aes256Gcm::new(aes_key.as_ref().into());
        let gcm_nonce = GcmNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(gcm_nonce, plaintext)
            .map_err(|_| EncryptionError::EncryptionFailed)?;

        Ok(Self {
            cipher: CIPHER_AES256GCM.to_string(),
            kdf: KDF_HKDF_SHA256.to_string(),
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce_bytes),
            ciphertext: BASE64.encode(ciphertext),
        })
    }

    /// Decrypts the envelope using the secret from a Agent Passport Token.
    pub fn decrypt(&self, secret_key: &str) -> Result<Zeroizing<Vec<u8>>, EncryptionError> {
        if self.cipher != CIPHER_AES256GCM {
            return Err(EncryptionError::UnsupportedCipher(self.cipher.clone()));
        }
        if self.kdf != KDF_HKDF_SHA256 {
            return Err(EncryptionError::UnsupportedKdf(self.kdf.clone()));
        }

        let salt = BASE64.decode(&self.salt)?;
        let nonce_bytes = BASE64.decode(&self.nonce)?;
        let ciphertext = BASE64.decode(&self.ciphertext)?;
        if nonce_bytes.len() != 12 {
            return Err(EncryptionError::DecryptionFailed);
        }

        // Derive key
        let hk = Hkdf::<Sha256>::new(Some(&salt), secret_key.as_bytes());
        let mut aes_key = Zeroizing::new([0u8; 32]);
        hk.expand(b"kitepass-agent-key-encryption", aes_key.as_mut())
            .map_err(|_| EncryptionError::KeyDerivationFailed("decryption"))?;

        let cipher = Aes256Gcm::new(aes_key.as_ref().into());
        let gcm_nonce = GcmNonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(gcm_nonce, ciphertext.as_ref())
            .map_err(|_| EncryptionError::DecryptionFailed)?;

        Ok(Zeroizing::new(plaintext))
    }
}

/// Generates a random secret key for Agent Passport Token (32 bytes, hex-encoded → 64 chars).
pub fn generate_secret_key() -> Zeroizing<String> {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let hex_secret = Zeroizing::new(hex::encode(secret));
    // Zeroize the raw bytes
    secret.iter_mut().for_each(|b| *b = 0);
    hex_secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_passport_token_round_trip() {
        let secret = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let formatted = AgentPassportToken::format("agp_abc123", secret);
        assert_eq!(
            formatted,
            "kite_apt_agp_abc123__a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        );

        let parsed = AgentPassportToken::parse(&formatted).unwrap();
        assert_eq!(parsed.agent_passport_id, "agp_abc123");
        assert_eq!(*parsed.secret_key, secret);
    }

    #[test]
    fn agent_passport_token_rejects_invalid_prefix() {
        assert!(AgentPassportToken::parse("bad_prefix_agp_123_secret").is_err());
    }

    #[test]
    fn agent_passport_token_rejects_missing_agp_prefix() {
        assert!(AgentPassportToken::parse("kite_apt_xyz_123_secret").is_err());
    }

    #[test]
    fn agent_passport_token_rejects_empty_secret() {
        assert!(AgentPassportToken::parse("kite_apt_agp_abc__").is_err());
    }

    #[test]
    fn agent_passport_token_supports_agent_passport_ids_with_additional_underscores() {
        let secret = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let formatted = AgentPassportToken::format("agp_alpha_beta", secret);
        let parsed = AgentPassportToken::parse(&formatted).unwrap();
        assert_eq!(parsed.agent_passport_id, "agp_alpha_beta");
        assert_eq!(*parsed.secret_key, secret);
    }

    #[test]
    fn agent_passport_token_rejects_overlong_agent_passport_ids() {
        let secret = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let agent_passport_id = format!("agp_{}", "x".repeat(MAX_AGENT_PASSPORT_ID_LEN));
        let formatted = AgentPassportToken::format(&agent_passport_id, secret);
        assert!(matches!(
            AgentPassportToken::parse(&formatted),
            Err(EncryptionError::InvalidTokenFormat)
        ));
    }

    #[test]
    fn crypto_envelope_encrypt_decrypt_round_trip() {
        let plaintext =
            b"-----BEGIN PRIVATE KEY-----\nfake pem data for testing\n-----END PRIVATE KEY-----";
        let secret = "test_secret_key_for_unit_test";

        let envelope = CryptoEnvelope::encrypt(plaintext, secret).unwrap();
        assert_eq!(envelope.cipher, "aes-256-gcm");
        assert_eq!(envelope.kdf, "hkdf-sha256");

        let decrypted = envelope.decrypt(secret).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn crypto_envelope_wrong_secret_fails() {
        let plaintext = b"secret data";
        let secret = "correct_secret";

        let envelope = CryptoEnvelope::encrypt(plaintext, secret).unwrap();
        let result = envelope.decrypt("wrong_secret");
        assert!(result.is_err());
    }

    #[test]
    fn crypto_envelope_rejects_unsupported_kdf() {
        let envelope = CryptoEnvelope {
            cipher: CIPHER_AES256GCM.to_string(),
            kdf: "pbkdf2".to_string(),
            salt: BASE64.encode("salt"),
            nonce: BASE64.encode([0u8; 12]),
            ciphertext: BASE64.encode("ciphertext"),
        };

        let result = envelope.decrypt("secret");
        assert!(matches!(result, Err(EncryptionError::UnsupportedKdf(_))));
    }

    #[test]
    fn crypto_envelope_serialization_round_trip() {
        let plaintext = b"test data";
        let secret = "a_secret";

        let envelope = CryptoEnvelope::encrypt(plaintext, secret).unwrap();
        let toml_str = toml::to_string(&envelope).unwrap();
        let deserialized: CryptoEnvelope = toml::from_str(&toml_str).unwrap();
        assert_eq!(envelope, deserialized);

        let decrypted = deserialized.decrypt(secret).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn generate_secret_key_is_64_hex_chars() {
        let secret = generate_secret_key();
        assert_eq!(secret.len(), 64);
        assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn crypto_envelope_rejects_invalid_nonce_length() {
        let envelope = CryptoEnvelope {
            cipher: CIPHER_AES256GCM.to_string(),
            kdf: KDF_HKDF_SHA256.to_string(),
            salt: BASE64.encode("salt"),
            nonce: BASE64.encode([0u8; 8]),
            ciphertext: BASE64.encode("ciphertext"),
        };

        let result = envelope.decrypt("secret");
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }
}
