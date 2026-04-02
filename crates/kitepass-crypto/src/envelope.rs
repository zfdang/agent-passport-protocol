use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use rand::RngCore;
use rand::rngs::OsRng;

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("invalid envelope input")]
    InvalidEnvelope,
    #[error("envelope encryption failed")]
    EncryptionFailed,
    #[error("envelope decryption failed")]
    DecryptionFailed,
}

#[derive(Debug, Clone)]
pub struct WrappedBlob {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub struct Envelope;

impl Envelope {
    pub fn wrap(
        wrapping_key: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<WrappedBlob, EnvelopeError> {
        let cipher = Aes256Gcm::new(wrapping_key.into());
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt(
                GcmNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| EnvelopeError::EncryptionFailed)?;

        Ok(WrappedBlob { nonce, ciphertext })
    }

    pub fn unwrap(
        wrapping_key: &[u8; 32],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        if nonce.len() != 12 || ciphertext.len() < 16 {
            return Err(EnvelopeError::InvalidEnvelope);
        }

        let cipher = Aes256Gcm::new(wrapping_key.into());
        cipher
            .decrypt(
                GcmNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| EnvelopeError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::{Envelope, EnvelopeError};

    #[test]
    fn wrap_then_unwrap_round_trips() {
        let wrapping_key = [7u8; 32];
        let aad = br#"{"wallet_id":"wal_123","session_id":"wis_123"}"#;
        let plaintext = b"wallet-secret-data";

        let wrapped = Envelope::wrap(&wrapping_key, plaintext, aad).expect("wrap should work");
        let unwrapped = Envelope::unwrap(&wrapping_key, &wrapped.nonce, &wrapped.ciphertext, aad)
            .expect("unwrap should work");

        assert_eq!(unwrapped, plaintext);
    }

    #[test]
    fn unwrap_rejects_short_nonce() {
        let err = Envelope::unwrap(&[0u8; 32], &[0u8; 11], &[0u8; 32], b"aad")
            .expect_err("short nonce should fail");
        assert!(matches!(err, EnvelopeError::InvalidEnvelope));
    }
}
