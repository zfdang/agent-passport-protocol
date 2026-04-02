use sha2::{Digest, Sha256};

/// Compute SHA-256 digest of the given data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
