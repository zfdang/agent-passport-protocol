/// TEE attestation verification result.
pub struct AttestationResult {
    pub valid: bool,
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub instance_id: String,
}
