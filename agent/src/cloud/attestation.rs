use crate::cloud::identity::DeviceIdentity;
use base64::Engine;
use sha2::{Digest, Sha256};

/// Remote attestation proof.
/// Proves: binary not tampered, config intact, chain unbroken.
pub struct AttestationProof {
    pub attestation_hash: String,
    pub signature: String,
}

impl AttestationProof {
    /// Build attestation = SHA256(binary_hash || config_hash || chain_root)
    /// Sign with device private key.
    pub fn build(
        identity: &DeviceIdentity,
        binary_hash: &str,
        config_hash: &str,
        chain_root: &str,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(binary_hash.as_bytes());
        hasher.update(config_hash.as_bytes());
        hasher.update(chain_root.as_bytes());
        let attestation_hash = hex::encode(hasher.finalize());

        let sig = identity.sign(attestation_hash.as_bytes());
        let signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        Self {
            attestation_hash,
            signature,
        }
    }
}

/// Compute SHA256 of a file on disk (for binary/config hashing).
pub fn hash_file(path: &str) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(hex::encode(hasher.finalize()))
}
