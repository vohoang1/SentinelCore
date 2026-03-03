use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const KEYS_DIR: &str = "data/identity";
const PRIVATE_KEY_FILE: &str = "data/identity/device_private.key";
const PUBLIC_KEY_FILE: &str = "data/identity/device_public.key";

/// Cryptographic device identity.
/// Private key never leaves the machine.
pub struct DeviceIdentity {
    signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub device_id: String,
}

impl DeviceIdentity {
    /// Load existing identity or generate new one on first boot.
    pub fn load_or_create() -> Self {
        let _ = fs::create_dir_all(KEYS_DIR);

        if Path::new(PRIVATE_KEY_FILE).exists() {
            Self::load_existing()
        } else {
            Self::generate_new()
        }
    }

    fn generate_new() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // Persist keys (production: use DPAPI or ACL-protected)
        fs::write(PRIVATE_KEY_FILE, signing_key.to_bytes()).expect("Cannot write private key");
        fs::write(PUBLIC_KEY_FILE, verifying_key.to_bytes()).expect("Cannot write public key");

        let device_id = Self::compute_device_id(&verifying_key);
        println!("New device identity created: {}", &device_id[..16]);

        Self {
            signing_key,
            verifying_key,
            device_id,
        }
    }

    fn load_existing() -> Self {
        let priv_bytes = fs::read(PRIVATE_KEY_FILE).expect("Cannot read private key");
        let key_bytes: [u8; 32] = priv_bytes.try_into().expect("Invalid private key length");

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();
        let device_id = Self::compute_device_id(&verifying_key);

        println!("Device identity loaded: {}", &device_id[..16]);

        Self {
            signing_key,
            verifying_key,
            device_id,
        }
    }

    /// device_id = SHA256(public_key) — deterministic.
    fn compute_device_id(vk: &VerifyingKey) -> String {
        let mut hasher = Sha256::new();
        hasher.update(vk.to_bytes());
        hex::encode(hasher.finalize())
    }

    /// Sign arbitrary payload with device private key.
    pub fn sign(&self, payload: &[u8]) -> Signature {
        self.signing_key.sign(payload)
    }

    /// Get public key bytes for enrollment.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}
