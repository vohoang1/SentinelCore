/// TLS configuration for mutual TLS (mTLS).
///
/// Production requirements:
/// - TLS 1.3 only
/// - Certificate pinning (server public key hash)  
/// - Client certificate (from enrollment)
/// - No fallback to insecure
/// - Reject invalid certificate chain
/// - Enforce SAN match
/// - Reject clock skew > 5 minutes

/// Pinned server public key hash (SHA256).
/// In production: load from config/hardcoded at compile time.
pub struct TlsConfig {
    pub server_pin_hash: String,
    pub client_cert_pem: Option<String>,
    pub client_key_pem: Option<String>,
    pub ca_cert_pem: Option<String>,
}

impl TlsConfig {
    pub fn new() -> Self {
        Self {
            server_pin_hash: String::new(),
            client_cert_pem: None,
            client_key_pem: None,
            ca_cert_pem: None,
        }
    }

    /// Load client certificate from enrollment response.
    pub fn set_client_cert(&mut self, cert_pem: String, key_pem: String) {
        self.client_cert_pem = Some(cert_pem);
        self.client_key_pem = Some(key_pem);
    }

    /// Set server certificate pin (SHA256 of server public key).
    pub fn set_server_pin(&mut self, pin_hash: String) {
        self.server_pin_hash = pin_hash;
    }

    /// Validate that all mTLS requirements are met.
    pub fn is_ready(&self) -> bool {
        self.client_cert_pem.is_some()
            && self.client_key_pem.is_some()
            && !self.server_pin_hash.is_empty()
    }
}
