use crate::cloud::identity::DeviceIdentity;
use crate::cloud::protocol::{EnrollmentRequest, EnrollmentResponse};
use base64::Engine;

const AGENT_VERSION: &str = "0.3.0";

/// First-boot enrollment flow.
/// Sends device public key + system info to cloud.
/// Receives client certificate + server endpoint.
pub struct EnrollmentManager;

impl EnrollmentManager {
    pub fn enroll(
        identity: &DeviceIdentity,
        enroll_url: &str,
    ) -> Result<EnrollmentResponse, String> {
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        let request = EnrollmentRequest {
            device_public_key: base64::engine::general_purpose::STANDARD
                .encode(identity.public_key_bytes()),
            hostname,
            os_version: "Windows".to_string(),
            agent_version: AGENT_VERSION.to_string(),
        };

        let body = serde_json::to_vec(&request).map_err(|e| format!("Serialize error: {}", e))?;

        let resp = ureq::post(enroll_url)
            .set("Content-Type", "application/json")
            .set("X-Device-Id", &identity.device_id)
            .send_bytes(&body)
            .map_err(|e| format!("Network error: {}", e))?;

        if resp.status() != 200 {
            return Err(format!("Enrollment rejected: HTTP {}", resp.status()));
        }

        let response_body = resp
            .into_string()
            .map_err(|e| format!("Read body error: {}", e))?;

        let enrollment: EnrollmentResponse = serde_json::from_str(&response_body)
            .map_err(|e| format!("Parse response error: {}", e))?;

        println!(
            "Enrolled successfully. Endpoint: {}",
            enrollment.server_endpoint
        );
        Ok(enrollment)
    }
}
