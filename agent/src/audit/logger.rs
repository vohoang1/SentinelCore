use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::event_classifier::SecurityLevel;
use super::hash_chain::{get_previous_hash, update_hash_chain};

const LOG_FILE: &str = "data/security_audit.log";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEvent {
    pub timestamp: String,
    pub request_id: String,
    pub source_pid: Option<u32>,
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub ai_score: f64,
    pub rule_triggered: Vec<String>,
    pub decision: String,
    pub response_time_ms: u64,
    pub security_level: SecurityLevel,
    pub previous_hash: Option<String>,
    pub hash_integrity: Option<String>,
}

pub fn write_audit_log(mut entry: AuditEvent) -> std::io::Result<()> {
    if entry.timestamp.is_empty() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        entry.timestamp = ts.to_string();
    }

    entry.previous_hash = Some(get_previous_hash());
    entry.hash_integrity = None;

    // Serialize precisely block to create sha
    let serialized_content = serde_json::to_string(&entry).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(serialized_content.as_bytes());
    let entry_hash = format!("{:x}", hasher.finalize());

    // Secure state mapping
    entry.hash_integrity = Some(entry_hash.clone());
    update_hash_chain(entry_hash);

    let final_record = serde_json::to_string(&entry).unwrap();

    if let Some(parent) = Path::new(LOG_FILE).parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)?;

    writeln!(file, "{}", final_record)?;

    Ok(())
}
