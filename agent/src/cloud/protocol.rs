use serde::{Deserialize, Serialize};

/// Telemetry upload frame — batched events with chain integrity.
#[derive(Serialize, Debug)]
pub struct UploadFrame {
    pub device_id: String,
    pub seq: u64,
    pub events: Vec<EventPayload>,
    pub metrics: MetricsPayload,
    pub chain_root: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Serialize, Debug)]
pub struct EventPayload {
    pub id: i64,
    pub ts: u64,
    pub event_kind: u8,
    pub process_name: Option<String>,
    pub pid: u32,
    pub parent_pid: u32,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub raw_hash: String,
}

#[derive(Serialize, Debug)]
pub struct MetricsPayload {
    pub events_ingested: u64,
    pub events_processed: u64,
    pub events_dropped: u64,
    pub queue_depth: usize,
    pub etw_errors: u64,
    pub signature_hits: u64,
    pub health_state: String,
}

/// Agent heartbeat — sent every 30 seconds.
#[derive(Serialize, Debug)]
pub struct Heartbeat {
    pub device_id: String,
    pub health_state: String,
    pub queue_depth: usize,
    pub etw_errors: u64,
    pub memory_usage_mb: u64,
    pub uptime_secs: u64,
    pub timestamp: u64,
}

/// Remote commands from cloud (controlled whitelist).
#[derive(Deserialize, Debug)]
pub struct RemoteCommand {
    pub command_type: CommandType,
    pub payload: Option<String>,
}

#[derive(Deserialize, Debug)]
pub enum CommandType {
    RequestVerify,
    RotateCertificate,
    UpdateConfig,
    ForceLogFlush,
}

/// Enrollment request — sent on first boot.
#[derive(Serialize, Debug)]
pub struct EnrollmentRequest {
    pub device_public_key: String,
    pub hostname: String,
    pub os_version: String,
    pub agent_version: String,
}

/// Enrollment response from cloud.
#[derive(Deserialize, Debug)]
pub struct EnrollmentResponse {
    pub device_id: String,
    pub server_endpoint: String,
    pub cert_pem: String,
    pub heartbeat_interval_secs: u64,
}
