use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    ProcessStart,
    ProcessStop,
    NetworkConnect,
    RegistrySet,
    KernelTelemetry,
}

#[derive(Debug, Clone)]
pub struct NormalizedEvent {
    pub kind: EventKind,
    pub timestamp: u64,
    pub priority: Priority,

    pub process: Option<ProcessInfo>,
    pub network: Option<NetworkInfo>,
    pub registry: Option<RegistryInfo>,
    pub kernel: Option<KernelTelemetryInfo>,
}

pub type SharedEvent = Arc<NormalizedEvent>;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub image: Arc<str>,
    pub command_line: Option<Arc<str>>,
}

#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub pid: u32,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone)]
pub struct RegistryInfo {
    pub pid: u32,
    pub key_path: Arc<str>,
    pub value_name: Option<Arc<str>>,
}

#[derive(Debug, Clone)]
pub struct KernelTelemetryInfo {
    pub raw_kernel_timestamp: i64,
    pub event_type: u32,
    pub event_name: Arc<str>,
    pub source_pid: u32,
    pub target_pid: u32,
    pub original_access: u32,
    pub stripped_access: u32,
    pub detail: Option<Arc<str>>,
    pub source_etw: EtwCorrelationInfo,
    pub target_etw: EtwCorrelationInfo,
}

#[derive(Debug, Clone)]
pub struct EtwCorrelationInfo {
    pub seen_in_window: bool,
    pub last_seen_ts: Option<u64>,
    pub image: Option<Arc<str>>,
}
