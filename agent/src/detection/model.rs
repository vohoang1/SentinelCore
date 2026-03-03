use crate::common::normalized_event::SharedEvent;

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
pub struct DetectionEvent {
    pub base: SharedEvent,
    pub risk_score: u32,
    pub severity: Severity,
}
