use super::state::ProcessState;
use super::CorrelatedAlert;

/// Trait for stateful correlation rules.
/// Each rule evaluates a ProcessState and optionally emits an alert.
pub trait CorrelationRule {
    fn evaluate(&self, state: &ProcessState, now_ts: u64) -> Option<CorrelatedAlert>;
}

// ─── Rule 1: PowerShell C2 Chain ────────────────────────────────

/// Detects: powershell + external connection + suspicious signature flag
/// within the rolling window.
pub struct PowershellC2Chain;

impl CorrelationRule for PowershellC2Chain {
    fn evaluate(&self, state: &ProcessState, _now_ts: u64) -> Option<CorrelatedAlert> {
        if !state.image_lower.contains("powershell") {
            return None;
        }
        if state.external_connections == 0 {
            return None;
        }
        if state.suspicious_flags == 0 {
            return None;
        }

        Some(CorrelatedAlert {
            rule_id: 1,
            rule_name: "PowerShell C2 Chain".to_string(),
            pid: state.pid,
            severity: 3, // HIGH
            first_seen: state.first_seen,
            evidence: format!(
                "external_conn={} sig_flags={:#x}",
                state.external_connections, state.suspicious_flags
            ),
        })
    }
}

// ─── Rule 2: Fast Spawn + Connect (Dropper Pattern) ────────────

/// Detects: spawn_count > 10 AND network_count > 0 within window.
pub struct FastSpawnConnect;

impl CorrelationRule for FastSpawnConnect {
    fn evaluate(&self, state: &ProcessState, _now_ts: u64) -> Option<CorrelatedAlert> {
        if state.spawn_count <= 10 {
            return None;
        }
        if state.network_count == 0 {
            return None;
        }

        Some(CorrelatedAlert {
            rule_id: 2,
            rule_name: "Fast Spawn + Connect (Dropper)".to_string(),
            pid: state.pid,
            severity: 3,
            first_seen: state.first_seen,
            evidence: format!("spawns={} net={}", state.spawn_count, state.network_count),
        })
    }
}

// ─── Rule 3: Network Burst / Port Scan ──────────────────────────

/// Detects: external_connections > 100 AND unique_dst > 20 within window.
pub struct NetworkBurstScan;

impl CorrelationRule for NetworkBurstScan {
    fn evaluate(&self, state: &ProcessState, _now_ts: u64) -> Option<CorrelatedAlert> {
        if state.external_connections <= 100 {
            return None;
        }
        if state.unique_dst_count() <= 20 {
            return None;
        }

        Some(CorrelatedAlert {
            rule_id: 3,
            rule_name: "Network Burst / Port Scan".to_string(),
            pid: state.pid,
            severity: 3,
            first_seen: state.first_seen,
            evidence: format!(
                "external={} unique_dst={}",
                state.external_connections,
                state.unique_dst_count()
            ),
        })
    }
}
