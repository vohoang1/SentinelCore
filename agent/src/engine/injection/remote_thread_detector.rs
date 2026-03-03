use super::handle_state::HandleTracker;
use super::process_memory_state::ProcessMemoryState;
use super::{InjectionAlert, InjectionTechnique};

/// Remote thread injection detector.
///
/// Correlates: handle open + memory write + thread start from non-image region.
pub struct RemoteThreadDetector;

impl RemoteThreadDetector {
    /// Evaluate remote thread injection.
    /// Called when a thread start event is observed for target_pid.
    pub fn evaluate(
        target_state: &ProcessMemoryState,
        handles: &HandleTracker,
        thread_start_addr: u64,
    ) -> Option<InjectionAlert> {
        // Must have remote writes
        if target_state.remote_writes == 0 {
            return None;
        }

        // Thread start address must NOT be in image-backed region
        if target_state.is_address_in_image(thread_start_addr) {
            return None;
        }

        // Must have injection-capable handle from some source
        for source_pid in &target_state.handle_source_pids {
            if handles.has_injection_handle(*source_pid, target_state.pid) {
                return Some(InjectionAlert {
                    rule_name: "Remote Thread Injection".to_string(),
                    source_pid: *source_pid,
                    target_pid: target_state.pid,
                    technique: InjectionTechnique::RemoteThread,
                    confidence: 90,
                    evidence: format!(
                        "remote_writes={} thread_addr={:#x} source={}",
                        target_state.remote_writes, thread_start_addr, source_pid
                    ),
                });
            }
        }

        // No handle correlation but still suspicious (lower confidence)
        if target_state.remote_threads > 0 {
            return Some(InjectionAlert {
                rule_name: "Suspicious Thread Start (Non-Image)".to_string(),
                source_pid: 0,
                target_pid: target_state.pid,
                technique: InjectionTechnique::RemoteThread,
                confidence: 50,
                evidence: format!(
                    "thread_addr={:#x} remote_threads={}",
                    thread_start_addr, target_state.remote_threads
                ),
            });
        }

        None
    }
}

/// RWX allocation abuse detector.
pub struct RwxDetector;

const RWX_THRESHOLD: u32 = 2;
const RWX_WINDOW_SECS: u64 = 30;

impl RwxDetector {
    pub fn evaluate(state: &ProcessMemoryState, now_ts: u64) -> Option<InjectionAlert> {
        if state.suspicious_allocs < RWX_THRESHOLD {
            return None;
        }
        if now_ts.saturating_sub(state.first_seen) > RWX_WINDOW_SECS {
            return None;
        }

        Some(InjectionAlert {
            rule_name: "RWX Allocation Abuse".to_string(),
            source_pid: state.pid,
            target_pid: state.pid,
            technique: InjectionTechnique::RwxAllocation,
            confidence: 80,
            evidence: format!(
                "suspicious_allocs={} in {}s",
                state.suspicious_allocs,
                now_ts.saturating_sub(state.first_seen)
            ),
        })
    }
}

/// APC injection detector.
pub struct ApcDetector;

impl ApcDetector {
    pub fn evaluate(state: &ProcessMemoryState) -> Option<InjectionAlert> {
        if state.apc_injections == 0 {
            return None;
        }

        Some(InjectionAlert {
            rule_name: "APC Injection".to_string(),
            source_pid: 0, // Source set by caller
            target_pid: state.pid,
            technique: InjectionTechnique::ApcInjection,
            confidence: 85,
            evidence: format!("apc_count={}", state.apc_injections),
        })
    }
}

/// Handle abuse detector — scanner pattern.
pub struct HandleAbuseDetector;

const HANDLE_SCANNER_THRESHOLD: usize = 5;

impl HandleAbuseDetector {
    pub fn evaluate_scanner(
        handles: &HandleTracker,
        source_pid: u32,
        sentinel_pid: u32,
    ) -> Option<InjectionAlert> {
        if !handles.is_handle_scanner(source_pid, HANDLE_SCANNER_THRESHOLD) {
            return None;
        }

        // Check if targeting SentinelCore → escalate CRITICAL
        let targeting_sentinel = handles.has_injection_handle(source_pid, sentinel_pid);

        Some(InjectionAlert {
            rule_name: if targeting_sentinel {
                "Handle Abuse (Targeting Agent)".to_string()
            } else {
                "Handle Scanner / Injector".to_string()
            },
            source_pid,
            target_pid: 0,
            technique: InjectionTechnique::HandleAbuse,
            confidence: if targeting_sentinel { 95 } else { 70 },
            evidence: format!(
                "foreign_targets={} targeting_sentinel={}",
                handles.foreign_target_count(source_pid),
                targeting_sentinel
            ),
        })
    }
}
