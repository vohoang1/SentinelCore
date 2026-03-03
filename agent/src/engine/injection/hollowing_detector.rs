use super::process_memory_state::ProcessMemoryState;
use super::{InjectionAlert, InjectionTechnique};

/// Process hollowing state machine detector.
///
/// Stages:
/// 1. CreateProcess(SUSPENDED)
/// 2. ZwUnmapViewOfSection (image unmapped)
/// 3. WriteProcessMemory (executable region)
/// 4. ResumeThread
///
/// If all 4 stages within 5 seconds → Hollowing alert (confidence 95).
pub struct HollowingDetector;

const HOLLOWING_WINDOW_SECS: u64 = 5;

impl HollowingDetector {
    /// Check if a process has completed the hollowing chain.
    pub fn evaluate(state: &ProcessMemoryState, now_ts: u64) -> Option<InjectionAlert> {
        // Must complete within time window
        if now_ts.saturating_sub(state.first_seen) > HOLLOWING_WINDOW_SECS {
            return None;
        }

        let stage = state.hollowing_stage();

        match stage {
            4 => Some(InjectionAlert {
                rule_name: "Process Hollowing (Full Chain)".to_string(),
                source_pid: 0, // parent set by caller
                target_pid: state.pid,
                technique: InjectionTechnique::ProcessHollowing,
                confidence: 95,
                evidence: "suspended→unmapped→exec_write→resumed".to_string(),
            }),
            3 => Some(InjectionAlert {
                rule_name: "Possible Process Hollowing (3/4 stages)".to_string(),
                source_pid: 0,
                target_pid: state.pid,
                technique: InjectionTechnique::ProcessHollowing,
                confidence: 70,
                evidence: format!(
                    "suspended={} unmapped={} exec_write={} resumed={}",
                    state.created_suspended,
                    state.image_unmapped,
                    state.executable_write,
                    state.resumed
                ),
            }),
            _ => None,
        }
    }
}
