pub mod handle_state;
pub mod hollowing_detector;
pub mod process_memory_state;
pub mod remote_thread_detector;

use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Mutex;

use self::handle_state::{HandleAccessEvent, HandleTracker};
use self::hollowing_detector::HollowingDetector;
use self::process_memory_state::ProcessMemoryState;
use self::remote_thread_detector::{ApcDetector, HandleAbuseDetector, RwxDetector};
use crate::common::normalized_event::{EventKind, NormalizedEvent};

// ─── Alert Data ─────────────────────────────────────────────────

#[derive(Debug)]
pub enum InjectionTechnique {
    RemoteThread,
    ProcessHollowing,
    RwxAllocation,
    ApcInjection,
    HandleAbuse,
}

pub struct InjectionAlert {
    pub rule_name: String,
    pub source_pid: u32,
    pub target_pid: u32,
    pub technique: InjectionTechnique,
    pub confidence: u8,
    pub evidence: String,
}

// ─── Whitelist ──────────────────────────────────────────────────

fn default_trusted_pids() -> HashSet<String> {
    let mut set = HashSet::new();
    set.insert("devenv.exe".to_string()); // Visual Studio
    set.insert("msvsmon.exe".to_string()); // VS debugger
    set.insert("windbg.exe".to_string()); // WinDbg
    set.insert("msmpeng.exe".to_string()); // Defender
    set.insert("mrt.exe".to_string()); // Malicious Removal Tool
    set.insert("taskmgr.exe".to_string()); // Task Manager
    set.insert("procexp64.exe".to_string()); // Process Explorer
    set
}

// ─── Injection Engine ───────────────────────────────────────────

const MAX_TRACKED_PIDS: usize = 50_000;
const EVICTION_TTL_SECS: u64 = 300; // 5 minutes

/// Main injection detection engine.
/// DashMap-based, bounded, non-blocking.
pub struct InjectionEngine {
    states: DashMap<u32, ProcessMemoryState>,
    handles: Mutex<HandleTracker>,
    trusted_images: HashSet<String>,
    sentinel_pid: u32,
}

impl InjectionEngine {
    pub fn new() -> Self {
        let sentinel_pid = std::process::id();
        Self {
            states: DashMap::with_capacity(10_000),
            handles: Mutex::new(HandleTracker::new()),
            trusted_images: default_trusted_pids(),
            sentinel_pid,
        }
    }

    /// Process an event through injection detection.
    /// Returns any alerts triggered.
    pub fn process(&self, event: &NormalizedEvent, now_ts: u64) -> Vec<InjectionAlert> {
        let pid = event.process.as_ref().map(|p| p.pid).unwrap_or(0);
        if pid == 0 {
            return Vec::new();
        }

        // Skip trusted processes
        if let Some(ref proc) = event.process {
            let img_lower = proc.image.to_lowercase();
            if self.trusted_images.iter().any(|t| img_lower.contains(t)) {
                return Vec::new();
            }
        }

        // Enforce bounded map
        if self.states.len() >= MAX_TRACKED_PIDS && !self.states.contains_key(&pid) {
            return Vec::new();
        }

        // Upsert state
        let mut entry = self
            .states
            .entry(pid)
            .or_insert_with(|| ProcessMemoryState::new(pid, now_ts));
        let state = entry.value_mut();
        state.last_seen = now_ts;

        let mut alerts = Vec::new();

        match event.kind {
            EventKind::ProcessStart => {
                // Check for suspended creation (placeholder — full impl needs ETW flags)
                // In production, the ETW event would carry suspension flag
            }
            EventKind::ProcessStop => {
                // Remove state on stop
                drop(entry);
                self.states.remove(&pid);
                return Vec::new();
            }
            EventKind::NetworkConnect => {
                // Not directly relevant to injection, but correlate with behavioral engine
            }
            EventKind::RegistrySet => {}
            EventKind::KernelTelemetry => {
                if let Some(ref k) = event.kernel {
                    if k.event_name.as_ref() == "HandleStrip" {
                        if let Ok(mut handles) = self.handles.lock() {
                            handles.record(
                                HandleAccessEvent {
                                    source_pid: k.source_pid,
                                    target_pid: k.target_pid,
                                    access_mask: k.original_access,
                                    timestamp: now_ts,
                                },
                                now_ts,
                            );
                        }
                    }
                }
            }
        }

        // Evaluate RWX abuse
        if let Some(alert) = RwxDetector::evaluate(state, now_ts) {
            alerts.push(alert);
        }

        // Evaluate APC injection
        if let Some(alert) = ApcDetector::evaluate(state) {
            alerts.push(alert);
        }

        // Evaluate hollowing
        if let Some(alert) = HollowingDetector::evaluate(state, now_ts) {
            alerts.push(alert);
        }

        // Evaluate handle abuse
        if let Ok(handles) = self.handles.lock() {
            if let Some(alert) =
                HandleAbuseDetector::evaluate_scanner(&handles, pid, self.sentinel_pid)
            {
                alerts.push(alert);
            }
        }

        alerts
    }

    /// Record a handle access event from ETW.
    pub fn record_handle_access(
        &self,
        source_pid: u32,
        target_pid: u32,
        access_mask: u32,
        now_ts: u64,
    ) {
        // Update target state
        if let Some(mut state) = self.states.get_mut(&target_pid) {
            state.record_handle_open(source_pid);
        }

        // Track in handle tracker
        if let Ok(mut handles) = self.handles.lock() {
            handles.record(
                HandleAccessEvent {
                    source_pid,
                    target_pid,
                    access_mask,
                    timestamp: now_ts,
                },
                now_ts,
            );
        }
    }

    /// Record a remote memory write from ETW.
    pub fn record_remote_write(&self, target_pid: u32) {
        if let Some(mut state) = self.states.get_mut(&target_pid) {
            state.remote_writes += 1;
            state.executable_write = true;
        }
    }

    /// Record a remote thread start from ETW.
    pub fn record_remote_thread(&self, target_pid: u32) {
        if let Some(mut state) = self.states.get_mut(&target_pid) {
            state.remote_threads += 1;
            state.resumed = true;
        }
    }

    /// Record an APC injection from ETW.
    pub fn record_apc_injection(&self, target_pid: u32) {
        if let Some(mut state) = self.states.get_mut(&target_pid) {
            state.apc_injections += 1;
        }
    }

    /// Mark a process as created suspended (hollowing start).
    pub fn mark_suspended(&self, pid: u32) {
        if let Some(mut state) = self.states.get_mut(&pid) {
            state.created_suspended = true;
        }
    }

    /// Mark a process as having its image unmapped (hollowing stage 2).
    pub fn mark_image_unmapped(&self, pid: u32) {
        if let Some(mut state) = self.states.get_mut(&pid) {
            state.image_unmapped = true;
        }
    }

    /// Run eviction pass.
    pub fn evict_expired(&self, now_ts: u64) -> usize {
        let before = self.states.len();
        self.states
            .retain(|_, state| now_ts.saturating_sub(state.last_seen) < EVICTION_TTL_SECS);
        before - self.states.len()
    }

    pub fn tracked_count(&self) -> usize {
        self.states.len()
    }
}
