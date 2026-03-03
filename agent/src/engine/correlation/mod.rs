pub mod eviction;
pub mod graph;
pub mod rules;
pub mod state;
pub mod window;

// Re-export legacy RateTracker for backward compatibility
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateTracker {
    pub timestamps: Mutex<VecDeque<Instant>>,
}

impl RateTracker {
    pub fn new() -> Self {
        Self {
            timestamps: Mutex::new(VecDeque::new()),
        }
    }

    pub fn record(&self) {
        let mut q = self.timestamps.lock().unwrap();
        let now = Instant::now();
        q.push_back(now);
        while let Some(front) = q.front() {
            if now.duration_since(*front).as_secs() > 5 {
                q.pop_front();
            } else {
                break;
            }
        }
        if q.len() > 50 {
            println!(
                "ALERT: Process spawn spike detected ({} spawns in 5s)!",
                q.len()
            );
        }
    }

    pub fn count_last(&self, seconds: u64) -> usize {
        let mut q = self.timestamps.lock().unwrap();
        let now = Instant::now();
        while let Some(front) = q.front() {
            if now.duration_since(*front).as_secs() > seconds {
                q.pop_front();
            } else {
                break;
            }
        }
        q.len()
    }
}

// ─── Behavioral Correlation Engine ──────────────────────────────

use crate::cloud::protocol::EventPayload;
use crate::common::normalized_event::{EventKind, NormalizedEvent};
use dashmap::DashMap;
use std::sync::Arc;

use self::graph::ProcessRelationGraph;
use self::rules::{CorrelationRule, FastSpawnConnect, NetworkBurstScan, PowershellC2Chain};
use self::state::ProcessState;

/// Correlated alert output.
pub struct CorrelatedAlert {
    pub rule_id: u32,
    pub rule_name: String,
    pub pid: u32,
    pub severity: u8,
    pub first_seen: u64,
    pub evidence: String,
}

/// Main behavioral correlation engine.
/// O(1) update, bounded memory, lock-minimized.
pub struct BehavioralEngine {
    states: DashMap<u32, ProcessState>,
    graph: ProcessRelationGraph,
    rules: Vec<Box<dyn CorrelationRule + Send + Sync>>,
    max_tracked: usize,
}

impl BehavioralEngine {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn CorrelationRule + Send + Sync>> = vec![
            Box::new(PowershellC2Chain),
            Box::new(FastSpawnConnect),
            Box::new(NetworkBurstScan),
        ];

        Self {
            states: DashMap::with_capacity(10_000),
            graph: ProcessRelationGraph::new(),
            rules,
            max_tracked: 50_000,
        }
    }

    /// Process a normalized event through the correlation engine.
    /// Returns alerts if any rule triggers.
    pub fn process(&self, event: &NormalizedEvent, now_ts: u64) -> Vec<CorrelatedAlert> {
        let pid = event.process.as_ref().map(|p| p.pid).unwrap_or(0);
        if pid == 0 {
            return Vec::new();
        }

        // Enforce bounded map
        if self.states.len() >= self.max_tracked && !self.states.contains_key(&pid) {
            return Vec::new(); // Degrade: skip new PIDs when at capacity
        }

        // Upsert ProcessState
        let mut entry = self
            .states
            .entry(pid)
            .or_insert_with(|| ProcessState::new(pid, now_ts));
        let state = entry.value_mut();

        // Update state based on event kind (O(1))
        match event.kind {
            EventKind::ProcessStart => {
                state.spawn_count += 1;
                state.last_seen = now_ts;

                if let Some(ref proc) = event.process {
                    state.image_lower = proc.image.to_lowercase();
                    state.ppid = proc.ppid;

                    // Track parent-child in graph
                    self.graph.add_edge(proc.ppid, pid);
                }
            }
            EventKind::ProcessStop => {
                state.last_seen = now_ts;
            }
            EventKind::NetworkConnect => {
                state.network_count += 1;
                state.last_seen = now_ts;

                if let Some(ref net) = event.network {
                    // Track unique destination IPs (bounded to 128)
                    let ip_str = net.dst_ip.to_string();
                    if state.recent_dst_ips.len() < 128 {
                        state.recent_dst_ips.insert(ip_str.clone());
                    }

                    // Check if external IP
                    let octets = match net.dst_ip {
                        std::net::IpAddr::V4(v4) => {
                            let o = v4.octets();
                            !(o[0] == 10
                                || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
                                || (o[0] == 192 && o[1] == 168)
                                || o[0] == 127)
                        }
                        std::net::IpAddr::V6(_) => true,
                    };
                    if octets {
                        state.external_connections += 1;
                    }
                }
            }
            EventKind::RegistrySet => {
                state.last_seen = now_ts;
            }
            EventKind::KernelTelemetry => {
                state.last_seen = now_ts;
            }
        }

        // Reset rolling counters if window expired
        state.maybe_reset_window(now_ts);

        // Evaluate correlation rules
        let mut alerts = Vec::new();
        for rule in &self.rules {
            if let Some(alert) = rule.evaluate(state, now_ts) {
                // Dedup: check cooldown (60s per rule per PID)
                if state.can_alert(alert.rule_id, now_ts, 60) {
                    state.record_alert(alert.rule_id, now_ts);
                    alerts.push(alert);
                }
            }
        }

        // Escalate if multiple rules triggered
        if alerts.len() >= 2 {
            for a in &mut alerts {
                a.severity = 4; // CRITICAL
            }
        }

        alerts
    }

    /// Mark a PID as having a signature hit (called from SignatureEngine).
    pub fn set_suspicious_flag(&self, pid: u32) {
        if let Some(mut state) = self.states.get_mut(&pid) {
            state.suspicious_flags |= 1;
        }
    }

    /// Run eviction pass — call from health monitor every 30s.
    pub fn evict_expired(&self, now_ts: u64, ttl_secs: u64) -> usize {
        let before = self.states.len();
        self.states
            .retain(|_pid, state| now_ts.saturating_sub(state.last_seen) < ttl_secs);
        let evicted = before - self.states.len();
        self.graph.evict_stale(now_ts, ttl_secs);
        evicted
    }

    pub fn tracked_count(&self) -> usize {
        self.states.len()
    }
}
