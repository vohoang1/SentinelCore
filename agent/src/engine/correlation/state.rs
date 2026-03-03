use std::collections::{HashMap, HashSet};

/// Per-process behavioral state.
/// All updates must be O(1). No allocations on hot path after init.
pub struct ProcessState {
    pub pid: u32,
    pub ppid: u32,
    pub image_lower: String,
    pub first_seen: u64,
    pub last_seen: u64,

    // Rolling counters (reset when window expires)
    pub spawn_count: u32,
    pub network_count: u32,
    pub external_connections: u32,

    // Flags set by signature engine
    pub suspicious_flags: u32,

    // Bounded IP set (max 128)
    pub recent_dst_ips: HashSet<String>,

    // Alert cooldown: rule_id → last_alert_ts
    alert_cooldowns: HashMap<u32, u64>,

    // Window tracking
    window_start: u64,
}

const WINDOW_DURATION_SECS: u64 = 120; // 2-minute rolling window

impl ProcessState {
    pub fn new(pid: u32, now_ts: u64) -> Self {
        Self {
            pid,
            ppid: 0,
            image_lower: String::new(),
            first_seen: now_ts,
            last_seen: now_ts,
            spawn_count: 0,
            network_count: 0,
            external_connections: 0,
            suspicious_flags: 0,
            recent_dst_ips: HashSet::with_capacity(16),
            alert_cooldowns: HashMap::new(),
            window_start: now_ts,
        }
    }

    /// Reset rolling counters if window expired. O(1) arithmetic.
    pub fn maybe_reset_window(&mut self, now_ts: u64) {
        if now_ts.saturating_sub(self.window_start) > WINDOW_DURATION_SECS {
            self.spawn_count = 0;
            self.network_count = 0;
            self.external_connections = 0;
            self.recent_dst_ips.clear();
            self.suspicious_flags = 0;
            self.window_start = now_ts;
        }
    }

    /// Check if alert is allowed (cooldown period).
    pub fn can_alert(&self, rule_id: u32, now_ts: u64, cooldown_secs: u64) -> bool {
        match self.alert_cooldowns.get(&rule_id) {
            Some(&last_ts) => now_ts.saturating_sub(last_ts) >= cooldown_secs,
            None => true,
        }
    }

    /// Record that an alert was emitted.
    pub fn record_alert(&mut self, rule_id: u32, now_ts: u64) {
        self.alert_cooldowns.insert(rule_id, now_ts);
    }

    /// Unique destination IP count in current window.
    pub fn unique_dst_count(&self) -> usize {
        self.recent_dst_ips.len()
    }
}
