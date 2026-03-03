use dashmap::DashMap;

/// Lightweight parent-child process graph.
/// Bounded, evictable, used for severity escalation.
pub struct ProcessRelationGraph {
    /// parent_pid → Vec<child_pid>
    children: DashMap<u32, Vec<u32>>,
    /// pid → last_seen_ts (for eviction)
    timestamps: DashMap<u32, u64>,
}

impl ProcessRelationGraph {
    pub fn new() -> Self {
        Self {
            children: DashMap::with_capacity(5_000),
            timestamps: DashMap::with_capacity(10_000),
        }
    }

    pub fn add_edge(&self, parent_pid: u32, child_pid: u32) {
        self.children
            .entry(parent_pid)
            .or_insert_with(|| Vec::with_capacity(4))
            .push(child_pid);

        let now = crate::health::metrics::now_epoch_secs();
        self.timestamps.insert(parent_pid, now);
        self.timestamps.insert(child_pid, now);
    }

    /// Get children of a process.
    pub fn get_children(&self, parent_pid: u32) -> Vec<u32> {
        self.children
            .get(&parent_pid)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Evict stale entries.
    pub fn evict_stale(&self, now_ts: u64, ttl_secs: u64) {
        self.timestamps
            .retain(|_pid, ts| now_ts.saturating_sub(*ts) < ttl_secs);
        self.children
            .retain(|pid, _| self.timestamps.contains_key(pid));
    }

    pub fn node_count(&self) -> usize {
        self.timestamps.len()
    }
}
