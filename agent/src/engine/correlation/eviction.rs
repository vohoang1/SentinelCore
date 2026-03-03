use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::BehavioralEngine;
use crate::health::metrics::now_epoch_secs;

const EVICTION_INTERVAL_SECS: u64 = 30;
const TTL_SECS: u64 = 600; // 10 minutes

/// Start a background eviction thread for the behavioral engine.
pub fn start_eviction_thread(engine: Arc<BehavioralEngine>) {
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(EVICTION_INTERVAL_SECS));

            let now = now_epoch_secs();
            let evicted = engine.evict_expired(now, TTL_SECS);
            let remaining = engine.tracked_count();

            if evicted > 0 {
                println!(
                    "[CORRELATION] Evicted {} stale states. Tracking {} PIDs.",
                    evicted, remaining
                );
            }

            // Anomaly detection: if tracked count growing fast
            if remaining > 40_000 {
                eprintln!(
                    "⚠️  CORRELATION: High state count ({}) — possible flood",
                    remaining
                );
            }
        }
    });
}
