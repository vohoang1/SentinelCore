#![allow(dead_code, unused_imports)]
use crate::health::metrics::{now_epoch_secs, CORE_METRICS};
use std::sync::atomic::Ordering;

/// Stall detection results aggregated per check cycle.
#[derive(Debug, Clone)]
pub struct HeartbeatStatus {
    pub etw_stall: bool,
    pub worker_stall: bool,
    pub queue_saturated: bool,
    pub possible_deadlock: bool,
}

pub struct HeartbeatChecker {
    last_processed: u64,
    stall_ticks: u32,
    saturation_ticks: u32,
    queue_capacity: usize,
}

impl HeartbeatChecker {
    pub fn new(queue_capacity: usize) -> Self {
        Self {
            last_processed: 0,
            stall_ticks: 0,
            saturation_ticks: 0,
            queue_capacity,
        }
    }

    /// Run all stall/deadlock checks and return aggregated status.
    /// Called once per monitor tick (every 1 second).
    pub fn check(&mut self) -> HeartbeatStatus {
        let snap = CORE_METRICS.snapshot();

        // 1) ETW Stall: no events for 10+ seconds
        let etw_stall = {
            let age = now_epoch_secs().saturating_sub(snap.last_event_ts);
            age > 10
        };

        // 2) Worker Stall: events_processed not increasing for 10+ ticks
        let worker_stall = {
            if snap.events_processed == self.last_processed && snap.events_ingested > 0 {
                self.stall_ticks += 1;
            } else {
                self.stall_ticks = 0;
            }
            self.last_processed = snap.events_processed;
            self.stall_ticks >= 10
        };

        // 3) Queue Saturation: depth > 90% for 5 consecutive ticks
        let queue_saturated = {
            let usage = snap.queue_depth as f64 / self.queue_capacity.max(1) as f64;
            if usage > 0.90 {
                self.saturation_ticks += 1;
            } else {
                self.saturation_ticks = 0;
            }
            self.saturation_ticks >= 5
        };

        // 4) Possible deadlock: workers marked busy but no processing progress for 5+ ticks
        let possible_deadlock = { snap.worker_busy > 0 && self.stall_ticks >= 5 };

        HeartbeatStatus {
            etw_stall,
            worker_stall,
            queue_saturated,
            possible_deadlock,
        }
    }
}
