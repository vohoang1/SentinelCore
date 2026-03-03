use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::health::exporter::HealthExporter;
use crate::health::heartbeat::{HeartbeatChecker, HeartbeatStatus};

/// Health state machine: Healthy → Degraded → Critical → Recovering → Healthy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HealthState {
    Healthy = 0,
    Degraded = 1,
    Critical = 2,
    Recovering = 3,
}

impl HealthState {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Healthy,
            1 => Self::Degraded,
            2 => Self::Critical,
            3 => Self::Recovering,
            _ => Self::Healthy,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::Degraded => "DEGRADED",
            Self::Critical => "CRITICAL",
            Self::Recovering => "RECOVERING",
        }
    }
}

/// Global health state — readable from any thread, zero-cost.
pub static HEALTH_STATE: AtomicU8 = AtomicU8::new(0);

pub fn current_health() -> HealthState {
    HealthState::from_u8(HEALTH_STATE.load(Ordering::Relaxed))
}

pub struct HealthMonitorV2;

impl HealthMonitorV2 {
    pub fn start(queue_capacity: usize) {
        thread::spawn(move || {
            let mut checker = HeartbeatChecker::new(queue_capacity);
            let mut exporter = HealthExporter::new();
            let mut tick: u64 = 0;

            loop {
                thread::sleep(Duration::from_secs(1));
                tick += 1;

                // 1) Run heartbeat checks
                let status = checker.check();

                // 2) Evaluate FSM transition
                let prev = current_health();
                let next = Self::evaluate_transition(prev, &status);

                if next != prev {
                    println!("Health state: {} → {}", prev.as_str(), next.as_str());
                    HEALTH_STATE.store(next as u8, Ordering::Relaxed);
                    Self::on_transition(prev, next);
                }

                // 3) Export snapshot every 5 seconds
                if tick % 5 == 0 {
                    exporter.export(next);
                }
            }
        });
    }

    fn evaluate_transition(current: HealthState, status: &HeartbeatStatus) -> HealthState {
        if status.etw_stall || status.queue_saturated || status.possible_deadlock {
            return HealthState::Critical;
        }
        if status.worker_stall {
            return HealthState::Degraded;
        }

        match current {
            HealthState::Critical => HealthState::Recovering,
            HealthState::Recovering => HealthState::Healthy,
            _ => HealthState::Healthy,
        }
    }

    fn on_transition(_from: HealthState, to: HealthState) {
        match to {
            HealthState::Critical => {
                eprintln!("🚨 CRITICAL: Activating self-healing procedures...");
                // In production: restart ETW, flush queue, alert console
            }
            HealthState::Degraded => {
                eprintln!("⚠️  DEGRADED: Workers lagging behind ingestion rate.");
            }
            HealthState::Recovering => {
                println!("🔄 RECOVERING: Conditions improving, monitoring...");
            }
            HealthState::Healthy => {
                println!("✅ HEALTHY: All systems nominal.");
            }
        }
    }
}
