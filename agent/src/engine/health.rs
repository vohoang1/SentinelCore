use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::pipeline::bus::EventBus;
use crate::sensor::etw_listener::{ETW_EVENTS_DROPPED, ETW_EVENTS_RECEIVED};

pub static HEALTH_STATUS: AtomicBool = AtomicBool::new(true);
pub static LAST_EVENT_TIME: AtomicU64 = AtomicU64::new(0);

pub struct HealthMonitor {
    bus: Arc<EventBus>,
    last_check: Instant,
    last_event_count: u64,
}

impl HealthMonitor {
    pub fn start(bus: Arc<EventBus>) {
        thread::spawn(move || {
            let mut monitor = Self {
                bus,
                last_check: Instant::now(),
                last_event_count: 0,
            };
            monitor.run();
        });
    }

    fn run(&mut self) {
        loop {
            thread::sleep(Duration::from_secs(5));

            let now = Instant::now();
            let elapsed = now.duration_since(self.last_check).as_secs();
            self.last_check = now;

            let current_count = ETW_EVENTS_RECEIVED.load(Ordering::Relaxed);
            let dropped = ETW_EVENTS_DROPPED.load(Ordering::Relaxed);
            let queue_depth = self.bus.depth.load(Ordering::Relaxed);

            // Throughput check
            let events_delta = current_count.saturating_sub(self.last_event_count);
            let throughput = events_delta / elapsed.max(1);
            self.last_event_count = current_count;

            // Buffer loss rate
            let loss_rate = if current_count > 0 {
                (dropped as f64 / current_count as f64) * 100.0
            } else {
                0.0
            };

            // ETW alive check (no events for 10s on active system = dead)
            let last_event = LAST_EVENT_TIME.load(Ordering::Relaxed);
            let event_age = crate::sensor::etw_listener::now().saturating_sub(last_event);
            let etw_alive = event_age < 10;

            // Worker lag (queue depth sustained high)
            let worker_lag = queue_depth > 5000;

            // Health decision
            let healthy = etw_alive && loss_rate < 5.0 && !worker_lag;
            HEALTH_STATUS.store(healthy, Ordering::Relaxed);

            if !healthy {
                eprintln!("⚠️  HEALTH DEGRADED:");
                if !etw_alive {
                    eprintln!("   - ETW session dead (no events for {}s)", event_age);
                }
                if loss_rate >= 5.0 {
                    eprintln!("   - Buffer loss rate: {:.2}%", loss_rate);
                }
                if worker_lag {
                    eprintln!("   - Worker lag: queue depth {}", queue_depth);
                }
            }

            // Metrics log
            println!(
                "[HEALTH] throughput={}/s loss={:.2}% queue={} alive={}",
                throughput, loss_rate, queue_depth, etw_alive
            );
        }
    }
}
