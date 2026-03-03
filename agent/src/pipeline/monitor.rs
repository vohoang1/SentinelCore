use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::pipeline::bus::EventBus;

pub static DEGRADE_MODE: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LoadState {
    Normal,
    Elevated,
    Critical,
}

pub fn start_monitor(bus: Arc<EventBus>) {
    thread::spawn(move || {
        let mut state = LoadState::Normal;

        loop {
            thread::sleep(Duration::from_millis(500)); // check twice a second for faster response

            let depth = bus.depth.load(Ordering::Relaxed);
            let usage = depth as f64 / bus.capacity as f64;

            let new_state = if usage > 0.85 {
                LoadState::Critical
            } else if usage > 0.60 {
                LoadState::Elevated
            } else {
                LoadState::Normal
            };

            if new_state != state {
                handle_state_change(new_state);
                state = new_state;
            }
        }
    });
}

fn handle_state_change(state: LoadState) {
    match state {
        LoadState::Normal => {
            DEGRADE_MODE.store(false, Ordering::Relaxed);
            println!("Load state → NORMAL");
        }
        LoadState::Elevated => {
            println!("Load state → ELEVATED");
        }
        LoadState::Critical => {
            DEGRADE_MODE.store(true, Ordering::Relaxed);
            println!("Load state → CRITICAL → Degrade mode ON");
        }
    }
}
