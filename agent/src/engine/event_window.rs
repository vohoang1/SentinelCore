use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::common::normalized_event::{EventKind, NormalizedEvent};

pub struct EventWindow {
    window: VecDeque<(Instant, NormalizedEvent)>,
    max_duration: Duration,
    max_size: usize,
}

impl EventWindow {
    pub fn new(duration_secs: u64, max_size: usize) -> Self {
        Self {
            window: VecDeque::with_capacity(max_size),
            max_duration: Duration::from_secs(duration_secs),
            max_size,
        }
    }

    pub fn push(&mut self, event: NormalizedEvent) {
        let now = Instant::now();

        // Age-based cleanup
        while let Some((ts, _)) = self.window.front() {
            if now.duration_since(*ts) > self.max_duration {
                self.window.pop_front();
            } else {
                break;
            }
        }

        // Size-based cap
        if self.window.len() >= self.max_size {
            self.window.pop_front();
        }

        self.window.push_back((now, event));
    }

    pub fn find_by_pid(&self, pid: u32) -> Vec<&NormalizedEvent> {
        self.window
            .iter()
            .filter(|(_, e)| match e.kind {
                EventKind::ProcessStart | EventKind::ProcessStop => {
                    e.process.as_ref().map_or(false, |p| p.pid == pid)
                }
                EventKind::NetworkConnect => e.network.as_ref().map_or(false, |n| n.pid == pid),
                _ => false,
            })
            .map(|(_, e)| e)
            .collect()
    }

    pub fn find_network_by_pid(&self, pid: u32) -> Vec<&NormalizedEvent> {
        self.window
            .iter()
            .filter(|(_, e)| {
                e.kind == EventKind::NetworkConnect
                    && e.network.as_ref().map_or(false, |n| n.pid == pid)
            })
            .map(|(_, e)| e)
            .collect()
    }

    pub fn count_by_kind(&self, kind: EventKind) -> usize {
        self.window.iter().filter(|(_, e)| e.kind == kind).count()
    }
}
