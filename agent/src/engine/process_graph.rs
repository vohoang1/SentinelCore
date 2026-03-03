use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::common::normalized_event::NormalizedEvent;
use crate::engine::correlation::RateTracker;

pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub image: Arc<str>,
    pub start_time: Instant,
}

pub struct ProcessGraph {
    pub processes: DashMap<u32, ProcessNode>,
    pub rate_tracker: RateTracker,
}

impl ProcessGraph {
    pub fn new() -> Self {
        Self {
            processes: DashMap::new(),
            rate_tracker: RateTracker::new(),
        }
    }

    pub fn on_start(&self, event: &NormalizedEvent) {
        if let Some(ref proc) = event.process {
            let node = ProcessNode {
                pid: proc.pid,
                ppid: proc.ppid,
                image: proc.image.clone(),
                start_time: Instant::now(),
            };

            self.processes.insert(proc.pid, node);

            self.detect_chain(event);
            self.rate_tracker.record();
        }
    }

    pub fn on_stop(&self, pid: u32) {
        self.processes.remove(&pid);
    }

    fn detect_chain(&self, event: &NormalizedEvent) {
        if let Some(ref proc) = event.process {
            if let Some(parent) = self.processes.get(&proc.ppid) {
                let parent_img = parent.image.to_lowercase();
                let child_img = proc.image.to_lowercase();

                if parent_img.contains("powershell") && child_img.contains("cmd") {
                    println!("ALERT: Suspicious chain detected: powershell -> cmd");
                }

                if parent_img.contains("winword") && child_img.contains("powershell") {
                    println!("ALERT: Office spawned PowerShell");
                }
            }
        }
    }
}
