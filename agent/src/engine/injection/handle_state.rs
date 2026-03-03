use std::collections::VecDeque;

/// Windows handle access mask constants.
pub const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;

/// A handle access event (source opening target).
pub struct HandleAccessEvent {
    pub source_pid: u32,
    pub target_pid: u32,
    pub access_mask: u32,
    pub timestamp: u64,
}

impl HandleAccessEvent {
    /// Check if this is a high-privilege handle open.
    pub fn is_high_privilege(&self) -> bool {
        self.access_mask == PROCESS_ALL_ACCESS
            || (self.access_mask & (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD))
                == (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD)
    }

    /// Check if this is a write+execute capable handle.
    pub fn is_injection_capable(&self) -> bool {
        (self.access_mask & PROCESS_VM_WRITE) != 0 && (self.access_mask & PROCESS_VM_OPERATION) != 0
    }
}

const MAX_RECENT_HANDLES: usize = 256;
const HANDLE_WINDOW_SECS: u64 = 10;

/// Rolling window of recent handle access events (bounded).
pub struct HandleTracker {
    events: VecDeque<HandleAccessEvent>,
}

impl HandleTracker {
    pub fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(MAX_RECENT_HANDLES),
        }
    }

    /// Record a new handle access event.
    pub fn record(&mut self, event: HandleAccessEvent, now_ts: u64) {
        // Evict old entries
        while let Some(front) = self.events.front() {
            if now_ts.saturating_sub(front.timestamp) > HANDLE_WINDOW_SECS {
                self.events.pop_front();
            } else {
                break;
            }
        }
        // Bounded
        if self.events.len() >= MAX_RECENT_HANDLES {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// Count how many foreign PIDs a given source_pid has opened handles to.
    pub fn foreign_target_count(&self, source_pid: u32) -> usize {
        let mut targets = std::collections::HashSet::new();
        for ev in &self.events {
            if ev.source_pid == source_pid && ev.source_pid != ev.target_pid {
                targets.insert(ev.target_pid);
            }
        }
        targets.len()
    }

    /// Check if source_pid has opened an injection-capable handle to target_pid.
    pub fn has_injection_handle(&self, source_pid: u32, target_pid: u32) -> bool {
        self.events.iter().any(|ev| {
            ev.source_pid == source_pid && ev.target_pid == target_pid && ev.is_injection_capable()
        })
    }

    /// Detect handle scanner pattern: opening > threshold foreign PIDs.
    pub fn is_handle_scanner(&self, source_pid: u32, threshold: usize) -> bool {
        self.foreign_target_count(source_pid) > threshold
    }
}
