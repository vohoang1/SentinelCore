use std::collections::HashSet;

/// Memory region descriptor — bounded per process.
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub protection: u32,
    pub is_image_backed: bool,
}

// Windows protection constants
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

const MAX_REGIONS_PER_PID: usize = 8;
const MAX_TRACKED_IPS_PER_PID: usize = 32;

/// Per-process memory state for injection detection.
/// All updates O(1). Bounded allocations.
pub struct ProcessMemoryState {
    pub pid: u32,
    pub first_seen: u64,
    pub last_seen: u64,

    // Memory tracking (bounded)
    pub regions: Vec<MemoryRegion>,

    // Counters
    pub suspicious_allocs: u32, // RWX allocations without image backing
    pub remote_writes: u32,     // Writes from foreign PIDs
    pub remote_threads: u32,    // Threads started from non-image memory
    pub apc_injections: u32,    // APC queue from foreign PIDs

    // Suspended state (for hollowing detection)
    pub created_suspended: bool,
    pub image_unmapped: bool,
    pub executable_write: bool,
    pub resumed: bool,

    // Handle abuse tracking
    pub foreign_handle_opens: u32, // How many foreign PIDs opened this
    pub handle_source_pids: HashSet<u32>, // Who opened handles to this (bounded)
}

impl ProcessMemoryState {
    pub fn new(pid: u32, now_ts: u64) -> Self {
        Self {
            pid,
            first_seen: now_ts,
            last_seen: now_ts,
            regions: Vec::with_capacity(MAX_REGIONS_PER_PID),
            suspicious_allocs: 0,
            remote_writes: 0,
            remote_threads: 0,
            apc_injections: 0,
            created_suspended: false,
            image_unmapped: false,
            executable_write: false,
            resumed: false,
            foreign_handle_opens: 0,
            handle_source_pids: HashSet::with_capacity(8),
        }
    }

    /// Record a memory allocation. Bounded to MAX_REGIONS_PER_PID.
    pub fn add_region(&mut self, region: MemoryRegion) {
        if self.regions.len() < MAX_REGIONS_PER_PID {
            // Check RWX abuse
            if region.protection == PAGE_EXECUTE_READWRITE
                && !region.is_image_backed
                && region.size >= 4096
            {
                self.suspicious_allocs += 1;
            }
            self.regions.push(region);
        }
    }

    /// Check if an address falls within a known image-backed region.
    pub fn is_address_in_image(&self, addr: u64) -> bool {
        self.regions
            .iter()
            .any(|r| r.is_image_backed && addr >= r.base && addr < r.base + r.size)
    }

    /// Record a handle open from a foreign PID. Bounded.
    pub fn record_handle_open(&mut self, source_pid: u32) {
        self.foreign_handle_opens += 1;
        if self.handle_source_pids.len() < MAX_TRACKED_IPS_PER_PID {
            self.handle_source_pids.insert(source_pid);
        }
    }

    /// Hollowing state machine progress.
    pub fn hollowing_stage(&self) -> u8 {
        let mut stage = 0;
        if self.created_suspended {
            stage += 1;
        }
        if self.image_unmapped {
            stage += 1;
        }
        if self.executable_write {
            stage += 1;
        }
        if self.resumed {
            stage += 1;
        }
        stage
    }
}
