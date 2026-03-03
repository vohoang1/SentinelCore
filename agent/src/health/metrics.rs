#![allow(dead_code, unused_imports)]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Global zero-lock metrics registry.
/// All fields are atomic — no Mutex, no heap allocation on hot path.
pub struct CoreMetrics {
    // Ingestion
    pub events_ingested: AtomicU64,
    pub events_processed: AtomicU64,
    pub events_dropped: AtomicU64,

    // Pipeline
    pub queue_depth: AtomicUsize,
    pub worker_busy: AtomicUsize,

    // ETW
    pub etw_errors: AtomicU64,
    pub etw_restarts: AtomicU64,

    // Detection
    pub signature_hits: AtomicU64,

    // Heartbeat
    pub last_event_ts: AtomicU64,
}

impl CoreMetrics {
    pub const fn new() -> Self {
        Self {
            events_ingested: AtomicU64::new(0),
            events_processed: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            queue_depth: AtomicUsize::new(0),
            worker_busy: AtomicUsize::new(0),
            etw_errors: AtomicU64::new(0),
            etw_restarts: AtomicU64::new(0),
            signature_hits: AtomicU64::new(0),
            last_event_ts: AtomicU64::new(0),
        }
    }

    pub fn record_ingested(&self) {
        self.events_ingested.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_processed(&self, count: u64) {
        self.events_processed.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_dropped(&self) {
        self.events_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_signature_hit(&self) {
        self.signature_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_etw_error(&self) {
        self.etw_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_etw_restart(&self) {
        self.etw_restarts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn touch_heartbeat(&self) {
        self.last_event_ts
            .store(now_epoch_secs(), Ordering::Relaxed);
    }

    pub fn worker_enter(&self) {
        self.worker_busy.fetch_add(1, Ordering::Relaxed);
    }

    pub fn worker_exit(&self) {
        self.worker_busy.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            events_ingested: self.events_ingested.load(Ordering::Relaxed),
            events_processed: self.events_processed.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            worker_busy: self.worker_busy.load(Ordering::Relaxed),
            etw_errors: self.etw_errors.load(Ordering::Relaxed),
            etw_restarts: self.etw_restarts.load(Ordering::Relaxed),
            signature_hits: self.signature_hits.load(Ordering::Relaxed),
            last_event_ts: self.last_event_ts.load(Ordering::Relaxed),
        }
    }
}

/// Immutable point-in-time snapshot for export and decision making.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub events_ingested: u64,
    pub events_processed: u64,
    pub events_dropped: u64,
    pub queue_depth: usize,
    pub worker_busy: usize,
    pub etw_errors: u64,
    pub etw_restarts: u64,
    pub signature_hits: u64,
    pub last_event_ts: u64,
}

/// Global singleton — initialized at startup, referenced everywhere via &CORE_METRICS.
pub static CORE_METRICS: CoreMetrics = CoreMetrics::new();

pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
