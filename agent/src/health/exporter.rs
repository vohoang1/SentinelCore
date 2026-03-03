use std::fs::{self, OpenOptions};
use std::io::Write;

use crate::health::metrics::CORE_METRICS;
use crate::health::monitor::HealthState;

pub struct HealthExporter {
    log_path: String,
}

impl HealthExporter {
    pub fn new() -> Self {
        let dir = "logs";
        let _ = fs::create_dir_all(dir);
        Self {
            log_path: format!("{}/health.jsonl", dir),
        }
    }

    pub fn export(&mut self, state: HealthState) {
        let snap = CORE_METRICS.snapshot();

        // Build JSON line manually to avoid serde_json dependency
        let json = format!(
            r#"{{"events_ingested":{},"events_processed":{},"events_dropped":{},"queue_depth":{},"worker_busy":{},"etw_errors":{},"etw_restarts":{},"signature_hits":{},"health":"{}"}}"#,
            snap.events_ingested,
            snap.events_processed,
            snap.events_dropped,
            snap.queue_depth,
            snap.worker_busy,
            snap.etw_errors,
            snap.etw_restarts,
            snap.signature_hits,
            state.as_str(),
        );

        // Console dump
        println!("[TELEMETRY] {}", json);

        // Append to JSONL file (one JSON per line, no locking needed — single writer)
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
        {
            let _ = writeln!(file, "{}", json);
        }
    }
}
