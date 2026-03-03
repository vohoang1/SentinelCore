use base64::Engine;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::cloud::identity::DeviceIdentity;
use crate::cloud::protocol::{MetricsPayload, UploadFrame};
use crate::cloud::spool::SpoolReader;
use crate::health::metrics::CORE_METRICS;
use crate::health::monitor::current_health;
use crate::storage::sqlite_store::SqliteStore;

static UPLOAD_SEQ: AtomicU64 = AtomicU64::new(0);

const MAX_RETRY_INTERVAL_SECS: u64 = 300; // 5 minutes cap

pub struct CloudUploader;

impl CloudUploader {
    /// Start the upload thread. Reads from spool, batches, compresses, uploads.
    pub fn start(identity: Arc<DeviceIdentity>, db_path: &'static str, endpoint: String) {
        thread::spawn(move || {
            upload_loop(identity, db_path, endpoint);
        });
    }
}

fn upload_loop(identity: Arc<DeviceIdentity>, db_path: &str, endpoint: String) {
    let mut retry_count: u32 = 0;

    loop {
        // Backpressure sleep
        let delay = if retry_count == 0 {
            5
        } else {
            (2u64.pow(retry_count.min(8))).min(MAX_RETRY_INTERVAL_SECS)
        };
        thread::sleep(Duration::from_secs(delay));

        // Open read-only connection to forensic DB
        let store = match SqliteStore::open(db_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("CloudUploader: cannot open DB: {}", e);
                retry_count += 1;
                continue;
            }
        };

        // Fetch pending events
        let events = SpoolReader::fetch_pending(&store);
        if events.is_empty() {
            retry_count = 0; // Nothing to upload — reset backoff
            continue;
        }

        let max_id = events.last().map(|e| e.id).unwrap_or(0);
        let seq = UPLOAD_SEQ.fetch_add(1, Ordering::Relaxed);

        // Build metrics snapshot
        let snap = CORE_METRICS.snapshot();
        let metrics = MetricsPayload {
            events_ingested: snap.events_ingested,
            events_processed: snap.events_processed,
            events_dropped: snap.events_dropped,
            queue_depth: snap.queue_depth,
            etw_errors: snap.etw_errors,
            signature_hits: snap.signature_hits,
            health_state: current_health().as_str().to_string(),
        };

        // Get chain root from metadata
        let chain_root = store.get_metadata("chain_root").unwrap_or_default();

        // Build frame
        let frame = UploadFrame {
            device_id: identity.device_id.clone(),
            seq,
            events,
            metrics,
            chain_root: chain_root.clone(),
            timestamp: crate::health::metrics::now_epoch_secs(),
            signature: String::new(), // Will be filled after serialization
        };

        // Serialize
        let json = match serde_json::to_vec(&frame) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("CloudUploader: serialize error: {}", e);
                continue;
            }
        };

        // Sign the frame
        let sig = identity.sign(&json);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        // Gzip compress (~80-95% reduction)
        let compressed = gzip_compress(&json);

        // Upload
        let upload_url = format!("{}/api/v1/telemetry", endpoint);
        match ureq::post(&upload_url)
            .set("Content-Type", "application/octet-stream")
            .set("Content-Encoding", "gzip")
            .set("X-Device-Id", &identity.device_id)
            .set("X-Signature", &sig_b64)
            .set("X-Seq", &seq.to_string())
            .send_bytes(&compressed)
        {
            Ok(resp) => {
                if resp.status() == 200 {
                    SpoolReader::mark_uploaded(&store, max_id);
                    retry_count = 0;
                    println!(
                        "CloudUploader: uploaded {} events (seq={})",
                        frame.events.len(),
                        seq
                    );
                } else {
                    eprintln!("CloudUploader: server returned {}", resp.status());
                    retry_count += 1;
                }
            }
            Err(e) => {
                eprintln!("CloudUploader: network error: {}. Retry in {}s", e, delay);
                retry_count += 1;

                // Health warning if spool is growing
                let pending = SpoolReader::pending_count(&store);
                if pending > 10_000 {
                    eprintln!("⚠️  CloudUploader: spool backlog {} events", pending);
                }
            }
        }
    }
}

fn gzip_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    let _ = encoder.write_all(data);
    encoder.finish().unwrap_or_else(|_| data.to_vec())
}
