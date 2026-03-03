use crossbeam::channel::Receiver;
use std::thread;

use crate::common::normalized_event::{EventKind, NormalizedEvent, SharedEvent};
use crate::storage::hashchain;
use crate::storage::sqlite_store::{EventRecord, SqliteStore};

const BATCH_SIZE: usize = 256;
const DB_PATH: &str = "data/sentinel_forensic.db";

pub fn start_writer_thread(rx: Receiver<SharedEvent>) {
    thread::spawn(move || {
        writer_loop(rx);
    });
}

fn writer_loop(rx: Receiver<SharedEvent>) {
    let store: SqliteStore = match SqliteStore::open(DB_PATH) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FATAL: Cannot open forensic DB: {}", e);
            return;
        }
    };

    // Resume chain from last stored hash, or start from genesis
    let mut previous_hash = store
        .load_last_chain_hash()
        .unwrap_or_else(|| hashchain::genesis_hash());

    println!(
        "Forensic Writer started. Chain root: {}",
        hex::encode(&previous_hash[..8])
    );

    let mut batch_events: Vec<SharedEvent> = Vec::with_capacity(BATCH_SIZE);
    let mut tick: u64 = 0;

    loop {
        batch_events.clear();

        // Block for first event
        match rx.recv() {
            Ok(event) => batch_events.push(event),
            Err(_) => {
                println!("Forensic Writer: channel closed, shutting down.");
                break;
            }
        }

        // Fill batch non-blocking
        while batch_events.len() < BATCH_SIZE {
            match rx.try_recv() {
                Ok(event) => batch_events.push(event),
                Err(_) => break,
            }
        }

        // Build EventRecords with hashchain
        let mut records: Vec<EventRecord> = Vec::with_capacity(batch_events.len());

        for event in &batch_events {
            let (ts, kind_u8, proc_name, pid, ppid, dst_ip, dst_port) = extract_fields(event);

            let raw_hash = hashchain::compute_raw_hash(
                ts,
                kind_u8,
                pid,
                ppid,
                proc_name.as_deref().unwrap_or(""),
                dst_ip.as_deref().unwrap_or(""),
                dst_port,
            );

            let chain_hash = hashchain::compute_chain_hash(&previous_hash, &raw_hash);

            records.push(EventRecord {
                ts,
                event_kind: kind_u8,
                process_name: proc_name,
                pid,
                parent_pid: ppid,
                src_ip: None,
                src_port: None,
                dst_ip,
                dst_port: Some(dst_port),
                signature: None,
                severity: None,
                raw_hash,
                chain_hash,
            });

            previous_hash = chain_hash;
        }

        // Bulk insert
        if let Err(e) = store.insert_batch(&records) {
            eprintln!("Forensic Writer: batch insert error: {}", e);
        }

        // Store chain root in metadata every 10 batches
        tick += 1;
        if tick % 10 == 0 {
            let _ = store.set_metadata("chain_root", &hex::encode(previous_hash));
        }

        // WAL checkpoint every 100 batches
        if tick % 100 == 0 {
            let _ = store.checkpoint();
        }
    }
}

fn extract_fields(
    event: &NormalizedEvent,
) -> (u64, u8, Option<String>, u32, u32, Option<String>, u16) {
    let ts = event.timestamp;
    let kind_u8 = match event.kind {
        EventKind::ProcessStart => 1,
        EventKind::ProcessStop => 2,
        EventKind::NetworkConnect => 3,
        EventKind::RegistrySet => 4,
        EventKind::KernelTelemetry => 5,
    };

    let (proc_name, pid, ppid) = if let Some(ref p) = event.process {
        (Some(p.image.to_string()), p.pid, p.ppid)
    } else {
        (None, 0, 0)
    };

    let (dst_ip, dst_port) = if let Some(ref n) = event.network {
        (Some(n.dst_ip.to_string()), n.dst_port)
    } else {
        (None, 0)
    };

    (ts, kind_u8, proc_name, pid, ppid, dst_ip, dst_port)
}
