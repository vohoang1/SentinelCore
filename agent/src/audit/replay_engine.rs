use super::logger::AuditEvent;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn replay_logs(log_path: &str) -> std::io::Result<Vec<AuditEvent>> {
    let file = File::open(log_path)?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        match serde_json::from_str::<AuditEvent>(&line) {
            Ok(evt) => {
                let integrity_status = evt.hash_integrity.as_deref().unwrap_or("UNVERIFIED");
                println!(
                    "[REPLAY] PID: {:?} | SecLevel: {:?} | Decision: {} | Integrity: {}",
                    evt.source_pid, evt.security_level, evt.decision, integrity_status
                );
                events.push(evt);
            }
            Err(e) => {
                eprintln!(
                    "[REPLAY] Failed to parse historical log entry payload: {}",
                    e
                );
            }
        }
    }

    Ok(events)
}
