use crate::storage::hashchain;
use crate::storage::sqlite_store::SqliteStore;

/// Verify the entire hashchain integrity of the forensic database.
/// Returns Ok(row_count) if all rows are valid, or Err with the first tampered row ID.
pub fn verify_chain(db_path: &str) -> Result<u64, String> {
    let store = SqliteStore::open(db_path).map_err(|e| format!("Cannot open DB: {}", e))?;

    let conn = store.connection();
    let mut stmt = conn
        .prepare("SELECT id, ts, event_kind, process_name, pid, parent_pid, dst_ip, dst_port, raw_hash, chain_hash FROM events ORDER BY id ASC")
        .map_err(|e| format!("Query error: {}", e))?;

    let mut previous_hash = hashchain::genesis_hash();
    let mut count: u64 = 0;

    let rows = stmt
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let ts: i64 = row.get(1)?;
            let event_kind: i64 = row.get(2)?;
            let process_name: Option<String> = row.get(3)?;
            let pid: Option<i64> = row.get(4)?;
            let ppid: Option<i64> = row.get(5)?;
            let dst_ip: Option<String> = row.get(6)?;
            let dst_port: Option<i64> = row.get(7)?;
            let raw_hash_blob: Vec<u8> = row.get(8)?;
            let chain_hash_blob: Vec<u8> = row.get(9)?;
            Ok((
                id,
                ts,
                event_kind,
                process_name,
                pid,
                ppid,
                dst_ip,
                dst_port,
                raw_hash_blob,
                chain_hash_blob,
            ))
        })
        .map_err(|e| format!("Query map error: {}", e))?;

    for row_result in rows {
        let (
            id,
            ts,
            event_kind,
            process_name,
            pid,
            ppid,
            dst_ip,
            dst_port,
            raw_hash_blob,
            chain_hash_blob,
        ) = row_result.map_err(|e| format!("Row error: {}", e))?;

        // Recompute raw_hash
        let recomputed_raw = hashchain::compute_raw_hash(
            ts as u64,
            event_kind as u8,
            pid.unwrap_or(0) as u32,
            ppid.unwrap_or(0) as u32,
            process_name.as_deref().unwrap_or(""),
            dst_ip.as_deref().unwrap_or(""),
            dst_port.unwrap_or(0) as u16,
        );

        // Check raw_hash integrity
        if raw_hash_blob.len() != 32 || recomputed_raw != raw_hash_blob.as_slice() {
            return Err(format!("TAMPERED: raw_hash mismatch at row id={}", id));
        }

        // Recompute chain_hash
        let mut stored_raw = [0u8; 32];
        stored_raw.copy_from_slice(&raw_hash_blob);

        let recomputed_chain = hashchain::compute_chain_hash(&previous_hash, &stored_raw);

        if chain_hash_blob.len() != 32 || recomputed_chain != chain_hash_blob.as_slice() {
            return Err(format!("TAMPERED: chain_hash mismatch at row id={}", id));
        }

        let mut stored_chain = [0u8; 32];
        stored_chain.copy_from_slice(&chain_hash_blob);
        previous_hash = stored_chain;
        count += 1;
    }

    println!(
        "Chain integrity verified: {} rows OK. Root: {:x?}",
        count,
        &previous_hash[..8]
    );
    Ok(count)
}
