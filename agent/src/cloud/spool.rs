use crate::cloud::protocol::EventPayload;
use crate::storage::sqlite_store::SqliteStore;
use rusqlite::params;

const SPOOL_BATCH_SIZE: usize = 500;

/// Spool system: fetch un-uploaded events from SQLite, mark them after upload.
/// No data deleted until cloud ACK received.
pub struct SpoolReader;

impl SpoolReader {
    /// Add 'uploaded' column to events table if not exists (one-time migration).
    pub fn ensure_spool_column(store: &SqliteStore) {
        let _ = store
            .connection()
            .execute_batch("ALTER TABLE events ADD COLUMN uploaded INTEGER DEFAULT 0;");
        let _ = store
            .connection()
            .execute_batch("CREATE INDEX IF NOT EXISTS idx_events_uploaded ON events(uploaded);");
    }

    /// Fetch next batch of un-uploaded events.
    pub fn fetch_pending(store: &SqliteStore) -> Vec<EventPayload> {
        let conn = store.connection();
        let mut stmt = match conn.prepare(
            "SELECT id, ts, event_kind, process_name, pid, parent_pid, dst_ip, dst_port, raw_hash
             FROM events WHERE uploaded = 0 ORDER BY id ASC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = stmt.query_map(params![SPOOL_BATCH_SIZE as i64], |row| {
            let raw_hash_blob: Vec<u8> = row.get(8)?;
            Ok(EventPayload {
                id: row.get(0)?,
                ts: row.get::<_, i64>(1)? as u64,
                event_kind: row.get::<_, i64>(2)? as u8,
                process_name: row.get(3)?,
                pid: row.get::<_, i64>(4)? as u32,
                parent_pid: row.get::<_, i64>(5)? as u32,
                dst_ip: row.get(6)?,
                dst_port: row.get::<_, Option<i64>>(7)?.map(|v| v as u16),
                raw_hash: hex::encode(raw_hash_blob),
            })
        });

        match rows {
            Ok(r) => r.filter_map(|x| x.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Mark events as uploaded after cloud ACK.
    pub fn mark_uploaded(store: &SqliteStore, max_id: i64) {
        let _ = store.connection().execute(
            "UPDATE events SET uploaded = 1 WHERE id <= ?1 AND uploaded = 0",
            params![max_id],
        );
    }

    /// Count pending un-uploaded events (for health monitoring).
    pub fn pending_count(store: &SqliteStore) -> u64 {
        store
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE uploaded = 0",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0) as u64
    }
}
