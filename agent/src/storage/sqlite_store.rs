use rusqlite::{params, Connection};
use std::fs;
use std::path::Path;

use crate::storage::error::StorageError;

const CURRENT_SCHEMA_VERSION: i32 = 1;

const INSERT_SQL: &str = "INSERT INTO events (ts, event_kind, process_name, pid, parent_pid,
     src_ip, src_port, dst_ip, dst_port, signature, severity, raw_hash, chain_hash)
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)";

/// Event record for bulk insert API.
pub struct EventRecord {
    pub ts: u64,
    pub event_kind: u8,
    pub process_name: Option<String>,
    pub pid: u32,
    pub parent_pid: u32,
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub signature: Option<String>,
    pub severity: Option<u8>,
    pub raw_hash: [u8; 32],
    pub chain_hash: [u8; 32],
}

/// SQLite forensic store — WAL mode, indexed, schema-versioned.
pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    pub fn open(db_path: &str) -> Result<Self, StorageError> {
        if let Some(parent) = Path::new(db_path).parent() {
            let _ = fs::create_dir_all(parent);
        }

        let conn = Connection::open(db_path)?;

        // WAL mode for crash safety + concurrent reads
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA temp_store=MEMORY;
             PRAGMA mmap_size=268435456;",
        )?;

        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), StorageError> {
        // Schema version table
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            );",
        )?;

        // Metadata table
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            );",
        )?;

        let version: i32 = self
            .conn
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);

        if version < CURRENT_SCHEMA_VERSION {
            self.run_migrations(version)?;
        }

        Ok(())
    }

    fn run_migrations(&self, from_version: i32) -> Result<(), StorageError> {
        if from_version < 1 {
            // V1: Core events table + indexes
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    event_kind INTEGER NOT NULL,
                    process_name TEXT,
                    pid INTEGER,
                    parent_pid INTEGER,
                    src_ip TEXT,
                    src_port INTEGER,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    signature TEXT,
                    severity INTEGER,
                    raw_hash BLOB NOT NULL,
                    chain_hash BLOB NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
                CREATE INDEX IF NOT EXISTS idx_events_kind ON events(event_kind);
                CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);
                CREATE INDEX IF NOT EXISTS idx_events_signature ON events(signature);

                DELETE FROM schema_version;
                INSERT INTO schema_version (version) VALUES (1);",
            )?;
        }

        Ok(())
    }

    // ─── Bulk Insert API ────────────────────────────────────────

    /// Batch insert with a single transaction. Uses prepare_cached for perf.
    pub fn insert_batch(&self, records: &[EventRecord]) -> Result<(), StorageError> {
        let tx = self.conn.unchecked_transaction()?;

        {
            let mut stmt = tx.prepare_cached(INSERT_SQL)?;
            for ev in records {
                stmt.execute(params![
                    ev.ts as i64,
                    ev.event_kind as i64,
                    ev.process_name.as_deref(),
                    ev.pid as i64,
                    ev.parent_pid as i64,
                    ev.src_ip.as_deref(),
                    ev.src_port.map(|v| v as i64),
                    ev.dst_ip.as_deref(),
                    ev.dst_port.map(|v| v as i64),
                    ev.signature.as_deref(),
                    ev.severity.map(|v| v as i64),
                    ev.raw_hash.as_slice(),
                    ev.chain_hash.as_slice(),
                ])?;
            }
        }

        tx.commit()?;
        Ok(())
    }

    // ─── Query APIs (read-only investigation) ───────────────────

    pub fn get_events_by_pid(&self, pid: u32) -> Result<Vec<(i64, i64, String)>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, ts, COALESCE(process_name,'') FROM events WHERE pid = ?1 ORDER BY ts ASC",
        )?;
        let rows = stmt.query_map(params![pid as i64], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn get_events_by_time_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<(i64, i64, i64)>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, ts, event_kind FROM events WHERE ts >= ?1 AND ts <= ?2 ORDER BY ts ASC",
        )?;
        let rows = stmt.query_map(params![start as i64, end as i64], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn search_by_signature(
        &self,
        pattern: &str,
    ) -> Result<Vec<(i64, i64, String)>, StorageError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, ts, signature FROM events WHERE signature LIKE ?1 ORDER BY ts ASC",
        )?;
        let like_pattern = format!("%{}%", pattern);
        let rows = stmt.query_map(params![like_pattern], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get::<_, String>(2)?))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // ─── WAL Checkpoint ─────────────────────────────────────────

    pub fn checkpoint(&self) -> Result<(), StorageError> {
        self.conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")?;
        Ok(())
    }

    // ─── Metadata ───────────────────────────────────────────────

    pub fn set_metadata(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_metadata(&self, key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .ok()
    }

    // ─── Chain Hash Recovery ────────────────────────────────────

    pub fn load_last_chain_hash(&self) -> Option<[u8; 32]> {
        let mut stmt = self
            .conn
            .prepare("SELECT chain_hash FROM events ORDER BY id DESC LIMIT 1")
            .ok()?;

        let blob: Option<Vec<u8>> = stmt.query_row([], |row| row.get(0)).ok();

        blob.and_then(|v| {
            if v.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                Some(arr)
            } else {
                None
            }
        })
    }

    /// Get connection ref for verification queries.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    // ─── Rotation / Cleanup ─────────────────────────────────────

    #[allow(dead_code)]
    pub fn cleanup_before(&self, ts: u64) -> Result<usize, StorageError> {
        let deleted = self
            .conn
            .execute("DELETE FROM events WHERE ts < ?1", params![ts as i64])?;
        Ok(deleted)
    }
}
