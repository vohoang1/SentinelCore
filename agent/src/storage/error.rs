#![allow(dead_code, unused_imports)]
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database corruption detected")]
    Corruption,

    #[error("Disk full — cannot write")]
    DiskFull,

    #[error("Permission denied on database file")]
    PermissionDenied,

    #[error("Constraint violation")]
    Constraint,

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

impl StorageError {
    /// Map raw rusqlite errors to domain-specific StorageError variants.
    pub fn from_sqlite(err: rusqlite::Error) -> Self {
        if let rusqlite::Error::SqliteFailure(ref e, _) = err {
            match e.extended_code {
                13 => return StorageError::DiskFull,        // SQLITE_FULL
                3 => return StorageError::PermissionDenied, // SQLITE_PERM
                2067 => return StorageError::Constraint,    // SQLITE_CONSTRAINT_UNIQUE
                _ => {}
            }
        }
        StorageError::Sqlite(err)
    }
}
