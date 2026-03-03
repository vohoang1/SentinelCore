use sha2::{Digest, Sha256};

/// Genesis seed — the very first link in the chain.
const GENESIS_SEED: &[u8] = b"SentinelCoreGenesis";

/// Compute the raw hash of an event using deterministic binary layout.
/// Fields are concatenated in fixed order: ts || event_kind || pid || ppid || image || dst_ip || dst_port
pub fn compute_raw_hash(
    ts: u64,
    event_kind: u8,
    pid: u32,
    ppid: u32,
    image: &str,
    dst_ip: &str,
    dst_port: u16,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ts.to_le_bytes());
    hasher.update(event_kind.to_le_bytes());
    hasher.update(pid.to_le_bytes());
    hasher.update(ppid.to_le_bytes());
    hasher.update(image.as_bytes());
    hasher.update(dst_ip.as_bytes());
    hasher.update(dst_port.to_le_bytes());
    hasher.finalize().into()
}

/// Compute the next chain hash: SHA256(previous_chain_hash || raw_hash)
pub fn compute_chain_hash(previous: &[u8; 32], raw_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(previous);
    hasher.update(raw_hash);
    hasher.finalize().into()
}

/// Genesis chain hash — the root of the chain.
pub fn genesis_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GENESIS_SEED);
    hasher.finalize().into()
}
