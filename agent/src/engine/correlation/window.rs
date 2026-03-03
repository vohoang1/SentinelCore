/// Temporal window logic using pure arithmetic.
/// No event queues, no timers — just timestamp math.

/// Check if a count exceeds threshold within a time window.
pub fn exceeds_rate(
    count: u32,
    window_start: u64,
    now: u64,
    window_secs: u64,
    threshold: u32,
) -> bool {
    if now.saturating_sub(window_start) > window_secs {
        return false; // Window expired, counters should have been reset
    }
    count > threshold
}

/// Compute events-per-second rate for a window.
pub fn rate_per_second(count: u32, window_start: u64, now: u64) -> f64 {
    let elapsed = now.saturating_sub(window_start).max(1);
    count as f64 / elapsed as f64
}
