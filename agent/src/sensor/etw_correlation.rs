use std::collections::HashMap;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};

use crate::common::normalized_event::EtwCorrelationInfo;

const MAX_TRACKED_PIDS: usize = 20_000;
const STALE_TTL_SECS: u64 = 120;

#[derive(Clone)]
struct PidTimeline {
    last_seen_ts: u64,
    last_image: Option<Arc<str>>,
}

static ETW_TIMELINE: OnceLock<Mutex<HashMap<u32, PidTimeline>>> = OnceLock::new();

fn timeline() -> &'static Mutex<HashMap<u32, PidTimeline>> {
    ETW_TIMELINE.get_or_init(|| Mutex::new(HashMap::with_capacity(8192)))
}

pub fn record_process_event(pid: u32, ts: u64, image: Option<Arc<str>>) {
    if pid == 0 {
        return;
    }

    let mut guard = timeline().lock().unwrap();
    if guard.len() >= MAX_TRACKED_PIDS && !guard.contains_key(&pid) {
        return;
    }

    let entry = guard.entry(pid).or_insert(PidTimeline {
        last_seen_ts: ts,
        last_image: None,
    });

    entry.last_seen_ts = ts;
    if image.is_some() {
        entry.last_image = image;
    }
}

pub fn record_image_load(pid: u32, ts: u64, image: Option<Arc<str>>) {
    record_process_event(pid, ts, image);
}

pub fn correlate(pid: u32, now_ts: u64, window_secs: u64) -> EtwCorrelationInfo {
    if pid == 0 {
        return EtwCorrelationInfo {
            seen_in_window: false,
            last_seen_ts: None,
            image: None,
        };
    }

    let guard = timeline().lock().unwrap();
    if let Some(item) = guard.get(&pid) {
        let age = now_ts.saturating_sub(item.last_seen_ts);
        if age <= window_secs {
            return EtwCorrelationInfo {
                seen_in_window: true,
                last_seen_ts: Some(item.last_seen_ts),
                image: item.last_image.clone(),
            };
        }
    }

    EtwCorrelationInfo {
        seen_in_window: false,
        last_seen_ts: None,
        image: None,
    }
}

pub fn prune(now_ts: u64) {
    let mut guard = timeline().lock().unwrap();
    guard.retain(|_, item| now_ts.saturating_sub(item.last_seen_ts) <= STALE_TTL_SECS);
}
