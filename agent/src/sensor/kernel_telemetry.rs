use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::cloud::kernel_comms::{KernelComm, TelemetryEvent};
use crate::common::normalized_event::{
    EventKind, KernelTelemetryInfo, NormalizedEvent, Priority, ProcessInfo,
};
use crate::pipeline::bus::EventBus;
use crate::sensor::etw_correlation;

const POLL_INTERVAL_MS: u64 = 200;
const MAX_READ_EVENTS: usize = 128;
const CORRELATION_WINDOW_SECS: u64 = 30;

pub struct KernelTelemetryListener;

impl KernelTelemetryListener {
    pub fn start(bus: Arc<EventBus>, kernel: Arc<KernelComm>) {
        thread::spawn(move || loop {
            let now_ts = crate::sensor::etw_listener::now();
            let events = kernel.read_telemetry(MAX_READ_EVENTS);

            for evt in events {
                let normalized = to_normalized(evt, now_ts);
                bus.try_enqueue(Arc::new(normalized));
            }

            etw_correlation::prune(now_ts);
            thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
        });
    }
}

fn to_normalized(evt: TelemetryEvent, now_ts: u64) -> NormalizedEvent {
    let source_etw = etw_correlation::correlate(evt.source_pid, now_ts, CORRELATION_WINDOW_SECS);
    let target_etw = etw_correlation::correlate(evt.target_pid, now_ts, CORRELATION_WINDOW_SECS);
    let detail = evt.detail_string();

    NormalizedEvent {
        kind: EventKind::KernelTelemetry,
        timestamp: now_ts,
        priority: Priority::High,
        process: Some(ProcessInfo {
            pid: evt.source_pid,
            ppid: 0,
            image: source_etw
                .image
                .clone()
                .unwrap_or_else(|| Arc::from("unknown")),
            command_line: None,
        }),
        network: None,
        registry: None,
        kernel: Some(KernelTelemetryInfo {
            raw_kernel_timestamp: evt.timestamp,
            event_type: evt.event_type,
            event_name: Arc::from(evt.type_name()),
            source_pid: evt.source_pid,
            target_pid: evt.target_pid,
            original_access: evt.original_access,
            stripped_access: evt.stripped_access,
            detail: if detail.is_empty() {
                None
            } else {
                Some(Arc::from(detail))
            },
            source_etw,
            target_etw,
        }),
    }
}
