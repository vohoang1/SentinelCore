use std::mem::{size_of, zeroed};
use std::ptr::null;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Etw::*;

use crate::common::normalized_event::{EventKind, NormalizedEvent, Priority, ProcessInfo};
use crate::pipeline::bus::EventBus;
use crate::sensor::etw_correlation;
use crate::sensor::etw_network;
use std::time::{SystemTime, UNIX_EPOCH};

const PROCESS_PROVIDER: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);

const NETWORK_PROVIDER: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);

const IMAGE_PROVIDER: GUID = GUID::from_u128(0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518);

pub static ETW_EVENTS_RECEIVED: AtomicU64 = AtomicU64::new(0);
pub static ETW_EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);

pub struct EtwListener;

static mut GLOBAL_BUS: Option<Arc<EventBus>> = None;

impl EtwListener {
    pub fn start(bus: Arc<EventBus>) {
        // Inject bus to global mutable state for C callback access
        unsafe {
            GLOBAL_BUS = Some(bus.clone());
        }

        thread::spawn(move || unsafe {
            Self::run();
        });
    }

    unsafe fn run() {
        let session_name: Vec<u16> = "SentinelCoreSession\0".encode_utf16().collect();

        let properties_size = size_of::<EVENT_TRACE_PROPERTIES>() + 1024;

        let mut retry_count: u32 = 0;

        loop {
            let mut buffer = vec![0u8; properties_size];
            let properties = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

            (*properties).Wnode.BufferSize = properties_size as u32;
            (*properties).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*properties).Wnode.ClientContext = 1;
            (*properties).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*properties).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;

            let mut session_handle: CONTROLTRACE_HANDLE = CONTROLTRACE_HANDLE { Value: 0 };

            // Try to stop any existing orphaned session First
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                PCWSTR(session_name.as_ptr()),
                properties,
                EVENT_TRACE_CONTROL_STOP,
            );

            let status = StartTraceW(
                &mut session_handle,
                PCWSTR(session_name.as_ptr()),
                properties,
            );

            if status.is_err() {
                retry_count += 1;
                crate::health::metrics::CORE_METRICS.record_etw_error();
                let delay = 2u64.pow(retry_count.min(4));
                eprintln!(
                    "Failed StartTraceW: {:?}. Retry {} in {}s...",
                    status, retry_count, delay
                );
                if retry_count > 3 {
                    eprintln!(
                        "🚨 CRITICAL: ETW failed {} times — agent is blind!",
                        retry_count
                    );
                }
                thread::sleep(std::time::Duration::from_secs(delay));
                continue;
            }
            retry_count = 0; // Success — reset counter

            let _ = EnableTraceEx2(
                session_handle,
                &PROCESS_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0 as u32,
                TRACE_LEVEL_VERBOSE as u8,
                EVENT_TRACE_FLAG_PROCESS.0 as u64,
                0,
                0,
                Some(null()),
            );

            let _ = EnableTraceEx2(
                session_handle,
                &NETWORK_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0 as u32,
                TRACE_LEVEL_VERBOSE as u8,
                EVENT_TRACE_FLAG_NETWORK_TCPIP.0 as u64,
                0,
                0,
                Some(null()),
            );

            let _ = EnableTraceEx2(
                session_handle,
                &IMAGE_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0 as u32,
                TRACE_LEVEL_VERBOSE as u8,
                EVENT_TRACE_FLAG_IMAGE_LOAD.0 as u64,
                0,
                0,
                Some(null()),
            );

            let mut logfile: EVENT_TRACE_LOGFILEW = zeroed();
            logfile.LoggerName = PWSTR(session_name.as_ptr() as _);
            logfile.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Anonymous2.EventRecordCallback = Some(event_callback);
            logfile.BufferCallback = Some(buffer_callback);

            let trace_handle = OpenTraceW(&mut logfile);
            if trace_handle.Value == (!0 as u64) {
                eprintln!(
                    "Failed OpenTraceW. Retry in {}s...",
                    2u64.pow(retry_count.min(4) + 1)
                );
                crate::health::metrics::CORE_METRICS.record_etw_error();
                let _ = ControlTraceW(
                    session_handle,
                    PCWSTR(session_name.as_ptr()),
                    properties,
                    EVENT_TRACE_CONTROL_STOP,
                );
                retry_count += 1;
                thread::sleep(std::time::Duration::from_secs(2u64.pow(retry_count.min(4))));
                continue;
            }

            println!("ETW Listener thread started: SentinelCoreSession");

            // Blocking call that processes events in a loop
            let _ = ProcessTrace(&[trace_handle], None, None);

            println!("ProcessTrace exited unexpectedly! Cleaning up and restarting ETW session...");

            // If we break out of ProcessTrace, it usually means the session was killed or corrupted.
            let _ = ControlTraceW(
                session_handle,
                PCWSTR(session_name.as_ptr()),
                properties,
                EVENT_TRACE_CONTROL_STOP,
            );

            crate::health::metrics::CORE_METRICS.record_etw_restart();
            // Exponential backoff on restart
            retry_count += 1;
            let delay = 2u64.pow(retry_count.min(4));
            thread::sleep(std::time::Duration::from_secs(delay));
        }
    }
}

unsafe extern "system" fn buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    let header = (*logfile).LogfileHeader;
    if header.BuffersLost > 0 {
        ETW_EVENTS_DROPPED.fetch_add(header.BuffersLost as u64, Ordering::Relaxed);
        println!("WARNING: ETW Buffers lost detected: {}", header.BuffersLost);
    }
    1
}

unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
    ETW_EVENTS_RECEIVED.fetch_add(1, Ordering::Relaxed);
    crate::health::metrics::CORE_METRICS.touch_heartbeat();
    crate::health::metrics::CORE_METRICS.record_ingested();

    let provider = (*record).EventHeader.ProviderId;

    if let Some(bus) = &GLOBAL_BUS {
        if provider == PROCESS_PROVIDER {
            handle_process(record, bus);
        } else if provider == IMAGE_PROVIDER {
            handle_image_load(record);
        } else if provider == NETWORK_PROVIDER {
            etw_network::handle_network(record, bus);
        }
    }
}

unsafe fn handle_process(record: *mut EVENT_RECORD, bus: &Arc<EventBus>) {
    let opcode = (*record).EventHeader.EventDescriptor.Opcode;
    let event_kind = match opcode {
        1 => EventKind::ProcessStart,
        2 => EventKind::ProcessStop,
        _ => return,
    };

    let timestamp = now();
    let pid = (*record).EventHeader.ProcessId;
    let image = extract_utf16_string(record);
    etw_correlation::record_process_event(pid, timestamp, image.clone());

    let event = NormalizedEvent {
        kind: event_kind,
        timestamp,
        priority: Priority::Medium,
        process: Some(ProcessInfo {
            pid,
            ppid: 0,
            image: image.unwrap_or_else(|| Arc::from("unknown")),
            command_line: None,
        }),
        network: None,
        registry: None,
        kernel: None,
    };

    bus.try_enqueue(Arc::new(event));
}

unsafe fn handle_image_load(record: *mut EVENT_RECORD) {
    let pid = (*record).EventHeader.ProcessId;
    let timestamp = now();
    let image = extract_utf16_string(record);
    etw_correlation::record_image_load(pid, timestamp, image);
}

unsafe fn extract_utf16_string(record: *mut EVENT_RECORD) -> Option<Arc<str>> {
    let len = (*record).UserDataLength as usize;
    if len < 2 || (*record).UserData.is_null() {
        return None;
    }

    let u16_len = len / 2;
    let raw = std::slice::from_raw_parts((*record).UserData as *const u16, u16_len);
    let end = raw.iter().position(|&c| c == 0).unwrap_or(u16_len);
    if end == 0 {
        return None;
    }

    let text = String::from_utf16_lossy(&raw[..end]).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(Arc::from(text))
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
