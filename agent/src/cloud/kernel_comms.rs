/// kernel_comms.rs — User-mode IOCTL client for the SentinelCore kernel driver
///
/// Supports 5 IOCTLs:
///   - SET_PID:             Protect our process PID
///   - CLEAR_PID:           Disable protection before exit
///   - QUERY_STATUS:        Get driver stats (handles stripped, files denied, queue depth)
///   - READ_TELEMETRY:      Drain ring buffer events from kernel
///   - AUTHORIZE_SHUTDOWN:  Send shutdown token before driver unload
use std::mem;

// ─── IOCTL code generation (matching globals.h) ─────────────────────────
const FILE_DEVICE_UNKNOWN: u32 = 0x22;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

const fn ctl_code(device: u32, function: u32, method: u32, access: u32) -> u32 {
    (device << 16) | (access << 14) | (function << 2) | method
}

const IOCTL_SENTINEL_SET_PID: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_SENTINEL_CLEAR_PID: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_SENTINEL_QUERY_STATUS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_SENTINEL_READ_TELEMETRY: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_SENTINEL_AUTHORIZE_SHUTDOWN: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);

const DEVICE_PATH: &str = "\\\\.\\SentinelKM";

// Must match SENTINEL_SHUTDOWN_TOKEN in globals.h
const SHUTDOWN_TOKEN: [u8; 16] = [
    0x53, 0x4E, 0x54, 0x4C, 0x2D, 0x41, 0x55, 0x54, 0x48, 0x2D, 0x54, 0x4F, 0x4B, 0x45, 0x4E, 0x00,
];

// ─── Structures matching kernel-side definitions ────────────────────────

/// Matches SENTINEL_STATUS in globals.h
#[repr(C)]
pub struct DriverStatus {
    pub protection_active: u32,
    pub protected_pid: u32,
    pub handles_stripped: i32,
    pub files_denied: i32,
    pub events_in_queue: u32,
}

/// Matches SENTINEL_EVENT_FLAT in globals.h
#[repr(C)]
#[derive(Clone)]
pub struct TelemetryEvent {
    pub timestamp: i64,  // LARGE_INTEGER
    pub event_type: u32, // SENTINEL_EVENT_TYPE
    pub source_pid: u32,
    pub target_pid: u32,
    pub original_access: u32, // ACCESS_MASK
    pub stripped_access: u32, // ACCESS_MASK
    pub detail: [u16; 128],   // WCHAR[128]
}

impl TelemetryEvent {
    pub fn detail_string(&self) -> String {
        let end = self
            .detail
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.detail.len());
        String::from_utf16_lossy(&self.detail[..end])
    }

    pub fn type_name(&self) -> &'static str {
        match self.event_type {
            1 => "HandleStrip",
            2 => "FileDenied",
            3 => "ProcessBlock",
            4 => "IoctlReject",
            _ => "Unknown",
        }
    }
}

// ─── KernelComm client ──────────────────────────────────────────────────

pub struct KernelComm {
    handle: isize,
}

impl KernelComm {
    /// Open handle to the kernel driver device.
    pub fn connect() -> Option<Self> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::GENERIC_READ;
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
        };

        let path: Vec<u16> = DEVICE_PATH
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                GENERIC_READ.0 | 0x40000000, // GENERIC_WRITE
                windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };

        match handle {
            Ok(h) => Some(Self { handle: h.0 }),
            Err(e) => {
                eprintln!("KernelComm: Cannot open driver device: {}", e);
                None
            }
        }
    }

    /// Tell driver to protect our PID. Registers us as the authorized service.
    pub fn set_protected_pid(&self, pid: u32) -> bool {
        let pid_bytes = pid.to_le_bytes();
        self.send_ioctl(IOCTL_SENTINEL_SET_PID, &pid_bytes)
    }

    /// Tell driver to clear protection.
    pub fn clear_protection(&self) -> bool {
        self.send_ioctl(IOCTL_SENTINEL_CLEAR_PID, &[])
    }

    /// Authorize driver unload with the shutdown token.
    pub fn authorize_shutdown(&self) -> bool {
        self.send_ioctl(IOCTL_SENTINEL_AUTHORIZE_SHUTDOWN, &SHUTDOWN_TOKEN)
    }

    /// Query driver status (protection state, counters, queue depth).
    pub fn query_status(&self) -> Option<DriverStatus> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::IO::DeviceIoControl;

        let mut status = DriverStatus {
            protection_active: 0,
            protected_pid: 0,
            handles_stripped: 0,
            files_denied: 0,
            events_in_queue: 0,
        };
        let mut bytes_returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                HANDLE(self.handle),
                IOCTL_SENTINEL_QUERY_STATUS,
                None,
                0,
                Some(&mut status as *mut _ as *mut _),
                mem::size_of::<DriverStatus>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        match ok {
            Ok(_) => Some(status),
            Err(_) => None,
        }
    }

    /// Read telemetry events from the kernel ring buffer.
    /// Returns up to `max_events` events.
    pub fn read_telemetry(&self, max_events: usize) -> Vec<TelemetryEvent> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::IO::DeviceIoControl;

        if max_events == 0 {
            return Vec::new();
        }

        let event_size = mem::size_of::<TelemetryEvent>();
        let buf_size = event_size * max_events;
        let mut buffer: Vec<u8> = vec![0u8; buf_size];
        let mut bytes_returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                HANDLE(self.handle),
                IOCTL_SENTINEL_READ_TELEMETRY,
                None,
                0,
                Some(buffer.as_mut_ptr() as *mut _),
                buf_size as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        match ok {
            Ok(_) => {
                let count = bytes_returned as usize / event_size;
                let mut events = Vec::with_capacity(count);
                for i in 0..count {
                    let offset = i * event_size;
                    let event: TelemetryEvent = unsafe {
                        std::ptr::read_unaligned(
                            buffer.as_ptr().add(offset) as *const TelemetryEvent
                        )
                    };
                    events.push(event);
                }
                events
            }
            Err(_) => Vec::new(),
        }
    }

    /// Send a raw IOCTL with input data.
    fn send_ioctl(&self, code: u32, input: &[u8]) -> bool {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::IO::DeviceIoControl;

        let mut bytes_returned: u32 = 0;
        let input_ptr = if input.is_empty() {
            None
        } else {
            Some(input.as_ptr() as *const _)
        };
        let input_len = input.len() as u32;

        let result = unsafe {
            DeviceIoControl(
                HANDLE(self.handle),
                code,
                input_ptr,
                input_len,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        };

        result.is_ok()
    }
}

impl Drop for KernelComm {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        unsafe {
            let _ = CloseHandle(HANDLE(self.handle));
        }
    }
}
