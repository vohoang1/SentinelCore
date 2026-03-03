use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;

use crate::common::normalized_event::{EventKind, NetworkInfo, NormalizedEvent, Priority};
use crate::pipeline::bus::EventBus;

#[repr(C)]
pub struct TcpIpConnect {
    pub process_id: u32,
    pub local_addr: u32,
    pub remote_addr: u32,
    pub local_port: u16,
    pub remote_port: u16,
}

pub unsafe fn handle_network(record: *mut EVENT_RECORD, bus: &Arc<EventBus>) {
    let opcode = (*record).EventHeader.EventDescriptor.Opcode;

    // TCP Connect opcode = 10
    if opcode != 10 {
        return;
    }

    let data = (*record).UserData as *const TcpIpConnect;
    if data.is_null() || (*record).UserDataLength < std::mem::size_of::<TcpIpConnect>() as u16 {
        return;
    }

    let pid = (*data).process_id;
    let dst_ip = IpAddr::V4(Ipv4Addr::from(u32::from_be((*data).remote_addr)));
    let dst_port = u16::from_be((*data).remote_port);

    let event = NormalizedEvent {
        kind: EventKind::NetworkConnect,
        timestamp: crate::sensor::etw_listener::now(),
        priority: Priority::Medium,
        process: None,
        network: Some(NetworkInfo {
            pid,
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip,
            dst_port,
            protocol: 6, // TCP
        }),
        registry: None,
        kernel: None,
    };

    bus.try_enqueue(Arc::new(event));
}
