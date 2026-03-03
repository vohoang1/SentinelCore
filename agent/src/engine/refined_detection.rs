use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use crate::common::normalized_event::{EventKind, NormalizedEvent};
use crate::engine::context_signature::{Alert, EngineContext, Signature};

pub struct RefinedNetworkSpike {
    recent: Mutex<Vec<(Instant, u32, IpAddr, u16)>>, // (time, pid, dst_ip, dst_port)
}

impl RefinedNetworkSpike {
    pub fn new() -> Self {
        Self {
            recent: Mutex::new(Vec::new()),
        }
    }
}

impl Signature for RefinedNetworkSpike {
    fn evaluate(&self, event: &NormalizedEvent, _ctx: &EngineContext) -> Option<Alert> {
        if event.kind != EventKind::NetworkConnect {
            return None;
        }

        let net = event.network.as_ref()?;
        let now = Instant::now();

        let mut recent = self.recent.lock().unwrap();

        // Add current event
        recent.push((now, net.pid, net.dst_ip, net.dst_port));

        // Clean old entries (>5s)
        recent.retain(|(t, _, _, _)| now.duration_since(*t).as_secs() < 5);

        // Process-specific spike
        let pid_count = recent.iter().filter(|(_, p, _, _)| *p == net.pid).count();
        if pid_count > 50 {
            return Some(Alert::new(&format!(
                "Process-specific network spike: PID {} made {} connections in 5s",
                net.pid, pid_count
            )));
        }

        // Unique destination analysis
        let unique_ips: HashSet<_> = recent.iter().map(|(_, _, ip, _)| ip).collect();
        let unique_ports: HashSet<_> = recent.iter().map(|(_, _, _, port)| port).collect();

        // Port scan signature: many unique ports, few IPs
        if unique_ports.len() > 20 && unique_ips.len() < 5 {
            return Some(Alert::new(&format!(
                "Port scan detected: {} unique ports to {} IPs",
                unique_ports.len(),
                unique_ips.len()
            )));
        }

        // Network scan signature: many unique IPs
        if unique_ips.len() > 30 {
            return Some(Alert::new(&format!(
                "Network scan detected: {} unique destinations",
                unique_ips.len()
            )));
        }

        None
    }
}

// Enhanced PowerShell detection with parent chain
pub struct EnhancedPowershellDetect;

impl Signature for EnhancedPowershellDetect {
    fn evaluate(&self, event: &NormalizedEvent, ctx: &EngineContext) -> Option<Alert> {
        if event.kind != EventKind::NetworkConnect {
            return None;
        }

        let net = event.network.as_ref()?;
        let proc = ctx.graph.processes.get(&net.pid)?;

        let image_lower = proc.image.to_lowercase();

        // Direct PowerShell
        if image_lower.contains("powershell") {
            if is_external_ip(net.dst_ip) {
                return Some(Alert::new("PowerShell external connection"));
            }
        }

        // Suspicious parent chain: Office → PowerShell → Network
        if let Some(parent) = ctx.graph.processes.get(&proc.ppid) {
            let parent_img = parent.image.to_lowercase();
            if (parent_img.contains("winword") || parent_img.contains("excel"))
                && image_lower.contains("powershell")
            {
                return Some(Alert::new(
                    "Office spawned PowerShell with network activity",
                ));
            }
        }

        // Rare process with immediate network
        if proc.start_time.elapsed().as_secs() < 2 {
            let is_rare = !is_common_process(&image_lower);
            if is_rare && is_external_ip(net.dst_ip) {
                return Some(Alert::new(&format!(
                    "Rare process {} connected immediately after spawn",
                    proc.image
                )));
            }
        }

        None
    }
}

fn is_external_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            !(octets[0] == 10
                || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                || (octets[0] == 192 && octets[1] == 168)
                || octets[0] == 127)
        }
        IpAddr::V6(_) => true,
    }
}

fn is_common_process(image: &str) -> bool {
    let common = [
        "chrome", "firefox", "msedge", "explorer", "svchost", "system", "services", "lsass",
        "csrss", "winlogon",
    ];
    common.iter().any(|c| image.contains(c))
}
