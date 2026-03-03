use std::net::IpAddr;
use std::sync::Arc;

use crate::common::normalized_event::{EventKind, NormalizedEvent};
use crate::engine::correlation::RateTracker;
use crate::engine::process_graph::ProcessGraph;
use crate::engine::refined_detection::{EnhancedPowershellDetect, RefinedNetworkSpike};

pub struct Alert {
    pub name: String,
    pub severity: String,
}

impl Alert {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            severity: "High".to_string(),
        }
    }
}

pub struct EngineContext {
    pub graph: Arc<ProcessGraph>,
    pub network_rate: RateTracker,
}

impl EngineContext {
    pub fn new(graph: Arc<ProcessGraph>) -> Self {
        Self {
            graph,
            network_rate: RateTracker::new(),
        }
    }
}

pub trait Signature: Send + Sync {
    fn evaluate(&self, event: &NormalizedEvent, ctx: &EngineContext) -> Option<Alert>;
}

pub struct ContextSignatureEngine {
    rules: Vec<Box<dyn Signature>>,
    context: EngineContext,
}

impl ContextSignatureEngine {
    pub fn new(graph: Arc<ProcessGraph>) -> Self {
        let mut rules: Vec<Box<dyn Signature>> = Vec::new();
        rules.push(Box::new(EnhancedPowershellDetect));
        rules.push(Box::new(FastSpawnConnect));
        rules.push(Box::new(RefinedNetworkSpike::new()));

        Self {
            rules,
            context: EngineContext::new(graph),
        }
    }

    pub fn evaluate(&self, event: &NormalizedEvent) {
        // Signature evaluation
        for rule in &self.rules {
            if let Some(alert) = rule.evaluate(event, &self.context) {
                println!("🚨 [ALERT] {} (Severity: {})", alert.name, alert.severity);
            }
        }
    }
}

// Rule 1: PowerShell → External IP
pub struct PowershellExternalConnect;

impl Signature for PowershellExternalConnect {
    fn evaluate(&self, event: &NormalizedEvent, ctx: &EngineContext) -> Option<Alert> {
        if event.kind != EventKind::NetworkConnect {
            return None;
        }

        let net = event.network.as_ref()?;
        let proc = ctx.graph.processes.get(&net.pid)?;

        if !proc.image.to_lowercase().contains("powershell") {
            return None;
        }

        if is_external_ip(net.dst_ip) {
            return Some(Alert::new("PowerShell external connection"));
        }

        None
    }
}

// Rule 2: Spawn → Connect within 3 seconds
pub struct FastSpawnConnect;

impl Signature for FastSpawnConnect {
    fn evaluate(&self, event: &NormalizedEvent, ctx: &EngineContext) -> Option<Alert> {
        if event.kind != EventKind::NetworkConnect {
            return None;
        }

        let net = event.network.as_ref()?;
        let proc = ctx.graph.processes.get(&net.pid)?;

        if proc.start_time.elapsed().as_secs() < 3 {
            return Some(Alert::new("Process connected immediately after spawn"));
        }

        None
    }
}

fn is_external_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Private ranges: 10.x, 172.16-31.x, 192.168.x, 127.x
            !(octets[0] == 10
                || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                || (octets[0] == 192 && octets[1] == 168)
                || octets[0] == 127)
        }
        IpAddr::V6(_) => true, // Simplified: treat all IPv6 as external
    }
}
