use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::common::normalized_event::{EventKind, NormalizedEvent};
use crate::engine::event_window::EventWindow;
use crate::engine::process_graph::ProcessGraph;

pub struct Alert {
    pub name: String,
    pub severity: String,
    pub score: u32,
}

impl Alert {
    pub fn critical(name: &str, score: u32) -> Self {
        Self {
            name: name.to_string(),
            severity: "Critical".to_string(),
            score,
        }
    }

    pub fn high(name: &str, score: u32) -> Self {
        Self {
            name: name.to_string(),
            severity: "High".to_string(),
            score,
        }
    }

    pub fn medium(name: &str, score: u32) -> Self {
        Self {
            name: name.to_string(),
            severity: "Medium".to_string(),
            score,
        }
    }
}

pub struct EngineContext {
    pub graph: Arc<ProcessGraph>,
    pub window: Mutex<EventWindow>,
}

impl EngineContext {
    pub fn new(graph: Arc<ProcessGraph>) -> Self {
        Self {
            graph,
            window: Mutex::new(EventWindow::new(10, 10000)),
        }
    }
}

pub trait ContextualSignature: Send + Sync {
    fn evaluate(&self, event: &NormalizedEvent, ctx: &EngineContext) -> Option<Alert>;
}

pub struct ContextualEngine {
    rules: Vec<Box<dyn ContextualSignature>>,
    context: EngineContext,
}

impl ContextualEngine {
    pub fn new(graph: Arc<ProcessGraph>) -> Self {
        let mut rules: Vec<Box<dyn ContextualSignature>> = Vec::new();
        rules.push(Box::new(DropperBehavior));
        rules.push(Box::new(OfficeChainC2));
        rules.push(Box::new(BeaconDetection));
        rules.push(Box::new(FastSpawnConnect));

        Self {
            rules,
            context: EngineContext::new(graph),
        }
    }

    pub fn evaluate(&self, event: &NormalizedEvent) {
        // Push to window first
        self.context.window.lock().unwrap().push(event.clone());

        let mut total_score = 0u32;
        let mut alerts = Vec::new();

        for rule in &self.rules {
            if let Some(alert) = rule.evaluate(event, &self.context) {
                total_score += alert.score;
                alerts.push(alert);
            }
        }

        // Emit alerts with aggregated score
        for alert in alerts {
            let severity = if total_score > 80 {
                "CRITICAL"
            } else if total_score > 50 {
                "HIGH"
            } else {
                alert.severity.as_str()
            };

            println!(
                "🚨 [ALERT] {} (Severity: {}, Score: {}/{})",
                alert.name, severity, alert.score, total_score
            );
        }
    }
}

// Rule 1: Dropper Pattern (Spawn → Connect → Exit)
pub struct DropperBehavior;

impl ContextualSignature for DropperBehavior {
    fn evaluate(&self, event: &NormalizedEvent, ctx: &EngineContext) -> Option<Alert> {
        if event.kind != EventKind::ProcessStop {
            return None;
        }

        let pid = event.process.as_ref()?.pid;
        let window = ctx.window.lock().unwrap();
        let events = window.find_by_pid(pid);

        let mut seen_start = false;
        let mut seen_connect = false;

        for e in events {
            match e.kind {
                EventKind::ProcessStart => seen_start = true,
                EventKind::NetworkConnect => seen_connect = true,
                _ => {}
            }
        }

        if seen_start && seen_connect {
            return Some(Alert::critical("Dropper-style execution pattern", 50));
        }

        None
    }
}

// Rule 2: Office → PowerShell → External C2
pub struct OfficeChainC2;

impl ContextualSignature for OfficeChainC2 {
    fn evaluate(&self, event: &NormalizedEvent, ctx: &EngineContext) -> Option<Alert> {
        if event.kind != EventKind::NetworkConnect {
            return None;
        }

        let net = event.network.as_ref()?;
        let proc = ctx.graph.processes.get(&net.pid)?;

        if !proc.image.to_lowercase().contains("powershell") {
            return None;
        }

        let parent = ctx.graph.processes.get(&proc.ppid)?;
        let parent_img = parent.image.to_lowercase();

        if (parent_img.contains("winword") || parent_img.contains("excel"))
            && is_external_ip(net.dst_ip)
        {
            return Some(Alert::high("Office macro → PowerShell → External C2", 40));
        }

        None
    }
}

// Rule 3: Beacon Detection (Interval-based)
pub struct BeaconDetection;

impl ContextualSignature for BeaconDetection {
    fn evaluate(&self, event: &NormalizedEvent, ctx: &EngineContext) -> Option<Alert> {
        if event.kind != EventKind::NetworkConnect {
            return None;
        }

        let net = event.network.as_ref()?;
        let window = ctx.window.lock().unwrap();
        let connects = window.find_network_by_pid(net.pid);

        if connects.len() < 5 {
            return None;
        }

        // Check if same destination IP
        let same_ip_count = connects
            .iter()
            .filter(|e| e.network.as_ref().map_or(false, |n| n.dst_ip == net.dst_ip))
            .count();

        if same_ip_count >= 5 {
            return Some(Alert::high(
                &format!("Beacon behavior: {} connections to same IP", same_ip_count),
                30,
            ));
        }

        None
    }
}

// Rule 4: Fast Spawn Connect
pub struct FastSpawnConnect;

impl ContextualSignature for FastSpawnConnect {
    fn evaluate(&self, event: &NormalizedEvent, ctx: &EngineContext) -> Option<Alert> {
        if event.kind != EventKind::NetworkConnect {
            return None;
        }

        let net = event.network.as_ref()?;
        let proc = ctx.graph.processes.get(&net.pid)?;

        if proc.start_time.elapsed().as_secs() < 3 {
            return Some(Alert::medium(
                &format!("Process {} connected <3s after spawn", proc.image),
                20,
            ));
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
