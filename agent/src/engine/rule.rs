use crate::common::normalized_event::{EventKind, NormalizedEvent};
use crate::detection::model::Severity;
use regex::Regex;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize, Clone)]
pub struct RuleDefinition {
    pub id: String,
    pub name: String,
    pub version: String,
    pub severity: String,
    pub condition: RuleCondition,
    pub action: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RuleCondition {
    pub event_type: String,
    pub image_path: Option<String>,
    pub args_contains: Option<Vec<String>>,
    pub network_dst_port: Option<u16>,
}

pub struct CompiledRule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub event_kind: EventKind,
    pub image_path_regex: Option<Regex>,
    pub args_contains: Vec<String>,
    pub network_dst_port: Option<u16>,
}

impl CompiledRule {
    pub fn compile(def: &RuleDefinition) -> Result<Arc<Self>, String> {
        let event_kind = match def.condition.event_type.as_str() {
            "ProcessStart" => EventKind::ProcessStart,
            "ProcessStop" => EventKind::ProcessStop,
            "NetworkConnect" => EventKind::NetworkConnect,
            "RegistrySet" => EventKind::RegistrySet,
            "KernelTelemetry" => EventKind::KernelTelemetry,
            other => return Err(format!("Unknown event type: {}", other)),
        };

        let severity = match def.severity.as_str() {
            "Low" => Severity::Low,
            "Medium" => Severity::Medium,
            "High" => Severity::High,
            "Critical" => Severity::Critical,
            other => return Err(format!("Unknown severity: {}", other)),
        };

        let image_path_regex = if let Some(ref pattern) = def.condition.image_path {
            // Case-insensitive regex
            let re = Regex::new(&format!("(?i){}", pattern))
                .map_err(|e| format!("Invalid regex pattern '{}': {}", pattern, e))?;
            Some(re)
        } else {
            None
        };

        Ok(Arc::new(Self {
            id: def.id.clone(),
            name: def.name.clone(),
            severity,
            event_kind,
            image_path_regex,
            args_contains: def.condition.args_contains.clone().unwrap_or_default(),
            network_dst_port: def.condition.network_dst_port,
        }))
    }

    pub fn matches(&self, event: &NormalizedEvent) -> bool {
        if self.event_kind != event.kind {
            return false;
        }

        match event.kind {
            EventKind::ProcessStart => {
                if let Some(ref proc) = event.process {
                    // Check image path
                    if let Some(ref regex) = self.image_path_regex {
                        if !regex.is_match(&proc.image) {
                            return false;
                        }
                    }

                    // Check args
                    if !self.args_contains.is_empty() {
                        if let Some(ref cmd) = proc.command_line {
                            // Needs to contain all required arguments to match
                            let cmd_lower = cmd.to_lowercase();
                            for arg in &self.args_contains {
                                if !cmd_lower.contains(&arg.to_lowercase()) {
                                    return false;
                                }
                            }
                        } else {
                            // Rule requires args, but event has none
                            return false;
                        }
                    }

                    return true;
                }
            }
            EventKind::NetworkConnect => {
                if let Some(ref net) = event.network {
                    if let Some(port) = self.network_dst_port {
                        if net.dst_port != port {
                            return false;
                        }
                    }
                    return true;
                }
            }
            _ => return false,
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::normalized_event::{EventKind, NormalizedEvent, Priority, ProcessInfo};

    #[test]
    fn test_powershell_yaml_parsing_and_matching() {
        let yaml = r#"
id: "SC-001"
name: "Suspicious PowerShell Execution"
version: "1.0.1"
severity: "High"
condition:
  event_type: "ProcessStart"
  image_path: "powershell.exe"
  args_contains: ["-enc", "-nop", "bypass"]
action: "Alert"
"#;

        let def: RuleDefinition = serde_yaml::from_str(yaml).expect("Failed to parse YAML");
        let rule = CompiledRule::compile(&def).expect("Failed to compile rule");

        let benign_event = NormalizedEvent {
            kind: EventKind::ProcessStart,
            timestamp: 1000,
            priority: Priority::Medium,
            process: Some(ProcessInfo {
                pid: 1234,
                ppid: 100,
                image: Arc::from("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
                command_line: Some(Arc::from("powershell.exe -NoProfile")),
            }),
            network: None,
            registry: None,
            kernel: None,
        };

        assert!(
            !rule.matches(&benign_event),
            "Rule should not match benign event missing all args"
        );

        let malicious_event = NormalizedEvent {
            kind: EventKind::ProcessStart,
            timestamp: 1001,
            priority: Priority::High,
            process: Some(ProcessInfo {
                pid: 5678,
                ppid: 100,
                image: Arc::from("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
                command_line: Some(Arc::from(
                    "powershell.exe -nop -exec bypass -enc ZWNobyAnaGVsbG8n",
                )),
            }),
            network: None,
            registry: None,
            kernel: None,
        };

        assert!(
            rule.matches(&malicious_event),
            "Rule should match malicious event"
        );
    }
}
