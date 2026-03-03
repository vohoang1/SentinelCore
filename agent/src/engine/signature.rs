use arc_swap::ArcSwap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use crate::common::normalized_event::NormalizedEvent;
use crate::engine::rule::{CompiledRule, RuleDefinition};

#[derive(Debug)]
pub struct Alert {
    pub rule_id: String,
    pub name: String,
    pub severity: crate::detection::model::Severity,
}

pub struct SignatureEngine {
    // Thread-safe pointer to our current ruleset
    rules: ArcSwap<Vec<Arc<CompiledRule>>>,
}

impl SignatureEngine {
    pub fn new(rules_dir: &Path) -> Self {
        let rules = Self::load_rules_from_dir(rules_dir);
        println!("Loaded {} rules into the Signature Engine.", rules.len());

        Self {
            rules: ArcSwap::from_pointee(rules),
        }
    }

    pub fn reload_rules(&self, rules_dir: &Path) {
        let new_rules = Self::load_rules_from_dir(rules_dir);
        let count = new_rules.len();
        self.rules.store(Arc::new(new_rules));
        println!("Hot-reloaded rules. Active rules: {}", count);
    }

    fn load_rules_from_dir(dir: &Path) -> Vec<Arc<CompiledRule>> {
        let mut compiled_rules = Vec::new();

        if !dir.exists() {
            println!("Rules directory {:?} not found, creating it.", dir);
            let _ = fs::create_dir_all(dir);
            return compiled_rules;
        }

        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .map_or(false, |ext| ext == "yaml" || ext == "yml")
                {
                    if let Ok(contents) = fs::read_to_string(&path) {
                        match serde_yaml::from_str::<RuleDefinition>(&contents) {
                            Ok(def) => match CompiledRule::compile(&def) {
                                Ok(rule) => compiled_rules.push(rule),
                                Err(e) => eprintln!("Failed to compile rule {}: {}", def.id, e),
                            },
                            Err(e) => eprintln!("Failed to parse YAML file {:?}: {}", path, e),
                        }
                    }
                }
            }
        }

        compiled_rules
    }

    pub fn analyze(&self, event: &NormalizedEvent) {
        // arc-swap allows zero-cost reads on the hot path
        let active_rules: arc_swap::Guard<Arc<Vec<Arc<CompiledRule>>>> = self.rules.load();

        for rule in active_rules.iter() {
            if rule.matches(event) {
                let alert = Alert {
                    rule_id: rule.id.clone(),
                    name: rule.name.clone(),
                    severity: rule.severity,
                };

                println!(
                    "🚨 [ALERT] [{}] {} (Severity: {:?})",
                    alert.rule_id, alert.name, alert.severity
                );
                // Production: Forward alert to console IPC / Storage
            }
        }
    }
}
