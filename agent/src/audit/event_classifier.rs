use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum SecurityLevel {
    Info,
    Warning,
    Critical,
    Incident,
}

pub fn classify_score(ai_score: f64, rules_triggered: usize) -> SecurityLevel {
    if ai_score > 0.90 || rules_triggered >= 3 {
        SecurityLevel::Incident
    } else if ai_score > 0.70 || rules_triggered >= 1 {
        let is_block = true; // Temporary logic mapping to decision logic
        if is_block {
            SecurityLevel::Critical
        } else {
            SecurityLevel::Warning
        }
    } else if ai_score > 0.40 {
        SecurityLevel::Warning
    } else {
        SecurityLevel::Info
    }
}
