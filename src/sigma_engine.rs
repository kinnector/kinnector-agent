use std::collections::HashMap;
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaEvent {
    pub category: String,
    pub fields: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum ConditionNode {
    And(Vec<ConditionNode>),
    Or(Vec<ConditionNode>),
    FieldMatch { field: String, value: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub category: String,
    pub condition: ConditionNode,
}

pub struct SigmaRulesEngine {
    rules: Vec<SigmaRule>,
}

impl SigmaRulesEngine {
    pub fn new() -> Self {
        let mut rules = Vec::new();
        let rules_dir = Path::new("/etc/kinnector/rules.d");

        if rules_dir.exists() {
            if let Ok(entries) = fs::read_dir(rules_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("json") {
                        if let Ok(content) = fs::read_to_string(&path) {
                            if let Ok(rule) = serde_json::from_str::<SigmaRule>(&content) {
                                info!("[Sigma] Loaded compiled rule: {} ({})", rule.title, rule.id);
                                rules.push(rule);
                            }
                        }
                    }
                }
            }
        }

        Self { rules }
    }

    /// Evaluates the event against all active Sigma rules
    pub fn evaluate(&self, event: &SigmaEvent) -> Option<&SigmaRule> {
        for rule in &self.rules {
            if rule.category == event.category {
                if Self::evaluate_node(&rule.condition, event) {
                    return Some(rule);
                }
            }
        }
        None
    }

    pub fn evaluate_node(node: &ConditionNode, event: &SigmaEvent) -> bool {
        match node {
            ConditionNode::And(sub_nodes) => {
                sub_nodes.iter().all(|n| Self::evaluate_node(n, event))
            }
            ConditionNode::Or(sub_nodes) => {
                sub_nodes.iter().any(|n| Self::evaluate_node(n, event))
            }
            ConditionNode::FieldMatch { field, value } => {
                if let Some(val) = event.fields.get(field) {
                    val.eq_ignore_ascii_case(value)
                } else {
                    false
                }
            }
        }
    }
}
