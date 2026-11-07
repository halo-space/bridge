use super::{Edge, Join, Node, Pipeline};
use crate::error::{IdpError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Input,
    Check,
    Issue,
    Verify,
    Effect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    #[serde(default)]
    pub route: Option<String>,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub op: Op,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub args: Value,
    #[serde(default)]
    pub edges: Vec<EdgeConfig>,
    #[serde(default)]
    pub join: Join,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineConfig {
    #[serde(default = "default_version")]
    pub version: u16,
    pub start: String,
    #[serde(default)]
    pub max_steps: Option<u32>,
    pub nodes: Vec<NodeConfig>,
}

fn default_version() -> u16 {
    1
}

impl PipelineConfig {
    pub fn compile_with(&self, cards: &Cards) -> Result<Pipeline> {
        cards.validate(self)?;
        self.clone().compile()
    }

    pub fn compile(self) -> Result<Pipeline> {
        if self.version != 1 {
            return Err(IdpError::Internal(format!(
                "Unsupported pipeline config version: {}",
                self.version
            )));
        }
        let nodes = self
            .nodes
            .into_iter()
            .map(NodeConfig::compile)
            .collect::<Result<Vec<_>>>()?;
        let mut pipeline = Pipeline::new(self.start, nodes);
        if let Some(max_steps) = self.max_steps {
            pipeline = pipeline.max_steps(max_steps);
        }
        pipeline.validate()?;
        Ok(pipeline)
    }
}

impl NodeConfig {
    fn compile(self) -> Result<Node> {
        let code = self.code.unwrap_or_default();
        let mut node = match self.op {
            Op::Input => Node::input(self.id, self.fields),
            Op::Check => Node::check(self.id, code),
            Op::Issue => Node::issue(self.id, code),
            Op::Verify => Node::verify(self.id, code),
            Op::Effect => Node::effect(self.id, code),
        };
        node.args = self.args;
        node.join = self.join;
        node.limit = self.limit;
        node.edges = self
            .edges
            .into_iter()
            .map(|edge| Edge {
                route: edge.route,
                to: edge.to,
            })
            .collect();
        Ok(node)
    }
}

/// 页面配置发布前使用的能力码表。未注册的 code 不允许发布。
#[derive(Debug, Clone, Default)]
pub struct Cards {
    values: BTreeMap<Op, BTreeSet<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_page_config_and_checks_registered_cards() {
        let config: PipelineConfig = serde_json::from_value(serde_json::json!({
            "version": 1,
            "start": "input",
            "nodes": [
                {
                    "id": "input",
                    "type": "input",
                    "fields": ["username", "password"],
                    "edges": [{"to": "password"}]
                },
                {
                    "id": "password",
                    "type": "verify",
                    "code": "password",
                    "args": {"source": "company"}
                }
            ]
        }))
        .unwrap();
        let cards = Cards::new().add(Op::Verify, "password");
        let pipeline = config.compile_with(&cards).unwrap();
        let node = pipeline.nodes().find(|node| node.id == "password").unwrap();
        assert_eq!(node.args["source"], "company");
    }

    #[test]
    fn rejects_unregistered_code() {
        let config = PipelineConfig {
            version: 1,
            start: "verify".into(),
            max_steps: None,
            nodes: vec![NodeConfig {
                id: "verify".into(),
                op: Op::Verify,
                code: Some("custom.card".into()),
                fields: Vec::new(),
                args: Value::Null,
                edges: Vec::new(),
                join: Join::All,
                limit: None,
            }],
        };
        assert!(config.compile_with(&Cards::new()).is_err());
    }
}

impl Cards {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(mut self, op: Op, code: impl Into<String>) -> Self {
        self.values.entry(op).or_default().insert(code.into());
        self
    }

    pub fn supports(&self, op: Op, code: &str) -> bool {
        self.values
            .get(&op)
            .is_some_and(|cards| cards.contains(code))
    }

    pub fn validate(&self, config: &PipelineConfig) -> Result<()> {
        for node in &config.nodes {
            if node.op == Op::Input {
                continue;
            }
            let code = node.code.as_deref().unwrap_or_default();
            if !self.supports(node.op, code) {
                return Err(IdpError::Internal(format!(
                    "Pipeline capability is not registered: {:?}/{}",
                    node.op, code
                )));
            }
        }
        Ok(())
    }
}
