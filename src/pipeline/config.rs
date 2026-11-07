use super::{Edge, Join, Node, Pipeline, Runner};
use crate::error::{IdpError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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
    #[serde(default)]
    pub once: bool,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub retries: u32,
    #[serde(default)]
    pub idempotency: Option<String>,
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

    pub(crate) fn compile(self) -> Result<Pipeline> {
        if self.version != 1 {
            return Err(IdpError::Internal(format!(
                "Unsupported pipeline config version: {}",
                self.version
            )));
        }
        let version = self.version;
        let hash = config_hash(&self)?;
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
        Ok(pipeline.stamp(version, hash))
    }
}

fn config_hash(config: &PipelineConfig) -> Result<String> {
    let data = serde_json::to_vec(config)
        .map_err(|e| IdpError::Internal(format!("Serialize pipeline config failed: {e}")))?;
    Ok(Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
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
        node.once = self.once;
        node.timeout_ms = self.timeout_ms;
        node.retries = self.retries;
        node.idempotency = self.idempotency;
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
    values: BTreeMap<Op, BTreeMap<String, Card>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Card {
    pub version: u16,
    pub args: BTreeMap<String, Arg>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Arg {
    pub kind: String,
    pub required: bool,
    pub secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Secret {
    pub key: String,
}

impl Secret {
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    pub fn value(&self) -> Value {
        json!({ "$secret": self.key })
    }

    pub async fn resolve<R: Resolve>(&self, source: &R) -> Result<String> {
        source.secret(&self.key).await
    }
}

pub fn secret(key: impl Into<String>) -> Value {
    Secret::new(key).value()
}

#[allow(async_fn_in_trait)]
pub trait Resolve: Send + Sync {
    async fn secret(&self, key: &str) -> Result<String>;
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
                once: false,
                timeout_ms: None,
                retries: 0,
                idempotency: None,
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
        self.values
            .entry(op)
            .or_default()
            .entry(code.into())
            .or_insert_with(|| Card {
                version: 1,
                args: BTreeMap::new(),
            });
        self
    }

    pub fn args(mut self, op: Op, code: impl Into<String>, fields: Vec<String>) -> Self {
        self.values
            .entry(op)
            .or_default()
            .entry(code.into())
            .or_insert_with(|| Card {
                version: 1,
                args: BTreeMap::new(),
            })
            .args
            .extend(fields.into_iter().map(|field| {
                (
                    field,
                    Arg {
                        kind: "string".into(),
                        required: true,
                        secret: false,
                    },
                )
            }));
        self
    }

    pub fn version(mut self, op: Op, code: impl Into<String>, version: u16) -> Self {
        self.values
            .entry(op)
            .or_default()
            .entry(code.into())
            .or_insert_with(|| Card {
                version,
                args: BTreeMap::new(),
            })
            .version = version;
        self
    }

    pub fn arg(
        mut self,
        op: Op,
        code: impl Into<String>,
        name: impl Into<String>,
        kind: impl Into<String>,
        required: bool,
        secret: bool,
    ) -> Self {
        self.values
            .entry(op)
            .or_default()
            .entry(code.into())
            .or_insert_with(|| Card {
                version: 1,
                args: BTreeMap::new(),
            })
            .args
            .insert(
                name.into(),
                Arg {
                    kind: kind.into(),
                    required,
                    secret,
                },
            );
        self
    }

    pub fn supports(&self, op: Op, code: &str) -> bool {
        self.values
            .get(&op)
            .is_some_and(|cards| cards.contains_key(code))
    }

    pub fn card(&self, op: Op, code: &str) -> Option<&Card> {
        self.values.get(&op).and_then(|cards| cards.get(code))
    }

    pub fn schema(&self) -> Value {
        let mut operations = serde_json::Map::new();
        for (op, cards) in &self.values {
            let values = cards
                .iter()
                .map(|(code, card)| json!({ "code": code, "version": card.version, "args": card.args }))
                .collect::<Vec<_>>();
            operations.insert(format!("{op:?}").to_lowercase(), Value::Array(values));
        }
        json!({ "version": 1, "operations": operations })
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
            let card = self.card(node.op, code).expect("supports checked above");
            for (field, arg) in &card.args {
                if arg.required && node.args.get(field).is_none() {
                    return Err(IdpError::Internal(format!(
                        "Pipeline capability argument is missing: {:?}/{} -> {}",
                        node.op, code, field
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn validate_runner<R: Runner>(&self, pipeline: &Pipeline, runner: &R) -> Result<()> {
        for node in pipeline.nodes() {
            if matches!(node.kind, super::Kind::Input) {
                continue;
            }
            if !runner.supports(node) {
                return Err(IdpError::Unsupported(node.id.clone()));
            }
            if let Some(code) = node_code(&node.kind) {
                let op = node_op(&node.kind);
                if let Some(card) = self.card(op, code) {
                    if runner.version(node) != card.version {
                        return Err(IdpError::Internal(format!(
                            "Pipeline capability version mismatch: {:?}/{}",
                            op, code
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

fn node_code(kind: &super::Kind) -> Option<&str> {
    match kind {
        super::Kind::Input => None,
        super::Kind::Check(code)
        | super::Kind::Issue(code)
        | super::Kind::Verify(code)
        | super::Kind::Effect(code) => Some(code),
    }
}

fn node_op(kind: &super::Kind) -> Op {
    match kind {
        super::Kind::Input => Op::Input,
        super::Kind::Check(_) => Op::Check,
        super::Kind::Issue(_) => Op::Issue,
        super::Kind::Verify(_) => Op::Verify,
        super::Kind::Effect(_) => Op::Effect,
    }
}
