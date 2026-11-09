use super::{Edge, Join, Node, Pipeline, Runner};
use crate::error::{Error, Result};
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
    pub timeout: Option<u64>,
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
            return Err(Error::Internal(format!(
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
        .map_err(|e| Error::Internal(format!("Serialize pipeline config failed: {e}")))?;
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
        node.timeout = self.timeout;
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
        let mut variants = vec![json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "minLength": 1 },
                "type": { "const": "input" },
                "fields": { "type": "array", "items": { "type": "string" } },
                "join": { "enum": ["all", "any"] },
                "limit": { "type": "integer", "minimum": 1 },
                "once": { "type": "boolean" },
                "timeout": { "type": "integer", "minimum": 1 },
                "retries": { "type": "integer", "minimum": 0 },
                "idempotency": { "type": "string", "minLength": 1 },
                "edges": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "route": { "type": ["string", "null"] },
                            "to": { "type": "string", "minLength": 1 }
                        },
                        "required": ["to"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["id", "type"],
            "additionalProperties": false
        })];
        for (op, cards) in &self.values {
            let values = cards
                .iter()
                .map(|(code, card)| {
                    let args = self.card_schema_value(card);
                    let mut required = vec![
                        Value::String("id".into()),
                        Value::String("type".into()),
                        Value::String("code".into()),
                    ];
                    if !card.args.is_empty() {
                        required.push(Value::String("args".into()));
                    }
                    variants.push(json!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string", "minLength": 1 },
                            "type": { "const": op_name(*op) },
                            "code": { "const": code },
                            "args": args,
                            "edges": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "route": { "type": ["string", "null"] },
                                        "to": { "type": "string", "minLength": 1 }
                                    },
                                    "required": ["to"],
                                    "additionalProperties": false
                                }
                            },
                            "fields": { "type": "array", "items": { "type": "string" } },
                            "join": { "enum": ["all", "any"] },
                            "limit": { "type": "integer", "minimum": 1 },
                            "once": { "type": "boolean" },
                            "timeout": { "type": "integer", "minimum": 1 },
                            "retries": { "type": "integer", "minimum": 0 },
                            "idempotency": { "type": "string", "minLength": 1 }
                        },
                        "required": required,
                        "additionalProperties": false
                    }));
                    json!({
                        "code": code,
                        "version": card.version,
                        "args": card.args,
                        "schema": self.card_schema_value(card)
                    })
                })
                .collect::<Vec<_>>();
            operations.insert(op_name(*op).into(), Value::Array(values));
        }
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "version": 1,
            "type": "object",
            "properties": {
                "version": { "type": "integer", "const": 1 },
                "start": { "type": "string", "minLength": 1 },
                "max_steps": { "type": "integer", "minimum": 1 },
                "nodes": { "type": "array", "items": { "oneOf": variants } }
            },
            "required": ["start", "nodes"],
            "additionalProperties": false,
            "operations": operations
        })
    }

    pub fn card_schema(&self, op: Op, code: &str) -> Option<Value> {
        self.card(op, code).map(|card| self.card_schema_value(card))
    }

    fn card_schema_value(&self, card: &Card) -> Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();
        for (name, arg) in &card.args {
            let mut schema = json_type(&arg.kind);
            if arg.secret {
                schema = json!({
                    "type": "object",
                    "properties": { "$secret": { "type": "string", "minLength": 1 } },
                    "required": ["$secret"],
                    "additionalProperties": false
                });
            }
            properties.insert(name.clone(), schema);
            if arg.required {
                required.push(Value::String(name.clone()));
            }
        }
        json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false
        })
    }

    pub fn validate(&self, config: &PipelineConfig) -> Result<()> {
        if config.start.trim().is_empty() {
            return Err(Error::Internal("Pipeline start node is empty".into()));
        }
        if config.max_steps == Some(0) {
            return Err(Error::Internal(
                "Pipeline max steps must be positive".into(),
            ));
        }
        self.validate_cards()?;
        let mut ids = BTreeMap::new();
        for node in &config.nodes {
            if node.id.trim().is_empty() {
                return Err(Error::Internal("Pipeline node id is empty".into()));
            }
            if ids.insert(node.id.clone(), ()).is_some() {
                return Err(Error::Internal(format!(
                    "Pipeline node id is duplicated: {}",
                    node.id
                )));
            }
            if node.limit == Some(0) {
                return Err(Error::Internal(format!(
                    "Pipeline node limit must be positive: {}",
                    node.id
                )));
            }
            if node.timeout == Some(0) {
                return Err(Error::Internal(format!(
                    "Pipeline timeout must be positive: {}",
                    node.id
                )));
            }
            if (node.once || node.idempotency.is_some()) && node.op != Op::Effect {
                return Err(Error::Internal(format!(
                    "Pipeline once/idempotency requires an effect node: {}",
                    node.id
                )));
            }
            validate_edges(node)?;
            if node.op == Op::Input {
                continue;
            }
            let code = node.code.as_deref().unwrap_or("");
            if code.trim().is_empty() {
                return Err(Error::Internal(format!(
                    "Pipeline capability code is empty: {}",
                    node.id
                )));
            }
            if !self.supports(node.op, code) {
                return Err(Error::Internal(format!(
                    "Pipeline capability is not registered: {:?}/{}",
                    node.op, code
                )));
            }
            let card = self.card(node.op, code).expect("supports checked above");
            validate_args(node, card, code)?;
        }
        Ok(())
    }

    fn validate_cards(&self) -> Result<()> {
        for (op, cards) in &self.values {
            for (code, card) in cards {
                if code.trim().is_empty() || card.version == 0 {
                    return Err(Error::Internal(format!(
                        "Invalid pipeline card: {:?}/{}",
                        op, code
                    )));
                }
                for (name, arg) in &card.args {
                    if name.trim().is_empty() || arg.kind.trim().is_empty() {
                        return Err(Error::Internal(format!(
                            "Invalid pipeline card argument: {:?}/{}",
                            op, code
                        )));
                    }
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
                return Err(Error::Unsupported(node.id.clone()));
            }
            if let Some(code) = node_code(&node.kind) {
                let op = node_op(&node.kind);
                if let Some(card) = self.card(op, code)
                    && runner.version(node) != card.version
                {
                    return Err(Error::Internal(format!(
                        "Pipeline capability version mismatch: {:?}/{}",
                        op, code
                    )));
                }
            }
        }
        Ok(())
    }
}

fn op_name(op: Op) -> &'static str {
    match op {
        Op::Input => "input",
        Op::Check => "check",
        Op::Issue => "issue",
        Op::Verify => "verify",
        Op::Effect => "effect",
    }
}

fn json_type(kind: &str) -> Value {
    match kind {
        "string" | "number" | "integer" | "boolean" | "object" | "array" | "null" => {
            json!({ "type": kind })
        }
        "any" => json!({}),
        _ => json!({ "type": "string" }),
    }
}

fn validate_edges(node: &NodeConfig) -> Result<()> {
    let mut routes = BTreeMap::new();
    for edge in &node.edges {
        if edge.to.trim().is_empty() {
            return Err(Error::Internal(format!(
                "Pipeline edge target is empty: {}",
                node.id
            )));
        }
        if edge
            .route
            .as_deref()
            .is_some_and(|route| route.trim().is_empty())
        {
            return Err(Error::Internal(format!(
                "Pipeline edge route is empty: {}",
                node.id
            )));
        }
        if routes.insert(edge.route.clone(), ()).is_some() {
            return Err(Error::Internal(format!(
                "Pipeline edge route is duplicated: {}",
                node.id
            )));
        }
    }
    Ok(())
}

fn validate_args(node: &NodeConfig, card: &Card, code: &str) -> Result<()> {
    let args = match &node.args {
        Value::Null => None,
        Value::Object(values) => Some(values),
        _ => {
            return Err(Error::Internal(format!(
                "Pipeline capability arguments must be an object: {}",
                node.id
            )));
        }
    };
    for (field, value) in args.into_iter().flat_map(|values| values.iter()) {
        let Some(arg) = card.args.get(field) else {
            return Err(Error::Internal(format!(
                "Pipeline capability argument is unknown: {:?}/{} -> {}",
                node.op, code, field
            )));
        };
        if arg.secret {
            let valid = value
                .get("$secret")
                .and_then(Value::as_str)
                .is_some_and(|key| !key.is_empty())
                && value.as_object().is_some_and(|object| object.len() == 1);
            if !valid {
                return Err(Error::Internal(format!(
                    "Pipeline secret argument is invalid: {:?}/{} -> {}",
                    node.op, code, field
                )));
            }
        } else if !matches_kind(value, &arg.kind) {
            return Err(Error::Internal(format!(
                "Pipeline capability argument has wrong type: {:?}/{} -> {}",
                node.op, code, field
            )));
        }
    }
    for (field, arg) in &card.args {
        if arg.required && args.is_none_or(|values| values.get(field).is_none()) {
            return Err(Error::Internal(format!(
                "Pipeline capability argument is missing: {:?}/{} -> {}",
                node.op, code, field
            )));
        }
    }
    Ok(())
}

fn matches_kind(value: &Value, kind: &str) -> bool {
    match kind {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        "any" => true,
        _ => false,
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
        let cards = Cards::new().arg(Op::Verify, "password", "source", "string", true, false);
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
                timeout: None,
                retries: 0,
                idempotency: None,
            }],
        };
        assert!(config.compile_with(&Cards::new()).is_err());
    }
}
