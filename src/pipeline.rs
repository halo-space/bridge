use crate::error::{IdpError, Result};
use crate::types::Identity;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub mod services;
pub use services::Services;
pub mod config;
pub use config::{Cards, EdgeConfig, NodeConfig, Op, PipelineConfig, SecretRef};

const DEFAULT_MAX_STEPS: u32 = 128;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Kind {
    Input,
    Check(String),
    Issue(String),
    Verify(String),
    Effect(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Edge {
    pub route: Option<String>,
    pub to: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum Join {
    #[default]
    All,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Node {
    pub id: String,
    pub kind: Kind,
    pub fields: Vec<String>,
    #[serde(default)]
    pub args: Value,
    #[serde(default)]
    pub once: bool,
    pub edges: Vec<Edge>,
    pub join: Join,
    /// Maximum number of times this node may execute. Required for cycles.
    pub limit: Option<u32>,
}

impl Node {
    pub fn input(id: impl Into<String>, fields: Vec<String>) -> Self {
        Self {
            id: id.into(),
            kind: Kind::Input,
            fields,
            args: Value::Null,
            once: false,
            edges: Vec::new(),
            join: Join::All,
            limit: None,
        }
    }

    pub fn check(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self::plain(id, Kind::Check(kind.into()))
    }

    pub fn issue(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self::plain(id, Kind::Issue(kind.into()))
    }

    pub fn verify(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self::plain(id, Kind::Verify(kind.into()))
    }

    pub fn effect(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self::plain(id, Kind::Effect(kind.into()))
    }

    pub fn edge(mut self, route: Option<impl Into<String>>, to: impl Into<String>) -> Self {
        self.edges.push(Edge {
            route: route.map(Into::into),
            to: to.into(),
        });
        self
    }

    pub fn args(mut self, args: Value) -> Self {
        self.args = args;
        self
    }

    pub fn once(mut self, once: bool) -> Self {
        self.once = once;
        self
    }

    pub fn join(mut self, join: Join) -> Self {
        self.join = join;
        self
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    fn plain(id: impl Into<String>, kind: Kind) -> Self {
        Self {
            id: id.into(),
            kind,
            fields: Vec::new(),
            args: Value::Null,
            once: false,
            edges: Vec::new(),
            join: Join::All,
            limit: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    pub tenant_id: i64,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub connection: Option<String>,
    pub identity: Option<Identity>,
    #[serde(default)]
    pub request: Value,
    #[serde(default)]
    pub meta: Map<String, Value>,
    pub data: Map<String, Value>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub node: String,
    pub at: i64,
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// 用户提交当前输入节点或校验节点需要的原始数据。
    Input { node: String, data: Value, at: i64 },
    Pass {
        node: String,
        routes: Vec<String>,
        data: Value,
        identity: Option<Identity>,
        at: i64,
    },
    Fail {
        node: String,
        reason: String,
        retry: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Output {
    Pass {
        routes: Vec<String>,
        data: Value,
        identity: Option<Identity>,
        at: i64,
    },
    Fail {
        reason: String,
        retry: bool,
    },
}

/// 调用方提供的节点执行器。执行器内部调用现有 issuer、sender、verifier 和 factor。
#[allow(async_fn_in_trait)]
pub trait Runner: Send + Sync {
    fn supports(&self, _node: &Node) -> bool {
        true
    }

    async fn run(&self, node: &Node, context: &Context) -> Result<Output>;
}

/// 在内置能力之外组合自定义节点处理器。
///
/// `Primary` 优先处理节点；只有遇到不支持的节点类型时才回退到 `Backup`。
/// 这样调用方可以替换 bridge 的默认实现，也可以增加社交、企业、业务风控或自定义认证方式。
pub struct Fallback<Primary, Backup> {
    pub primary: Primary,
    pub backup: Backup,
}

impl<Primary, Backup> Fallback<Primary, Backup> {
    pub fn new(primary: Primary, backup: Backup) -> Self {
        Self { primary, backup }
    }
}

#[allow(async_fn_in_trait)]
impl<Primary, Backup> Runner for Fallback<Primary, Backup>
where
    Primary: Runner,
    Backup: Runner,
{
    fn supports(&self, node: &Node) -> bool {
        self.primary.supports(node) || self.backup.supports(node)
    }

    async fn run(&self, node: &Node, context: &Context) -> Result<Output> {
        match self.primary.run(node, context).await {
            Err(IdpError::Unsupported(_)) => self.backup.run(node, context).await,
            result => result,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub context: Context,
    pub current: Option<String>,
    pub ready: VecDeque<String>,
    #[serde(default)]
    pub cancelled: BTreeSet<String>,
    pub activated: BTreeSet<String>,
    pub completed: BTreeSet<String>,
    pub arrived: BTreeMap<String, BTreeSet<String>>,
    pub failed: BTreeMap<String, BTreeSet<String>>,
    pub visits: BTreeMap<String, u32>,
    pub steps: u32,
    #[serde(default)]
    pub denied: Option<(String, String)>,
    /// 已经收到输入、等待内置执行器校验的节点。
    #[serde(default)]
    pub submitted: BTreeSet<String>,
    /// 每个活动节点沿 DAG 继承的输入快照，避免不同分支混用数据。
    #[serde(default)]
    pub payloads: BTreeMap<String, Value>,
    #[serde(default)]
    pub pipeline_version: u16,
    #[serde(default)]
    pub pipeline_hash: Option<String>,
    #[serde(default)]
    pub effects: BTreeMap<String, Effect>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Effect {
    pub routes: Vec<String>,
    pub data: Value,
    pub identity: Option<Identity>,
    pub at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Progress {
    Need {
        node: String,
        kind: String,
        fields: Vec<String>,
    },
    Retry {
        node: String,
        reason: String,
    },
    Deny {
        node: String,
        reason: String,
    },
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pipeline {
    start: String,
    nodes: BTreeMap<String, Node>,
    max_steps: u32,
    #[serde(default)]
    config_version: u16,
    #[serde(default)]
    config_hash: Option<String>,
    #[serde(default)]
    invalid: Option<String>,
}

impl Pipeline {
    pub fn new(start: impl Into<String>, nodes: Vec<Node>) -> Self {
        let mut invalid = None;
        let mut mapped = BTreeMap::new();
        for node in nodes {
            if mapped.contains_key(&node.id) && invalid.is_none() {
                invalid = Some(format!("Pipeline node id is duplicated: {}", node.id));
            }
            mapped.insert(node.id.clone(), node);
        }
        Self {
            start: start.into(),
            nodes: mapped,
            max_steps: DEFAULT_MAX_STEPS,
            config_version: 0,
            config_hash: None,
            invalid,
        }
    }

    pub fn from_config(config: PipelineConfig, cards: &Cards) -> Result<Self> {
        config.compile_with(cards)
    }

    pub(crate) fn stamp(mut self, version: u16, hash: String) -> Self {
        self.config_version = version;
        self.config_hash = Some(hash);
        self
    }

    pub fn max_steps(mut self, max_steps: u32) -> Self {
        self.max_steps = max_steps.max(1);
        self
    }

    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(reason) = &self.invalid {
            return Err(IdpError::Internal(reason.clone()));
        }
        if !self.nodes.contains_key(&self.start) {
            return Err(IdpError::Internal(format!(
                "Pipeline start node not found: {}",
                self.start
            )));
        }
        if self.max_steps == 0 {
            return Err(IdpError::Internal("Pipeline max steps is zero".into()));
        }
        for node in self.nodes.values() {
            if node.id.trim().is_empty() {
                return Err(IdpError::Internal("Pipeline node id is empty".into()));
            }
            for edge in &node.edges {
                if !self.nodes.contains_key(&edge.to) {
                    return Err(IdpError::Internal(format!(
                        "Pipeline edge target not found: {}",
                        edge.to
                    )));
                }
            }
        }
        self.validate_cycles()
    }

    pub fn start(&self, context: Context) -> Result<(Run, Progress)> {
        self.validate()?;
        let mut run = Run {
            context,
            current: None,
            ready: VecDeque::new(),
            cancelled: BTreeSet::new(),
            activated: BTreeSet::new(),
            completed: BTreeSet::new(),
            arrived: BTreeMap::new(),
            failed: BTreeMap::new(),
            visits: BTreeMap::new(),
            steps: 0,
            denied: None,
            submitted: BTreeSet::new(),
            payloads: BTreeMap::new(),
            pipeline_version: self.config_version,
            pipeline_hash: self.config_hash.clone(),
            effects: BTreeMap::new(),
        };
        self.schedule(&mut run, &self.start)?;
        let progress = self.advance(&mut run)?;
        Ok((run, progress))
    }

    pub fn resume(&self, run: &mut Run, event: Event) -> Result<Progress> {
        self.validate()?;
        if run.pipeline_version != self.config_version || run.pipeline_hash != self.config_hash {
            return Err(IdpError::AuthFailed("Pipeline version mismatch".into()));
        }
        let Some(current) = run.current.clone() else {
            return Ok(self.advance(run)?);
        };
        let node = self
            .nodes
            .get(&current)
            .ok_or_else(|| IdpError::Internal(format!("Pipeline node not found: {current}")))?;
        run.steps = run.steps.saturating_add(1);
        if run.steps > self.max_steps {
            return Ok(Progress::Deny {
                node: current,
                reason: "Pipeline step limit exceeded".into(),
            });
        }

        match event {
            Event::Input {
                node: event_node,
                data,
                at,
            } => {
                self.check_node(&current, &event_node)?;
                if !matches!(node.kind, Kind::Input | Kind::Verify(_)) {
                    return Err(IdpError::AuthFailed(format!(
                        "Pipeline node does not accept input: {current}"
                    )));
                }
                run.context.data.insert(current.clone(), data.clone());
                run.context.evidence.push(Evidence {
                    node: current.clone(),
                    at,
                    data: data.clone(),
                });
                if matches!(node.kind, Kind::Verify(_)) {
                    let inherited = run.payloads.get(&current).cloned();
                    run.payloads
                        .insert(current.clone(), merge_data(inherited, data.clone()));
                    run.submitted.insert(current.clone());
                    return Ok(self.need(&current));
                }
                let inherited = run.payloads.get(&current).cloned();
                run.payloads
                    .insert(current.clone(), merge_data(inherited, data.clone()));
                let targets = self.targets(node, &[])?;
                run.completed.insert(current.clone());
                run.current = None;
                for target in targets {
                    let inherited = run
                        .payloads
                        .get(&current)
                        .cloned()
                        .unwrap_or_else(|| run.context.data[&current].clone());
                    let payload = merge_data(Some(inherited), run.context.data[&current].clone());
                    run.payloads.insert(target.clone(), payload.clone());
                    run.context.data.insert(target.clone(), payload);
                    if matches!(node.kind, Kind::Input)
                        && self
                            .nodes
                            .get(&target)
                            .is_some_and(|next| matches!(next.kind, Kind::Verify(_)))
                    {
                        run.submitted.insert(target.clone());
                    }
                    self.arrive(run, &current, &target, false)?;
                }
                self.advance(run)
            }
            Event::Pass {
                node: event_node,
                routes,
                data,
                identity,
                at,
            } => {
                self.check_node(&current, &event_node)?;
                let targets = self.targets(node, &routes)?;
                let effect_identity = identity.clone();
                if let Some(identity) = identity {
                    if let Some(existing) = &run.context.identity {
                        if existing.provider != identity.provider
                            || existing.subject != identity.subject
                        {
                            return Ok(Progress::Deny {
                                node: current,
                                reason: "Identity mismatch".into(),
                            });
                        }
                    } else {
                        run.context.identity = Some(identity);
                    }
                }
                run.context.data.insert(current.clone(), data.clone());
                run.context.evidence.push(Evidence {
                    node: current.clone(),
                    at,
                    data: data.clone(),
                });
                if node.once && matches!(node.kind, Kind::Effect(_)) {
                    run.effects.insert(
                        current.clone(),
                        Effect {
                            routes: routes.clone(),
                            data: data.clone(),
                            identity: effect_identity,
                            at,
                        },
                    );
                }
                run.submitted.remove(&current);
                run.completed.insert(current.clone());
                run.current = None;
                for target in targets {
                    let inherited = run.payloads.get(&current).cloned();
                    let payload = merge_data(inherited, data.clone());
                    run.payloads.insert(target.clone(), payload.clone());
                    run.context.data.insert(target.clone(), payload);
                    self.arrive(run, &current, &target, false)?;
                }
                self.advance(run)
            }
            Event::Fail {
                node: event_node,
                reason,
                retry,
            } => {
                self.check_node(&current, &event_node)?;
                run.submitted.remove(&current);
                if retry {
                    let visits = run.visits.entry(current.clone()).or_default();
                    *visits = visits.saturating_add(1);
                    if let Some(limit) = node.limit {
                        if *visits > limit.max(1) {
                            run.denied =
                                Some((current.clone(), "Pipeline node limit exceeded".into()));
                            return Ok(Progress::Deny {
                                node: current,
                                reason: "Pipeline node limit exceeded".into(),
                            });
                        }
                    }
                    return Ok(Progress::Retry {
                        node: current,
                        reason,
                    });
                }
                run.completed.insert(current.clone());
                run.current = None;
                let targets = self.targets(node, &[])?;
                if targets.is_empty() {
                    return Ok(Progress::Deny {
                        node: current,
                        reason,
                    });
                }
                for target in targets {
                    self.arrive(run, &current, &target, true)?;
                }
                self.advance(run)
            }
        }
    }

    /// 执行当前节点一次，并把执行结果交回 DAG 状态机。
    pub async fn execute<R: Runner>(&self, run: &mut Run, runner: &R) -> Result<Progress> {
        let node_id = run
            .current
            .clone()
            .ok_or_else(|| IdpError::Internal("Pipeline has no current node".into()))?;
        let node = self
            .nodes
            .get(&node_id)
            .ok_or_else(|| IdpError::Internal(format!("Pipeline node not found: {node_id}")))?;
        if !runner.supports(node) {
            return Err(IdpError::Unsupported(format!("{}", node.id)));
        }
        if node.once {
            if let Some(effect) = run.effects.get(&node_id).cloned() {
                return self.resume(
                    run,
                    Event::Pass {
                        node: node_id,
                        routes: effect.routes,
                        data: effect.data,
                        identity: effect.identity,
                        at: effect.at,
                    },
                );
            }
        }
        let output = runner.run(node, &run.context).await?;
        let event = match output {
            Output::Pass {
                routes,
                data,
                identity,
                at,
            } => Event::Pass {
                node: node_id,
                routes,
                data,
                identity,
                at,
            },
            Output::Fail { reason, retry } => Event::Fail {
                node: node_id,
                reason,
                retry,
            },
        };
        self.resume(run, event)
    }

    /// 自动推进所有可以由执行器处理的节点。
    ///
    /// `Input` 和尚未收到数据的 `Verify` 节点会暂停并返回 `Need`；
    /// `Check`、`Issue`、`Effect` 以及已经收到输入的 `Verify` 节点会继续执行。
    pub async fn run<R: Runner>(&self, run: &mut Run, runner: &R) -> Result<Progress> {
        loop {
            let Some(current) = run.current.clone() else {
                return self.advance(run);
            };
            let node = self
                .nodes
                .get(&current)
                .ok_or_else(|| IdpError::Internal(format!("Pipeline node not found: {current}")))?;
            let waiting = matches!(node.kind, Kind::Input)
                || (matches!(node.kind, Kind::Verify(_)) && !run.submitted.contains(&current));
            if waiting {
                return Ok(self.need(&current));
            }
            let progress = self.execute(run, runner).await?;
            match progress {
                Progress::Need { ref node, .. }
                    if run.current.as_deref() == Some(node.as_str())
                        && (matches!(self.nodes[node.as_str()].kind, Kind::Input)
                            || (matches!(self.nodes[node.as_str()].kind, Kind::Verify(_))
                                && !run.submitted.contains(node))) =>
                {
                    return Ok(progress);
                }
                Progress::Done | Progress::Retry { .. } | Progress::Deny { .. } => {
                    return Ok(progress);
                }
                Progress::Need { .. } => continue,
            }
        }
    }

    fn advance(&self, run: &mut Run) -> Result<Progress> {
        if let Some((node, reason)) = run.denied.clone() {
            return Ok(Progress::Deny { node, reason });
        }
        if run.current.is_some() {
            return Ok(self.need(run.current.as_deref().unwrap()));
        }
        while let Some(node_id) = run.ready.pop_front() {
            if run.cancelled.contains(&node_id) {
                continue;
            }
            run.current = Some(node_id.clone());
            return Ok(self.need(&node_id));
        }
        if self.has_waiting_join(run) {
            return Ok(Progress::Deny {
                node: self.start.clone(),
                reason: "Pipeline has no executable branch".into(),
            });
        }
        Ok(Progress::Done)
    }

    fn need(&self, node_id: &str) -> Progress {
        let node = &self.nodes[node_id];
        let (kind, fields) = match &node.kind {
            Kind::Input => ("input".into(), node.fields.clone()),
            Kind::Check(kind) => (kind.clone(), Vec::new()),
            Kind::Issue(kind) => (kind.clone(), Vec::new()),
            Kind::Verify(kind) => (kind.clone(), Vec::new()),
            Kind::Effect(kind) => (kind.clone(), Vec::new()),
        };
        Progress::Need {
            node: node_id.to_string(),
            kind,
            fields,
        }
    }

    fn schedule(&self, run: &mut Run, node_id: &str) -> Result<()> {
        if run.cancelled.contains(node_id) {
            return Ok(());
        }
        if run.current.as_deref() == Some(node_id) || run.ready.iter().any(|id| id == node_id) {
            return Ok(());
        }
        self.nodes
            .get(node_id)
            .ok_or_else(|| IdpError::Internal(format!("Pipeline node not found: {node_id}")))?;
        run.activated.insert(node_id.to_string());
        if !(run.steps == 0 && node_id == self.start)
            && !self.incoming(node_id).is_empty()
            && !self.ready_for(run, node_id)
        {
            return Ok(());
        }
        let node = &self.nodes[node_id];
        if node.join == Join::Any && self.all_failed(run, node_id) {
            run.denied = Some((node_id.to_string(), "All branches failed".into()));
            return Ok(());
        }
        let visits = run.visits.entry(node_id.to_string()).or_default();
        *visits = visits.saturating_add(1);
        if let Some(limit) = node.limit {
            if *visits > limit.max(1) {
                run.denied = Some((node_id.to_string(), "Pipeline node limit exceeded".into()));
                return Ok(());
            }
        }
        if node.join == Join::Any {
            for source in self.incoming(node_id) {
                if source != node_id {
                    run.ready.retain(|id| id != &source);
                    run.cancelled.insert(source);
                }
            }
        }
        run.ready.push_back(node_id.to_string());
        Ok(())
    }

    fn arrive(&self, run: &mut Run, from: &str, target: &str, failed: bool) -> Result<()> {
        if failed {
            run.failed
                .entry(target.to_string())
                .or_default()
                .insert(from.to_string());
        } else {
            run.arrived
                .entry(target.to_string())
                .or_default()
                .insert(from.to_string());
        }
        self.schedule(run, target)?;
        Ok(())
    }

    fn ready_for(&self, run: &Run, node_id: &str) -> bool {
        let Some(node) = self.nodes.get(node_id) else {
            return false;
        };
        let expected = self
            .incoming(node_id)
            .into_iter()
            .filter(|source| run.activated.contains(source))
            .collect::<BTreeSet<_>>();
        let arrived = run.arrived.get(node_id).cloned().unwrap_or_default();
        let failed = run.failed.get(node_id).cloned().unwrap_or_default();
        match node.join {
            Join::All => !expected.is_empty() && expected.is_subset(&arrived),
            Join::Any => {
                !arrived.is_empty() || (!expected.is_empty() && expected.is_subset(&failed))
            }
        }
    }

    fn all_failed(&self, run: &Run, node_id: &str) -> bool {
        let expected = self
            .incoming(node_id)
            .into_iter()
            .filter(|source| run.activated.contains(source))
            .collect::<BTreeSet<_>>();
        let failed = run.failed.get(node_id).cloned().unwrap_or_default();
        !expected.is_empty() && expected.is_subset(&failed)
    }

    fn has_waiting_join(&self, run: &Run) -> bool {
        self.nodes.keys().any(|node_id| {
            run.activated.contains(node_id)
                && !run.completed.contains(node_id)
                && !run.ready.iter().any(|id| id == node_id)
                && run.current.as_deref() != Some(node_id)
                && !self.ready_for(run, node_id)
        })
    }

    fn targets(&self, node: &Node, routes: &[String]) -> Result<Vec<String>> {
        let targets = if routes.is_empty() {
            node.edges
                .iter()
                .filter(|edge| edge.route.is_none())
                .map(|edge| edge.to.clone())
                .collect::<Vec<_>>()
        } else {
            node.edges
                .iter()
                .filter(|edge| {
                    edge.route
                        .as_ref()
                        .is_some_and(|route| routes.contains(route))
                })
                .map(|edge| edge.to.clone())
                .collect::<Vec<_>>()
        };
        if !routes.is_empty() && targets.is_empty() {
            return Err(IdpError::AuthFailed(format!(
                "Pipeline route not found at node {}",
                node.id
            )));
        }
        Ok(targets)
    }

    fn incoming(&self, target: &str) -> BTreeSet<String> {
        self.nodes
            .values()
            .filter(|node| node.edges.iter().any(|edge| edge.to == target))
            .map(|node| node.id.clone())
            .collect()
    }

    fn check_node(&self, expected: &str, actual: &str) -> Result<()> {
        if expected == actual {
            Ok(())
        } else {
            Err(IdpError::AuthFailed(format!(
                "Pipeline node mismatch: expected {expected}, got {actual}"
            )))
        }
    }

    fn validate_cycles(&self) -> Result<()> {
        fn visit(
            pipeline: &Pipeline,
            node: &str,
            stack: &mut Vec<String>,
            visiting: &mut BTreeSet<String>,
            done: &mut BTreeSet<String>,
        ) -> Result<()> {
            if done.contains(node) {
                return Ok(());
            }
            if visiting.contains(node) {
                let start = stack.iter().position(|id| id == node).unwrap_or(0);
                for id in &stack[start..] {
                    if pipeline.nodes[id].limit.is_none() {
                        return Err(IdpError::Internal(format!(
                            "Pipeline cycle requires node limit: {id}"
                        )));
                    }
                }
                return Ok(());
            }
            visiting.insert(node.to_string());
            stack.push(node.to_string());
            for edge in &pipeline.nodes[node].edges {
                visit(pipeline, &edge.to, stack, visiting, done)?;
            }
            stack.pop();
            visiting.remove(node);
            done.insert(node.to_string());
            Ok(())
        }

        let mut stack = Vec::new();
        let mut visiting = BTreeSet::new();
        let mut done = BTreeSet::new();
        visit(self, &self.start, &mut stack, &mut visiting, &mut done)
    }
}

fn merge_data(previous: Option<Value>, current: Value) -> Value {
    match (previous, current) {
        (Some(Value::Object(mut previous)), Value::Object(current)) => {
            previous.extend(current);
            Value::Object(previous)
        }
        (_, current) => current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(node: &str, routes: &[&str]) -> Event {
        Event::Pass {
            node: node.into(),
            routes: routes.iter().map(|route| (*route).into()).collect(),
            data: Value::Null,
            identity: None,
            at: 1,
        }
    }

    #[test]
    fn runs_phone_captcha_sms_totp_chain() {
        let nodes = vec![
            Node::input("phone", vec!["phone".into()]).edge(None::<String>, "captcha"),
            Node::verify("captcha", "slider").edge(None::<String>, "sms"),
            Node::issue("sms", "sms").edge(None::<String>, "code"),
            Node::input("code", vec!["code".into()]).edge(None::<String>, "sms_check"),
            Node::verify("sms_check", "sms").edge(None::<String>, "totp"),
            Node::verify("totp", "totp").edge(None::<String>, "audit"),
            Node::effect("audit", "audit"),
        ];
        let pipeline = Pipeline::new("phone", nodes);
        let (mut run, progress) = pipeline.start(Context::default()).unwrap();
        assert!(matches!(progress, Progress::Need { node, .. } if node == "phone"));
        for node in [
            "phone",
            "captcha",
            "sms",
            "code",
            "sms_check",
            "totp",
            "audit",
        ] {
            let progress = pipeline.resume(&mut run, pass(node, &[])).unwrap();
            if node == "audit" {
                assert_eq!(progress, Progress::Done);
            }
        }
    }

    #[test]
    fn supports_if_else_routes() {
        let pipeline = Pipeline::new(
            "password",
            vec![
                Node::verify("password", "password")
                    .edge(Some("normal"), "audit")
                    .edge(Some("risk"), "totp"),
                Node::verify("totp", "totp").edge(None::<String>, "audit"),
                Node::effect("audit", "audit").join(Join::Any),
            ],
        );
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        assert!(matches!(
            pipeline.resume(&mut run, pass("password", &["risk"])).unwrap(),
            Progress::Need { ref node, .. } if node == "totp"
        ));
        assert!(matches!(
            pipeline.resume(&mut run, pass("totp", &[])).unwrap(),
            Progress::Need { ref node, .. } if node == "audit"
        ));
    }

    #[test]
    fn supports_all_and_any_joins() {
        let all = Pipeline::new(
            "start",
            vec![
                Node::verify("start", "start")
                    .edge(Some("a"), "a")
                    .edge(Some("b"), "b"),
                Node::verify("a", "a").edge(None::<String>, "join"),
                Node::verify("b", "b").edge(None::<String>, "join"),
                Node::effect("join", "audit").join(Join::All),
            ],
        );
        let (mut run, _) = all.start(Context::default()).unwrap();
        assert!(matches!(
            all.resume(&mut run, pass("start", &["a", "b"])).unwrap(),
            Progress::Need { ref node, .. } if node == "a"
        ));
        assert!(matches!(
            all.resume(&mut run, pass("a", &[])).unwrap(),
            Progress::Need { ref node, .. } if node == "b"
        ));
        assert!(matches!(
            all.resume(&mut run, pass("b", &[])).unwrap(),
            Progress::Need { ref node, .. } if node == "join"
        ));

        let any = Pipeline::new(
            "start",
            vec![
                Node::verify("start", "start")
                    .edge(Some("a"), "a")
                    .edge(Some("b"), "b"),
                Node::verify("a", "a").edge(None::<String>, "join"),
                Node::verify("b", "b").edge(None::<String>, "join"),
                Node::effect("join", "audit").join(Join::Any),
            ],
        );
        let (mut run, _) = any.start(Context::default()).unwrap();
        any.resume(&mut run, pass("start", &["a", "b"])).unwrap();
        assert!(matches!(
            any.resume(&mut run, pass("a", &[])).unwrap(),
            Progress::Need { ref node, .. } if node == "join"
        ));
    }

    #[test]
    fn handles_all_and_any_branch_failures() {
        let all = Pipeline::new(
            "start",
            vec![
                Node::verify("start", "start")
                    .edge(Some("a"), "a")
                    .edge(Some("b"), "b"),
                Node::verify("a", "a").edge(None::<String>, "join"),
                Node::verify("b", "b").edge(None::<String>, "join"),
                Node::effect("join", "audit").join(Join::All),
            ],
        );
        let (mut run, _) = all.start(Context::default()).unwrap();
        all.resume(&mut run, pass("start", &["a", "b"])).unwrap();
        assert!(matches!(
            all.resume(
                &mut run,
                Event::Fail {
                    node: "a".into(),
                    reason: "bad".into(),
                    retry: false,
                },
            )
            .unwrap(),
            Progress::Need { ref node, .. } if node == "b"
        ));
        assert!(matches!(
            all.resume(&mut run, pass("b", &[])).unwrap(),
            Progress::Deny { .. }
        ));

        let any = Pipeline::new(
            "start",
            vec![
                Node::verify("start", "start")
                    .edge(Some("a"), "a")
                    .edge(Some("b"), "b"),
                Node::verify("a", "a").edge(None::<String>, "join"),
                Node::verify("b", "b").edge(None::<String>, "join"),
                Node::effect("join", "audit").join(Join::Any),
            ],
        );
        let (mut run, _) = any.start(Context::default()).unwrap();
        any.resume(&mut run, pass("start", &["a", "b"])).unwrap();
        any.resume(
            &mut run,
            Event::Fail {
                node: "a".into(),
                reason: "bad".into(),
                retry: false,
            },
        )
        .unwrap();
        assert!(matches!(
            any.resume(
                &mut run,
                Event::Fail {
                    node: "b".into(),
                    reason: "bad".into(),
                    retry: false,
                },
            )
            .unwrap(),
            Progress::Deny { .. }
        ));
    }

    #[test]
    fn restores_run_and_rejects_bad_routes() {
        let pipeline = Pipeline::new(
            "start",
            vec![
                Node::verify("start", "check").edge(Some("ok"), "done"),
                Node::effect("done", "audit"),
            ],
        );
        let (run, _) = pipeline.start(Context::default()).unwrap();
        let encoded = serde_json::to_string(&run).unwrap();
        let mut restored: Run = serde_json::from_str(&encoded).unwrap();
        assert!(
            pipeline
                .resume(&mut restored, pass("start", &["missing"]))
                .is_err()
        );
        assert!(
            pipeline
                .resume(&mut restored, pass("wrong", &["ok"]))
                .is_err()
        );
        assert!(matches!(
            pipeline.resume(&mut restored, pass("start", &["ok"])).unwrap(),
            Progress::Need { ref node, .. } if node == "done"
        ));
    }

    #[test]
    fn enforces_global_limit_and_exposes_custom_kind() {
        let pipeline = Pipeline::new(
            "check",
            vec![
                Node::check("check", "risk_score").edge(None::<String>, "done"),
                Node::effect("done", "audit"),
            ],
        )
        .max_steps(1);
        let (mut run, progress) = pipeline.start(Context::default()).unwrap();
        assert!(matches!(
            progress,
            Progress::Need { ref node, ref kind, .. }
                if node == "check" && kind == "risk_score"
        ));
        assert!(matches!(
            pipeline.resume(&mut run, pass("check", &[])).unwrap(),
            Progress::Need { ref node, .. } if node == "done"
        ));
        assert!(matches!(
            pipeline.resume(&mut run, pass("done", &[])).unwrap(),
            Progress::Deny { .. }
        ));
    }

    #[test]
    fn supports_retry_and_bounded_cycles() {
        let retry = Pipeline::new("captcha", vec![Node::verify("captcha", "slider")]);
        let (mut run, _) = retry.start(Context::default()).unwrap();
        assert!(matches!(
            retry
                .resume(
                    &mut run,
                    Event::Fail {
                        node: "captcha".into(),
                        reason: "wrong".into(),
                        retry: true,
                    },
                )
                .unwrap(),
            Progress::Retry { .. }
        ));

        let cycle = Pipeline::new(
            "captcha",
            vec![
                Node::verify("captcha", "slider")
                    .edge(Some("retry"), "captcha")
                    .edge(Some("pass"), "done")
                    .limit(2),
                Node::effect("done", "audit"),
            ],
        );
        let (mut run, _) = cycle.start(Context::default()).unwrap();
        let first = cycle.resume(&mut run, pass("captcha", &["retry"])).unwrap();
        assert!(matches!(first, Progress::Need { ref node, .. } if node == "captcha"));
        assert!(matches!(
            cycle.resume(&mut run, pass("captcha", &["retry"])).unwrap(),
            Progress::Deny { .. }
        ));
    }

    #[test]
    fn validates_graph_and_identity() {
        let duplicate = Pipeline::new(
            "one",
            vec![Node::input("one", vec![]), Node::effect("one", "audit")],
        );
        assert!(duplicate.start(Context::default()).is_err());

        let missing = Pipeline::new(
            "one",
            vec![Node::input("one", vec![]).edge(None::<String>, "two")],
        );
        assert!(missing.start(Context::default()).is_err());

        let pipeline = Pipeline::new("one", vec![Node::verify("one", "password")]);
        let (mut run, _) = pipeline
            .start(Context {
                identity: Some(Identity::new("local", "1")),
                ..Context::default()
            })
            .unwrap();
        let progress = pipeline
            .resume(
                &mut run,
                Event::Pass {
                    node: "one".into(),
                    routes: Vec::new(),
                    data: Value::Null,
                    identity: Some(Identity::new("local", "2")),
                    at: 1,
                },
            )
            .unwrap();
        assert!(matches!(progress, Progress::Deny { .. }));
    }

    struct Pass;

    impl Runner for Pass {
        async fn run(&self, _node: &Node, _context: &Context) -> Result<Output> {
            Ok(Output::Pass {
                routes: Vec::new(),
                data: Value::Null,
                identity: None,
                at: 1,
            })
        }
    }

    #[tokio::test]
    async fn executes_nodes_through_runner() {
        let pipeline = Pipeline::new(
            "input",
            vec![
                Node::input("input", vec!["phone".into()]).edge(None::<String>, "verify"),
                Node::verify("verify", "captcha"),
            ],
        );
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        assert!(matches!(
            pipeline.execute(&mut run, &Pass).await.unwrap(),
            Progress::Need { ref node, .. } if node == "verify"
        ));
        assert_eq!(
            pipeline.execute(&mut run, &Pass).await.unwrap(),
            Progress::Done
        );
    }

    struct Unsupported;

    impl Runner for Unsupported {
        async fn run(&self, node: &Node, _context: &Context) -> Result<Output> {
            Err(IdpError::Unsupported(format!(
                "Unsupported pipeline verifier: {}",
                node.id
            )))
        }
    }

    struct Custom;

    impl Runner for Custom {
        async fn run(&self, _node: &Node, _context: &Context) -> Result<Output> {
            Ok(Output::Pass {
                routes: Vec::new(),
                data: serde_json::json!({ "custom": true }),
                identity: None,
                at: 1,
            })
        }
    }

    #[tokio::test]
    async fn extends_builtin_runner_with_custom_kind() {
        let pipeline = Pipeline::new("custom", vec![Node::effect("custom", "social.custom")]);
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        let runner = Fallback::new(Custom, Unsupported);
        assert_eq!(
            pipeline.run(&mut run, &runner).await.unwrap(),
            Progress::Done
        );
        assert_eq!(run.context.data["custom"]["custom"], Value::Bool(true));
    }

    struct BasePass;

    impl Runner for BasePass {
        async fn run(&self, _node: &Node, _context: &Context) -> Result<Output> {
            Ok(Output::Pass {
                routes: Vec::new(),
                data: serde_json::json!({ "source": "base" }),
                identity: None,
                at: 1,
            })
        }
    }

    struct Override;

    impl Runner for Override {
        async fn run(&self, _node: &Node, _context: &Context) -> Result<Output> {
            Ok(Output::Pass {
                routes: Vec::new(),
                data: serde_json::json!({ "source": "custom" }),
                identity: None,
                at: 1,
            })
        }
    }

    #[tokio::test]
    async fn custom_runner_overrides_builtin_kind() {
        let pipeline = Pipeline::new("password", vec![Node::effect("password", "password")]);
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        let runner = Fallback::new(Override, BasePass);
        assert_eq!(
            pipeline.run(&mut run, &runner).await.unwrap(),
            Progress::Done
        );
        assert_eq!(
            run.context.data["password"]["source"],
            Value::String("custom".into())
        );
    }
}
