use crate::error::{IdpError, Result};
use crate::types::Identity;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    pub id: String,
    pub kind: Kind,
    pub fields: Vec<String>,
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
            edges: Vec::new(),
            join: Join::All,
            limit: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    pub tenant_id: i64,
    pub identity: Option<Identity>,
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
            invalid,
        }
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
        };
        self.schedule(&mut run, &self.start)?;
        let progress = self.advance(&mut run)?;
        Ok((run, progress))
    }

    pub fn resume(&self, run: &mut Run, event: Event) -> Result<Progress> {
        self.validate()?;
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
            Event::Pass {
                node: event_node,
                routes,
                data,
                identity,
                at,
            } => {
                self.check_node(&current, &event_node)?;
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
                    data,
                });
                run.completed.insert(current.clone());
                run.current = None;
                for target in self.targets(node, &routes)? {
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
}
