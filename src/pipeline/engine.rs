use super::model::check_value;
use super::run::clean;
use super::*;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};
use uuid::Uuid;

const DEFAULT_MAX_STEPS: u32 = 128;

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
            return Err(Error::Internal(reason.clone()));
        }
        if !self.nodes.contains_key(&self.start) {
            return Err(Error::Internal(format!(
                "Pipeline start node not found: {}",
                self.start
            )));
        }
        if self.max_steps == 0 {
            return Err(Error::Internal("Pipeline max steps is zero".into()));
        }
        for node in self.nodes.values() {
            if node.id.trim().is_empty() {
                return Err(Error::Internal("Pipeline node id is empty".into()));
            }
            match &node.kind {
                Kind::Input => {}
                Kind::Check(code) | Kind::Issue(code) | Kind::Verify(code) | Kind::Effect(code)
                    if code.trim().is_empty() =>
                {
                    return Err(Error::Internal(format!(
                        "Pipeline capability code is empty: {}",
                        node.id
                    )));
                }
                _ => {}
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
            if (node.once || node.idempotency.is_some()) && !matches!(node.kind, Kind::Effect(_)) {
                return Err(Error::Internal(format!(
                    "Pipeline once/idempotency requires an effect node: {}",
                    node.id
                )));
            }
            let mut routes = BTreeSet::new();
            for edge in &node.edges {
                if !self.nodes.contains_key(&edge.to) {
                    return Err(Error::Internal(format!(
                        "Pipeline edge target not found: {}",
                        edge.to
                    )));
                }
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
                if !routes.insert(edge.route.clone()) {
                    return Err(Error::Internal(format!(
                        "Pipeline edge route is duplicated: {}",
                        node.id
                    )));
                }
            }
        }
        self.validate_cycles()
    }

    pub fn start(&self, context: Context) -> Result<(Run, Progress)> {
        self.validate()?;
        context.validate()?;
        let mut run = Run {
            run_id: Uuid::new_v4().to_string(),
            context,
            current: None,
            ready: VecDeque::new(),
            cancelled: BTreeSet::new(),
            activated: BTreeSet::new(),
            completed: BTreeSet::new(),
            arrived: BTreeMap::new(),
            failed: BTreeMap::new(),
            visits: BTreeMap::new(),
            attempts: BTreeMap::new(),
            steps: 0,
            expires_at: None,
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

    /// 从调用方可信短期存储恢复 Run，并校验版本、hash、节点引用、步数和过期时间。
    ///
    /// `bytes` 不应直接来自浏览器或其他不可信客户端；调用方仍需在外部存储层
    /// 设置 TTL，并在恢复后继续按本方法返回的 Run 执行。
    pub fn restore(&self, bytes: &[u8], now: i64) -> Result<Run> {
        self.validate()?;
        let run: Run = serde_json::from_slice(bytes)
            .map_err(|error| Error::AuthFailed(format!("Invalid Pipeline Run: {error}")))?;
        if run.pipeline_version != self.config_version || run.pipeline_hash != self.config_hash {
            return Err(Error::AuthFailed("Pipeline version mismatch".into()));
        }
        if run.expires_at.is_some_and(|expires| expires <= now) {
            return Err(Error::AuthFailed("Pipeline Run expired".into()));
        }
        if run.steps > self.max_steps {
            return Err(Error::AuthFailed("Pipeline step limit exceeded".into()));
        }
        run.context.validate()?;
        let known = |id: &str| self.nodes.contains_key(id);
        if run.current.as_deref().is_some_and(|id| !known(id))
            || run.ready.iter().any(|id| !known(id))
            || run.activated.iter().any(|id| !known(id))
            || run.completed.iter().any(|id| !known(id))
            || run.cancelled.iter().any(|id| !known(id))
            || run
                .arrived
                .iter()
                .any(|(target, sources)| !known(target) || sources.iter().any(|id| !known(id)))
            || run
                .failed
                .iter()
                .any(|(target, sources)| !known(target) || sources.iter().any(|id| !known(id)))
            || run.visits.keys().any(|id| !known(id))
            || run.attempts.keys().any(|id| !known(id))
            || run.payloads.keys().any(|id| !known(id))
            || run.denied.as_ref().is_some_and(|(id, _)| !known(id))
        {
            return Err(Error::AuthFailed(
                "Pipeline Run contains an unknown node".into(),
            ));
        }
        Ok(run)
    }

    pub fn resume(&self, run: &mut Run, event: Event) -> Result<Progress> {
        if matches!(event, Event::Input { .. }) {
            self.apply(run, event)
        } else {
            Err(Error::AuthFailed(
                "Pipeline pass/fail results must come from a Runner".into(),
            ))
        }
    }

    fn apply(&self, run: &mut Run, event: Event) -> Result<Progress> {
        self.validate()?;
        if let Event::Input { data, .. } | Event::Pass { data, .. } = &event {
            check_value(data, 0)?;
        }
        if run.pipeline_version != self.config_version || run.pipeline_hash != self.config_hash {
            return Err(Error::AuthFailed("Pipeline version mismatch".into()));
        }
        if let Some((node, reason)) = run.denied.clone() {
            return Ok(Progress::Deny { node, reason });
        }
        let Some(current) = run.current.clone() else {
            return self.advance(run);
        };
        let node = self
            .nodes
            .get(&current)
            .ok_or_else(|| Error::Internal(format!("Pipeline node not found: {current}")))?;
        match event {
            Event::Input {
                node: event_node,
                data,
                at,
            } => {
                self.check_node(&current, &event_node)?;
                if !matches!(node.kind, Kind::Input | Kind::Verify(_)) {
                    return Err(Error::AuthFailed(format!(
                        "Pipeline node does not accept input: {current}"
                    )));
                }
                if matches!(node.kind, Kind::Input) {
                    validate_input(&node.fields, &data)?;
                }
                run.steps = run.steps.saturating_add(1);
                if run.steps > self.max_steps {
                    run.denied = Some((current.clone(), "Pipeline step limit exceeded".into()));
                    run.current = None;
                    return Ok(Progress::Deny {
                        node: current,
                        reason: "Pipeline step limit exceeded".into(),
                    });
                }
                run.context.data.insert(current.clone(), data.clone());
                run.context.evidence.push(Evidence {
                    node: current.clone(),
                    at,
                    data: clean(data.clone()),
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
                clear_completed(
                    self,
                    &mut run.context,
                    &mut run.payloads,
                    &run.completed,
                    None,
                );
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
                run.steps = run.steps.saturating_add(1);
                if run.steps > self.max_steps {
                    run.denied = Some((current.clone(), "Pipeline step limit exceeded".into()));
                    run.current = None;
                    return Ok(Progress::Deny {
                        node: current,
                        reason: "Pipeline step limit exceeded".into(),
                    });
                }
                let targets = self.targets(node, &routes)?;
                let effect_identity = identity.clone();
                if let Some(identity) = identity {
                    if let Some(existing) = &run.context.identity {
                        if existing.provider != identity.provider
                            || existing.subject != identity.subject
                        {
                            run.denied = Some((current.clone(), "Identity mismatch".into()));
                            run.current = None;
                            return Ok(Progress::Deny {
                                node: current,
                                reason: "Identity mismatch".into(),
                            });
                        }
                    } else {
                        run.context.identity = Some(identity);
                    }
                }
                let safe = clean(data.clone());
                run.context.data.insert(current.clone(), data.clone());
                run.context.evidence.push(Evidence {
                    node: current.clone(),
                    at,
                    data: safe.clone(),
                });
                if (node.once || node.idempotency.is_some()) && matches!(node.kind, Kind::Effect(_))
                {
                    let effect_key = node.idempotency.clone().unwrap_or_else(|| current.clone());
                    run.effects.insert(
                        effect_key,
                        Effect {
                            routes: routes.clone(),
                            data: safe.clone(),
                            identity: effect_identity,
                            at,
                        },
                    );
                }
                run.submitted.remove(&current);
                run.attempts.remove(&current);
                run.completed.insert(current.clone());
                run.current = None;
                for target in targets {
                    let inherited = run.payloads.get(&current).cloned();
                    let payload = merge_data(inherited.map(clean), data.clone());
                    run.payloads.insert(target.clone(), payload.clone());
                    run.context.data.insert(target.clone(), payload);
                    self.arrive(run, &current, &target, false)?;
                }
                let preserve = matches!(node.kind, Kind::Issue(_)).then_some(current.as_str());
                clear_completed(
                    self,
                    &mut run.context,
                    &mut run.payloads,
                    &run.completed,
                    preserve,
                );
                self.advance(run)
            }
            Event::Fail {
                node: event_node,
                reason,
                retry,
            } => {
                self.check_node(&current, &event_node)?;
                run.steps = run.steps.saturating_add(1);
                if run.steps > self.max_steps {
                    run.denied = Some((current.clone(), "Pipeline step limit exceeded".into()));
                    run.current = None;
                    return Ok(Progress::Deny {
                        node: current,
                        reason: "Pipeline step limit exceeded".into(),
                    });
                }
                run.submitted.remove(&current);
                if retry {
                    if matches!(node.kind, Kind::Verify(_)) {
                        run.context.data.remove(&current);
                        run.payloads.remove(&current);
                        clear_completed(
                            self,
                            &mut run.context,
                            &mut run.payloads,
                            &run.completed,
                            None,
                        );
                    }
                    let visits = run.visits.entry(current.clone()).or_default();
                    *visits = visits.saturating_add(1);
                    if let Some(limit) = node.limit
                        && *visits > limit.max(1)
                    {
                        run.denied = Some((current.clone(), "Pipeline node limit exceeded".into()));
                        run.current = None;
                        return Ok(Progress::Deny {
                            node: current,
                            reason: "Pipeline node limit exceeded".into(),
                        });
                    }
                    return Ok(Progress::Retry {
                        node: current,
                        reason,
                    });
                }
                run.attempts.remove(&current);
                run.context.data.remove(&current);
                run.payloads.remove(&current);
                run.completed.insert(current.clone());
                run.current = None;
                let targets = self.targets(node, &[])?;
                if targets.is_empty() {
                    run.denied = Some((current.clone(), reason.clone()));
                    return Ok(Progress::Deny {
                        node: current,
                        reason,
                    });
                }
                for target in targets {
                    self.arrive(run, &current, &target, true)?;
                }
                clear_completed(
                    self,
                    &mut run.context,
                    &mut run.payloads,
                    &run.completed,
                    None,
                );
                self.advance(run)
            }
        }
    }

    /// 执行当前节点一次，并把执行结果交回 DAG 状态机。
    pub async fn execute<R: Runner>(&self, run: &mut Run, runner: &R) -> Result<Progress> {
        let node_id = run
            .current
            .clone()
            .ok_or_else(|| Error::Internal("Pipeline has no current node".into()))?;
        let node = self
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::Internal(format!("Pipeline node not found: {node_id}")))?;
        if !runner.supports(node) {
            return Err(Error::Unsupported(node.id.to_string()));
        }
        let effect_key = node.idempotency.clone().unwrap_or_else(|| node_id.clone());
        if matches!(node.kind, Kind::Effect(_))
            && (node.once || node.idempotency.is_some())
            && let Some(effect) = run.effects.get(&effect_key).cloned()
        {
            return self.apply(
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
        let attempts = run.attempts.entry(node_id.clone()).or_default();
        *attempts = attempts.saturating_add(1);
        let attempt = *attempts;
        let evidence = self.evidence(run, &node_id);
        let context = run
            .context
            .view(&node_id, run.payloads.get(&node_id), &evidence);
        let started = Instant::now();
        let output = match runner.run(node, &context).await {
            Ok(output) => output,
            Err(error) => return self.runner_error(run, &node_id, node, attempt, error),
        };
        if let Some(timeout) = node.timeout
            && started.elapsed() > Duration::from_secs(timeout)
        {
            let reason = "Pipeline node timeout".to_string();
            let attempt = *run.attempts.get(&node_id).unwrap_or(&1);
            if attempt <= node.retries {
                if matches!(node.kind, Kind::Verify(_)) {
                    run.context.data.remove(&node_id);
                    run.payloads.remove(&node_id);
                    clear_completed(
                        self,
                        &mut run.context,
                        &mut run.payloads,
                        &run.completed,
                        None,
                    );
                }
                return Ok(Progress::Retry {
                    node: node_id,
                    reason,
                });
            }
            run.denied = Some((node_id.clone(), reason.clone()));
            run.current = None;
            return Ok(Progress::Deny {
                node: node_id,
                reason,
            });
        }
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
                retry: retry && attempt <= node.retries,
            },
        };
        self.apply(run, event)
    }

    /// 在调用方给定的执行边界内执行一个节点。
    ///
    /// `deadline` 只负责在节点开始前和完成后检查边界；Rust future 本身不能
    /// 被 bridge 强制中断。调用方应在超时或取消时中止外层 future，并把
    /// `cancelled` 作为自己的取消信号。这样 bridge 不绑定 Tokio、线程池或
    /// Session 实现，同时保证不会在已过期的运行状态上继续推进图。
    pub async fn execute_until<R, C>(
        &self,
        run: &mut Run,
        runner: &R,
        deadline: Instant,
        cancelled: &C,
    ) -> Result<Progress>
    where
        R: Runner,
        C: Fn() -> bool + Send + Sync,
    {
        let node = run
            .current
            .clone()
            .ok_or_else(|| Error::Internal("Pipeline has no current node".into()))?;
        if cancelled() || Instant::now() >= deadline {
            return Ok(Progress::Retry {
                node,
                reason: "Pipeline execution boundary reached".into(),
            });
        }
        let progress = self.execute(run, runner).await?;
        if cancelled() || Instant::now() >= deadline {
            return Ok(Progress::Retry {
                node,
                reason: "Pipeline execution boundary reached".into(),
            });
        }
        Ok(progress)
    }

    /// 使用调用方提供的原子副作用存储执行节点。
    pub async fn execute_with<R: Runner, E: Effects>(
        &self,
        run: &mut Run,
        runner: &R,
        effects: &E,
    ) -> Result<Progress> {
        if run.run_id.is_empty() {
            run.run_id = Uuid::new_v4().to_string();
        }
        let node_id = run
            .current
            .clone()
            .ok_or_else(|| Error::Internal("Pipeline has no current node".into()))?;
        let node = self
            .nodes
            .get(&node_id)
            .ok_or_else(|| Error::Internal(format!("Pipeline node not found: {node_id}")))?;
        if !runner.supports(node) {
            return Err(Error::Unsupported(node.id.clone()));
        }
        let key = node
            .idempotency
            .clone()
            .unwrap_or_else(|| format!("{}:{}", run.run_id, node_id));
        let guarded =
            matches!(node.kind, Kind::Effect(_)) && (node.once || node.idempotency.is_some());
        let mut lease = None;
        if guarded {
            let timeout = node.timeout.unwrap_or(60).max(1);
            match effects.begin(&key, timeout).await? {
                Claim::Done(effect) => {
                    return self.apply(
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
                Claim::Busy => {
                    return Ok(Progress::Retry {
                        node: node_id,
                        reason: "Pipeline effect is running in another process".into(),
                    });
                }
                Claim::New { lease: value } => lease = Some(value),
            }
        }

        let attempts = run.attempts.entry(node_id.clone()).or_default();
        *attempts = attempts.saturating_add(1);
        let attempt = *attempts;
        let evidence = self.evidence(run, &node_id);
        let context = run
            .context
            .view(&node_id, run.payloads.get(&node_id), &evidence);
        let started = Instant::now();
        let output = match runner.run(node, &context).await {
            Ok(output) => output,
            Err(error) => {
                if let Some(lease) = lease.as_deref() {
                    effects.cancel(&key, lease).await?;
                }
                return self.runner_error(run, &node_id, node, attempt, error);
            }
        };
        if let Some(timeout) = node.timeout
            && started.elapsed() > Duration::from_secs(timeout)
        {
            if let Some(lease) = lease.as_deref() {
                effects.cancel(&key, lease).await?;
            }
            let reason = "Pipeline node timeout".to_string();
            let attempt = *run.attempts.get(&node_id).unwrap_or(&1);
            if attempt <= node.retries {
                if matches!(node.kind, Kind::Verify(_)) {
                    run.context.data.remove(&node_id);
                    run.payloads.remove(&node_id);
                    clear_completed(
                        self,
                        &mut run.context,
                        &mut run.payloads,
                        &run.completed,
                        None,
                    );
                }
                return Ok(Progress::Retry {
                    node: node_id,
                    reason,
                });
            }
            run.denied = Some((node_id.clone(), reason.clone()));
            run.current = None;
            return Ok(Progress::Deny {
                node: node_id,
                reason,
            });
        }
        let event = match output {
            Output::Pass {
                routes,
                data,
                identity,
                at,
            } => {
                if let Some(lease) = lease.as_deref() {
                    let effect = Effect {
                        routes: routes.clone(),
                        data: data.clone(),
                        identity: identity.clone(),
                        at,
                    };
                    if let Err(error) = effects.complete(&key, lease, effect).await {
                        effects.cancel(&key, lease).await?;
                        return Err(error);
                    }
                }
                Event::Pass {
                    node: node_id,
                    routes,
                    data,
                    identity,
                    at,
                }
            }
            Output::Fail { reason, retry } => {
                if let Some(lease) = lease.as_deref() {
                    effects.cancel(&key, lease).await?;
                }
                Event::Fail {
                    node: node_id,
                    reason,
                    retry: retry && attempt <= node.retries,
                }
            }
        };
        self.apply(run, event)
    }

    fn runner_error(
        &self,
        run: &mut Run,
        node_id: &str,
        node: &Node,
        attempt: u32,
        error: Error,
    ) -> Result<Progress> {
        if !retryable(&error) {
            return Err(error);
        }
        let reason = error.to_string();
        if attempt <= node.retries {
            if matches!(node.kind, Kind::Verify(_)) {
                run.context.data.remove(node_id);
                run.payloads.remove(node_id);
                clear_completed(
                    self,
                    &mut run.context,
                    &mut run.payloads,
                    &run.completed,
                    None,
                );
            }
            return Ok(Progress::Retry {
                node: node_id.to_string(),
                reason,
            });
        }
        run.denied = Some((node_id.to_string(), reason.clone()));
        run.current = None;
        Ok(Progress::Deny {
            node: node_id.to_string(),
            reason,
        })
    }

    /// 自动推进所有可以由执行器处理的节点。
    ///
    /// `Input` 和尚未收到数据的 `Verify` 节点会暂停并返回 `Need`；
    /// `Check`、`Issue`、`Effect` 以及已经收到输入的 `Verify` 节点会继续执行。
    pub async fn run<R: Runner>(&self, run: &mut Run, runner: &R) -> Result<Progress> {
        loop {
            if let Some((node, reason)) = run.denied.clone() {
                return Ok(Progress::Deny { node, reason });
            }
            let Some(current) = run.current.clone() else {
                return self.advance(run);
            };
            let node = self
                .nodes
                .get(&current)
                .ok_or_else(|| Error::Internal(format!("Pipeline node not found: {current}")))?;
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

    pub async fn run_with<R: Runner, E: Effects>(
        &self,
        run: &mut Run,
        runner: &R,
        effects: &E,
    ) -> Result<Progress> {
        loop {
            if let Some((node, reason)) = run.denied.clone() {
                return Ok(Progress::Deny { node, reason });
            }
            let Some(current) = run.current.clone() else {
                return self.advance(run);
            };
            let node = self
                .nodes
                .get(&current)
                .ok_or_else(|| Error::Internal(format!("Pipeline node not found: {current}")))?;
            let waiting = matches!(node.kind, Kind::Input)
                || (matches!(node.kind, Kind::Verify(_)) && !run.submitted.contains(&current));
            if waiting {
                return Ok(self.need(&current));
            }
            let progress = self.execute_with(run, runner, effects).await?;
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
            let reason = "Pipeline has no executable branch".to_string();
            run.denied = Some((self.start.clone(), reason.clone()));
            run.current = None;
            return Ok(Progress::Deny {
                node: self.start.clone(),
                reason,
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
            .ok_or_else(|| Error::Internal(format!("Pipeline node not found: {node_id}")))?;
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
        if let Some(limit) = node.limit
            && *visits > limit.max(1)
        {
            run.denied = Some((node_id.to_string(), "Pipeline node limit exceeded".into()));
            return Ok(());
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
            return Err(Error::AuthFailed(format!(
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

    fn evidence(&self, run: &Run, node_id: &str) -> Vec<Evidence> {
        let mut allowed = BTreeSet::new();
        let mut pending = vec![node_id.to_string()];
        while let Some(node) = pending.pop() {
            if !allowed.insert(node.clone()) {
                continue;
            }
            for source in self.incoming(&node) {
                if run.activated.contains(&source) {
                    pending.push(source);
                }
            }
        }
        run.context
            .evidence
            .iter()
            .filter(|item| allowed.contains(&item.node))
            .cloned()
            .collect()
    }

    fn check_node(&self, expected: &str, actual: &str) -> Result<()> {
        if expected == actual {
            Ok(())
        } else {
            Err(Error::AuthFailed(format!(
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
                        return Err(Error::Internal(format!(
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
        for node in self.nodes.keys() {
            visit(self, node, &mut stack, &mut visiting, &mut done)?;
        }
        Ok(())
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

fn clear_completed(
    pipeline: &Pipeline,
    context: &mut Context,
    payloads: &mut BTreeMap<String, Value>,
    completed: &BTreeSet<String>,
    preserve: Option<&str>,
) {
    for node in completed {
        if preserve == Some(node.as_str())
            && pipeline
                .nodes
                .get(node)
                .is_some_and(|item| matches!(item.kind, Kind::Issue(_)))
        {
            continue;
        }
        if let Some(value) = context.data.get_mut(node) {
            let current = std::mem::replace(value, Value::Null);
            *value = clean(current);
        }
        if let Some(value) = payloads.get_mut(node) {
            let current = std::mem::replace(value, Value::Null);
            *value = clean(current);
        }
    }
}

fn validate_input(fields: &[String], data: &Value) -> Result<()> {
    if fields.is_empty() {
        return Ok(());
    }
    let object = data
        .as_object()
        .ok_or_else(|| Error::AuthFailed("Pipeline input must be an object".into()))?;
    for field in fields {
        if object.get(field).is_none_or(Value::is_null) {
            return Err(Error::AuthFailed(format!(
                "Pipeline input is missing field: {field}"
            )));
        }
    }
    Ok(())
}

fn retryable(error: &Error) -> bool {
    matches!(
        error,
        Error::StoreError(_)
            | Error::Transient(_)
            | Error::LdapError(_)
            | Error::EmailFailed(_)
            | Error::SmsFailed(_)
            | Error::SyncError(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Identity;

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
            let progress = pipeline.apply(&mut run, pass(node, &[])).unwrap();
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
            pipeline.apply(&mut run, pass("password", &["risk"])).unwrap(),
            Progress::Need { ref node, .. } if node == "totp"
        ));
        assert!(matches!(
            pipeline.apply(&mut run, pass("totp", &[])).unwrap(),
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
            all.apply(&mut run, pass("start", &["a", "b"])).unwrap(),
            Progress::Need { ref node, .. } if node == "a"
        ));
        assert!(matches!(
            all.apply(&mut run, pass("a", &[])).unwrap(),
            Progress::Need { ref node, .. } if node == "b"
        ));
        assert!(matches!(
            all.apply(&mut run, pass("b", &[])).unwrap(),
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
        any.apply(&mut run, pass("start", &["a", "b"])).unwrap();
        assert!(matches!(
            any.apply(&mut run, pass("a", &[])).unwrap(),
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
        all.apply(&mut run, pass("start", &["a", "b"])).unwrap();
        assert!(matches!(
            all.apply(
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
            all.apply(&mut run, pass("b", &[])).unwrap(),
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
        any.apply(&mut run, pass("start", &["a", "b"])).unwrap();
        any.apply(
            &mut run,
            Event::Fail {
                node: "a".into(),
                reason: "bad".into(),
                retry: false,
            },
        )
        .unwrap();
        assert!(matches!(
            any.apply(
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
                .apply(&mut restored, pass("start", &["missing"]))
                .is_err()
        );
        assert!(
            pipeline
                .apply(&mut restored, pass("wrong", &["ok"]))
                .is_err()
        );
        assert!(matches!(
            pipeline.apply(&mut restored, pass("start", &["ok"])).unwrap(),
            Progress::Need { ref node, .. } if node == "done"
        ));
    }

    #[test]
    fn restores_only_current_and_unexpired_runs() {
        let pipeline = Pipeline::new(
            "start",
            vec![
                Node::input("start", vec!["account".into()]),
                Node::effect("done", "audit"),
            ],
        );
        let (run, _) = pipeline.start(Context::default()).unwrap();
        let encoded = serde_json::to_vec(&run.expires_at(100)).unwrap();
        assert!(pipeline.restore(&encoded, 99).is_ok());
        assert!(pipeline.restore(&encoded, 100).is_err());

        let mut tampered: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        tampered["pipeline_version"] = serde_json::json!(7);
        let tampered = serde_json::to_vec(&tampered).unwrap();
        assert!(pipeline.restore(&tampered, 99).is_err());
    }

    #[test]
    fn rejects_oversized_pipeline_values() {
        let pipeline = Pipeline::new("start", vec![Node::input("start", Vec::new())]);
        let context = Context {
            request: serde_json::json!({ "blob": "x".repeat(9 * 1024) }),
            ..Context::default()
        };
        assert!(pipeline.start(context).is_err());
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
            pipeline.apply(&mut run, pass("check", &[])).unwrap(),
            Progress::Need { ref node, .. } if node == "done"
        ));
        assert!(matches!(
            pipeline.apply(&mut run, pass("done", &[])).unwrap(),
            Progress::Deny { .. }
        ));
    }

    #[test]
    fn supports_retry_and_bounded_cycles() {
        let retry = Pipeline::new("captcha", vec![Node::verify("captcha", "slider")]);
        let (mut run, _) = retry.start(Context::default()).unwrap();
        assert!(matches!(
            retry
                .apply(
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
        let first = cycle.apply(&mut run, pass("captcha", &["retry"])).unwrap();
        assert!(matches!(first, Progress::Need { ref node, .. } if node == "captcha"));
        assert!(matches!(
            cycle.apply(&mut run, pass("captcha", &["retry"])).unwrap(),
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
            .apply(
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
        assert!(run.current.is_none());
        assert!(matches!(
            pipeline.resume(
                &mut run,
                Event::Input {
                    node: "one".into(),
                    data: serde_json::json!({ "code": "123456" }),
                    at: 2,
                },
            ),
            Ok(Progress::Deny { .. })
        ));
    }

    #[test]
    fn public_resume_accepts_input_only() {
        let pipeline = Pipeline::new("check", vec![Node::verify("check", "password")]);
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        let current = run.current.clone();
        assert!(matches!(
            pipeline.resume(&mut run, pass("check", &[])),
            Err(Error::AuthFailed(message)) if message.contains("must come from a Runner")
        ));
        assert_eq!(run.current, current);
    }

    #[test]
    fn input_fields_are_required() {
        let pipeline = Pipeline::new("input", vec![Node::input("input", vec!["account".into()])]);
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        assert!(matches!(
            pipeline.resume(
                &mut run,
                Event::Input {
                    node: "input".into(),
                    data: serde_json::json!({}),
                    at: 1,
                },
            ),
            Err(Error::AuthFailed(message)) if message.contains("account")
        ));
    }

    #[test]
    fn deny_is_terminal_after_a_failed_leaf() {
        let pipeline = Pipeline::new("check", vec![Node::verify("check", "password")]);
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        let denied = pipeline
            .apply(
                &mut run,
                Event::Fail {
                    node: "check".into(),
                    reason: "invalid".into(),
                    retry: false,
                },
            )
            .unwrap();
        assert!(matches!(denied, Progress::Deny { .. }));
        assert!(matches!(
            pipeline.resume(
                &mut run,
                Event::Input {
                    node: "check".into(),
                    data: serde_json::json!({ "password": "secret" }),
                    at: 1,
                },
            ),
            Ok(Progress::Deny { .. })
        ));
    }

    #[test]
    fn refuses_to_serialize_pending_authentication_material() {
        let pipeline = Pipeline::new("input", vec![Node::verify("input", "password")]);
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        let _ = pipeline
            .apply(
                &mut run,
                Event::Input {
                    node: "input".into(),
                    data: serde_json::json!({ "password": "secret" }),
                    at: 1,
                },
            )
            .unwrap();
        assert!(serde_json::to_string(&run).is_err());

        let mut context = Context {
            request: serde_json::json!({ "password_hash": "hash" }),
            ..Context::default()
        };
        context
            .meta
            .insert("access_token".into(), serde_json::json!("token"));
        let (run, _) = pipeline.start(context).unwrap();
        assert!(serde_json::to_string(&run).is_err());
    }

    #[test]
    fn refuses_to_serialize_protocol_challenge() {
        let pipeline = Pipeline::new("issue", vec![Node::issue("issue", "passkey")]);
        let mut context = Context::default();
        context.data.insert(
            "issue".into(),
            serde_json::json!({"options": {"challenge": "opaque"}}),
        );
        let (run, _) = pipeline.start(context).unwrap();
        assert!(serde_json::to_string(&run).is_err());
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
        assert!(serde_json::to_string(&run).is_ok());
    }

    #[tokio::test]
    async fn runner_context_redacts_request_and_meta_secrets() {
        use std::sync::{Arc, Mutex};

        let pipeline = Pipeline::new(
            "input",
            vec![
                Node::input("input", vec!["phone".into()]).edge(None::<String>, "verify"),
                Node::verify("verify", "captcha"),
            ],
        );
        let seen = Arc::new(Mutex::new(None));
        let capture = seen.clone();
        struct Inspect(Arc<Mutex<Option<Context>>>);
        impl Runner for Inspect {
            async fn run(&self, _node: &Node, context: &Context) -> Result<Output> {
                *self.0.lock().unwrap() = Some(context.clone());
                Ok(Output::Pass {
                    routes: Vec::new(),
                    data: Value::Null,
                    identity: None,
                    at: 1,
                })
            }
        }
        let mut context = Context {
            request: serde_json::json!({"password": "secret", "return_to": "/home"}),
            ..Context::default()
        };
        context
            .meta
            .insert("access_token".into(), Value::String("secret".into()));
        context
            .meta
            .insert("device".into(), Value::String("browser".into()));
        let (mut run, _) = pipeline.start(context).unwrap();
        pipeline
            .resume(
                &mut run,
                Event::Input {
                    node: "input".into(),
                    data: serde_json::json!({"phone": "13800138000"}),
                    at: 1,
                },
            )
            .unwrap();
        pipeline.run(&mut run, &Inspect(capture)).await.unwrap();
        let seen = seen.lock().unwrap().clone().unwrap();
        assert_eq!(seen.request, serde_json::json!({"return_to": "/home"}));
        assert_eq!(
            seen.meta.get("device"),
            Some(&Value::String("browser".into()))
        );
        assert!(!seen.meta.contains_key("access_token"));
    }

    #[tokio::test]
    async fn keeps_issue_material_until_the_next_input() {
        let pipeline = Pipeline::new(
            "issue",
            vec![
                Node::issue("issue", "passkey").edge(None::<String>, "input"),
                Node::input("input", vec!["value".into()]),
            ],
        );
        let (mut run, progress) = pipeline.start(Context::default()).unwrap();
        assert!(matches!(progress, Progress::Need { ref node, .. } if node == "issue"));
        struct IssuePass;
        impl Runner for IssuePass {
            async fn run(&self, _node: &Node, _context: &Context) -> Result<Output> {
                Ok(Output::Pass {
                    routes: Vec::new(),
                    data: serde_json::json!({
                        "options": { "challenge": "public" },
                        "state": "secret"
                    }),
                    identity: None,
                    at: 1,
                })
            }
        }
        assert!(matches!(
            pipeline.run(&mut run, &IssuePass).await.unwrap(),
            Progress::Need { ref node, .. } if node == "input"
        ));
        assert_eq!(run.context.data["issue"]["state"], "secret");
        assert!(serde_json::to_string(&run).is_err());
        run.clear();
        assert!(serde_json::to_string(&run).is_ok());
        let progress = pipeline
            .resume(
                &mut run,
                Event::Input {
                    node: "input".into(),
                    data: serde_json::json!({ "value": "ok" }),
                    at: 1,
                },
            )
            .unwrap();
        assert_eq!(run.context.data["issue"].get("state"), None);
        assert_eq!(progress, Progress::Done);
        assert!(serde_json::to_string(&run).is_ok());
    }

    #[tokio::test]
    async fn clears_password_before_waiting_for_a_following_factor() {
        let pipeline = Pipeline::new(
            "password",
            vec![
                Node::input("password", vec!["password".into()]).edge(None::<String>, "check"),
                Node::verify("check", "password").edge(None::<String>, "totp"),
                Node::input("totp", vec!["code".into()]),
            ],
        );
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        pipeline
            .resume(
                &mut run,
                Event::Input {
                    node: "password".into(),
                    data: serde_json::json!({ "password": "secret" }),
                    at: 1,
                },
            )
            .unwrap();
        assert!(matches!(
            pipeline.run(&mut run, &Pass).await.unwrap(),
            Progress::Need { ref node, .. } if node == "totp"
        ));
        assert!(serde_json::to_string(&run).is_ok());
    }

    struct Unsupported;

    impl Runner for Unsupported {
        async fn run(&self, node: &Node, _context: &Context) -> Result<Output> {
            Err(Error::Unsupported(format!(
                "Unsupported pipeline verifier: {}",
                node.id
            )))
        }
    }

    struct Flaky {
        calls: std::sync::atomic::AtomicU32,
    }

    impl Runner for Flaky {
        async fn run(&self, _node: &Node, _context: &Context) -> Result<Output> {
            let call = self
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if call == 0 {
                Err(Error::Transient("temporary provider failure".into()))
            } else {
                Ok(Output::Pass {
                    routes: Vec::new(),
                    data: Value::Null,
                    identity: None,
                    at: 1,
                })
            }
        }
    }

    #[tokio::test]
    async fn retries_retryable_runner_errors() {
        let pipeline = Pipeline::new("effect", vec![Node::effect("effect", "audit").retries(1)]);
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        let runner = Flaky {
            calls: std::sync::atomic::AtomicU32::new(0),
        };
        assert!(matches!(
            pipeline.run(&mut run, &runner).await.unwrap(),
            Progress::Retry { ref node, .. } if node == "effect"
        ));
        assert_eq!(
            pipeline.run(&mut run, &runner).await.unwrap(),
            Progress::Done
        );
    }

    struct BusinessError;

    impl Runner for BusinessError {
        async fn run(&self, _node: &Node, _context: &Context) -> Result<Output> {
            Err(Error::OAuthError("invalid authorization code".into()))
        }
    }

    #[tokio::test]
    async fn does_not_retry_provider_business_rejections() {
        let pipeline = Pipeline::new("effect", vec![Node::effect("effect", "audit").retries(2)]);
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        assert!(matches!(
            pipeline.run(&mut run, &BusinessError).await,
            Err(Error::OAuthError(message)) if message == "invalid authorization code"
        ));
    }

    struct BusyEffects;

    impl Effects for BusyEffects {
        async fn begin(&self, _key: &str, _timeout: u64) -> Result<Claim> {
            Ok(Claim::Busy)
        }

        async fn complete(&self, _key: &str, _lease: &str, _effect: Effect) -> Result<()> {
            Ok(())
        }

        async fn cancel(&self, _key: &str, _lease: &str) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn waits_for_a_running_effect() {
        let pipeline = Pipeline::new("audit", vec![Node::effect("audit", "audit").once(true)]);
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        assert!(matches!(
            pipeline
                .execute_with(&mut run, &Pass, &BusyEffects)
                .await
                .unwrap(),
            Progress::Retry { ref node, .. } if node == "audit"
        ));
    }

    #[derive(Clone, Default)]
    struct LeaseEffects {
        completed: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    }

    impl Effects for LeaseEffects {
        async fn begin(&self, _key: &str, timeout: u64) -> Result<Claim> {
            assert_eq!(timeout, 12);
            Ok(Claim::New {
                lease: "lease-1".into(),
            })
        }

        async fn complete(&self, _key: &str, lease: &str, _effect: Effect) -> Result<()> {
            *self.completed.lock().unwrap() = Some(lease.into());
            Ok(())
        }

        async fn cancel(&self, _key: &str, _lease: &str) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn completes_effect_with_the_store_lease() {
        let pipeline = Pipeline::new(
            "audit",
            vec![Node::effect("audit", "audit").once(true).timeout(12)],
        );
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        let effects = LeaseEffects::default();
        assert_eq!(
            pipeline
                .execute_with(&mut run, &Pass, &effects)
                .await
                .unwrap(),
            Progress::Done
        );
        assert_eq!(
            effects.completed.lock().unwrap().as_deref(),
            Some("lease-1")
        );
    }

    #[tokio::test]
    async fn honors_explicit_execution_boundary() {
        let pipeline = Pipeline::new("audit", vec![Node::effect("audit", "audit")]);
        let (mut run, _) = pipeline.start(Context::default()).unwrap();
        let progress = pipeline
            .execute_until(
                &mut run,
                &Pass,
                Instant::now() - Duration::from_secs(1),
                &|| false,
            )
            .await
            .unwrap();
        assert!(matches!(progress, Progress::Retry { node, .. } if node == "audit"));
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
