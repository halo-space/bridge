use super::run::{Effect, clean};
use crate::error::{Error, Result};
use crate::types::Identity;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// 明确标记不应进入日志、审计或可恢复运行状态的值。
/// JSON 上下文仍会保留字段名清理作为最后一道防线；调用方在有类型边界的
/// API 中应优先使用此类型，并只在真正需要的位置调用 `expose`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sensitive<T>(pub T);

impl<T> Sensitive<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

pub(crate) const MAX_VALUE_BYTES: usize = 64 * 1024;
const MAX_VALUE_DEPTH: usize = 16;
const MAX_OBJECT_FIELDS: usize = 256;
const MAX_ARRAY_ITEMS: usize = 1024;
const MAX_STRING_BYTES: usize = 8 * 1024;

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
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub retries: u32,
    #[serde(default)]
    pub idempotency: Option<String>,
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
            timeout: None,
            retries: 0,
            idempotency: None,
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

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout.max(1));
        self
    }

    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    pub fn idempotency(mut self, key: impl Into<String>) -> Self {
        self.idempotency = Some(key.into());
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
            timeout: None,
            retries: 0,
            idempotency: None,
            edges: Vec::new(),
            join: Join::All,
            limit: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
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

impl Context {
    /// 校验跨请求上下文的大小，避免把任意大对象带入 Run 或 Runner。
    pub fn validate(&self) -> Result<()> {
        if serde_json::to_vec(self)
            .map(|bytes| bytes.len() > MAX_VALUE_BYTES)
            .unwrap_or(true)
        {
            return Err(Error::AuthFailed("Pipeline context is too large".into()));
        }
        check_value(&self.request, 0)?;
        for value in self.meta.values() {
            check_value(value, 0)?;
        }
        for value in self.data.values() {
            check_value(value, 0)?;
        }
        for item in &self.evidence {
            check_value(&item.data, 0)?;
        }
        Ok(())
    }

    /// 为当前节点创建执行视图。
    ///
    /// Run 内部会保留完整流程状态，但 Runner 只应看到当前节点继承到的
    /// 数据。这样自定义 Runner 不会因为读取 Context 而混用其他分支的输入。
    /// `request`、`meta` 和已经确认的身份仍按调用方上下文传入。
    pub(crate) fn view(&self, node: &str, data: Option<&Value>, evidence: &[Evidence]) -> Self {
        let mut current = Map::new();
        if let Some(data) = data {
            current.insert(node.to_string(), data.clone());
        }
        Self {
            protocol: self.protocol.clone(),
            connection: self.connection.clone(),
            identity: self.identity.clone(),
            request: clean(self.request.clone()),
            meta: self
                .meta
                .iter()
                .filter(|(key, _)| !super::run::secret_name(key))
                .map(|(key, value)| (key.clone(), clean(value.clone())))
                .collect(),
            data: current,
            evidence: evidence.to_vec(),
        }
    }
}

pub(crate) fn check_value(value: &Value, depth: usize) -> Result<()> {
    if depth > MAX_VALUE_DEPTH {
        return Err(Error::AuthFailed(
            "Pipeline value is too deeply nested".into(),
        ));
    }
    if serde_json::to_vec(value)
        .map(|bytes| bytes.len() > MAX_VALUE_BYTES)
        .unwrap_or(true)
    {
        return Err(Error::AuthFailed("Pipeline value is too large".into()));
    }
    match value {
        Value::String(text) if text.len() > MAX_STRING_BYTES => {
            Err(Error::AuthFailed("Pipeline text is too large".into()))
        }
        Value::Object(object) => {
            if object.len() > MAX_OBJECT_FIELDS {
                return Err(Error::AuthFailed(
                    "Pipeline object has too many fields".into(),
                ));
            }
            for value in object.values() {
                check_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            if values.len() > MAX_ARRAY_ITEMS {
                return Err(Error::AuthFailed(
                    "Pipeline array has too many items".into(),
                ));
            }
            for value in values {
                check_value(value, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
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

    fn version(&self, _node: &Node) -> u16 {
        1
    }

    async fn run(&self, node: &Node, context: &Context) -> Result<Output>;
}

/// 调用方提供的副作用幂等存储。
///
/// `begin` 必须由存储实现原子占用同一个 key。新执行返回带 lease 的 `New`，
/// 已有完成结果返回 `Done`，仍在有效租约内的其他执行返回 `Busy`。
/// `New` 对应的占用必须带过期时间，进程崩溃后才能由其他进程接管。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Claim {
    New { lease: String },
    Busy,
    Done(Effect),
}

#[allow(async_fn_in_trait)]
pub trait Effects: Send + Sync {
    /// 原子占用 key，并创建 `timeout` 秒的租约。过期后允许其他进程接管。
    async fn begin(&self, key: &str, timeout: u64) -> Result<Claim>;
    /// 只有持有同一个 lease 的执行者才能提交完成结果。
    async fn complete(&self, key: &str, lease: &str, effect: Effect) -> Result<()>;
    /// 只有持有同一个 lease 的执行者才能释放占用。
    async fn cancel(&self, key: &str, lease: &str) -> Result<()>;
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
            Err(Error::Unsupported(_)) => self.backup.run(node, context).await,
            result => result,
        }
    }
}
