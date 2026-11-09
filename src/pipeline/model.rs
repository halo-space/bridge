use super::run::Effect;
use crate::error::{Error, Result};
use crate::types::Identity;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

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
/// `begin` 必须由存储实现原子占用同一个 key；已有完成结果返回 `Done`，
/// 新执行返回 `New`。这样多个进程恢复同一个 Run 时不会重复执行副作用。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Claim {
    New,
    Done(Effect),
}

#[allow(async_fn_in_trait)]
pub trait Effects: Send + Sync {
    async fn begin(&self, key: &str) -> Result<Claim>;
    async fn complete(&self, key: &str, effect: Effect) -> Result<()>;
    async fn cancel(&self, key: &str) -> Result<()>;
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
