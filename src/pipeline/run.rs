use super::Context;
use crate::types::Identity;
use serde::ser::Error as SerError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Deserialize)]
pub struct Run {
    #[serde(default)]
    pub run_id: String,
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
    /// 当前节点已经交给 Runner 的次数，用于落实节点 retries 上限。
    #[serde(default)]
    pub attempts: BTreeMap<String, u32>,
    pub steps: u32,
    /// 调用方设置的短期运行状态过期时间（Unix 秒）。
    #[serde(default)]
    pub expires_at: Option<i64>,
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

impl Run {
    /// 设置运行状态的过期时间。调用方应把这个时间同时写入短期存储 TTL。
    pub fn expires_at(mut self, at: i64) -> Self {
        self.expires_at = Some(at);
        self
    }

    /// 清理运行状态中的短期认证材料，便于调用方保存剩余流程。
    ///
    /// 调用方应先把当前节点需要返回给浏览器或用户的内容保存到自己的
    /// 短期存储，再调用此方法。下一次提交输入时，调用方需要把被清理的
    /// `state`、验证码答案或其他材料重新放入输入数据。
    pub fn clear(&mut self) {
        for value in self.context.data.values_mut() {
            let current = std::mem::replace(value, Value::Null);
            *value = clean(current);
        }
        self.context.request = clean(std::mem::take(&mut self.context.request));
        self.context.meta.retain(|key, _| !secret_name(key));
        for value in self.context.meta.values_mut() {
            let current = std::mem::replace(value, Value::Null);
            *value = clean(current);
        }
        for item in &mut self.context.evidence {
            item.data = clean(std::mem::replace(&mut item.data, Value::Null));
        }
        for value in self.payloads.values_mut() {
            let current = std::mem::replace(value, Value::Null);
            *value = clean(current);
        }
        for effect in self.effects.values_mut() {
            effect.data = clean(std::mem::replace(&mut effect.data, Value::Null));
        }
    }
}

#[derive(Serialize)]
struct RunWire<'a> {
    run_id: &'a String,
    context: &'a Context,
    current: &'a Option<String>,
    ready: &'a VecDeque<String>,
    cancelled: &'a BTreeSet<String>,
    activated: &'a BTreeSet<String>,
    completed: &'a BTreeSet<String>,
    arrived: &'a BTreeMap<String, BTreeSet<String>>,
    failed: &'a BTreeMap<String, BTreeSet<String>>,
    visits: &'a BTreeMap<String, u32>,
    attempts: &'a BTreeMap<String, u32>,
    steps: u32,
    expires_at: &'a Option<i64>,
    denied: &'a Option<(String, String)>,
    submitted: &'a BTreeSet<String>,
    payloads: &'a BTreeMap<String, Value>,
    pipeline_version: u16,
    pipeline_hash: &'a Option<String>,
    effects: &'a BTreeMap<String, Effect>,
}

impl Serialize for Run {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.context.data.values().any(contains_secret)
            || contains_secret(&self.context.request)
            || self
                .context
                .meta
                .iter()
                .any(|(key, value)| secret_name(key) || contains_secret(value))
            || self.payloads.values().any(contains_secret)
            || self
                .context
                .evidence
                .iter()
                .any(|item| contains_secret(&item.data))
            || self
                .effects
                .values()
                .any(|effect| contains_secret(&effect.data))
        {
            return Err(S::Error::custom(
                "Pipeline Run contains pending authentication material; execute or clear it before persistence",
            ));
        }
        if let Err(error) = self.context.validate() {
            return Err(S::Error::custom(error.to_string()));
        }
        RunWire {
            run_id: &self.run_id,
            context: &self.context,
            current: &self.current,
            ready: &self.ready,
            cancelled: &self.cancelled,
            activated: &self.activated,
            completed: &self.completed,
            arrived: &self.arrived,
            failed: &self.failed,
            visits: &self.visits,
            attempts: &self.attempts,
            steps: self.steps,
            expires_at: &self.expires_at,
            denied: &self.denied,
            submitted: &self.submitted,
            payloads: &self.payloads,
            pipeline_version: self.pipeline_version,
            pipeline_hash: &self.pipeline_hash,
            effects: &self.effects,
        }
        .serialize(serializer)
    }
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

pub(crate) fn clean(value: Value) -> Value {
    match value {
        Value::Object(mut object) => {
            object.retain(|key, _| !secret_name(key));
            for value in object.values_mut() {
                let current = std::mem::replace(value, Value::Null);
                *value = clean(current);
            }
            Value::Object(object)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(clean).collect()),
        value => value,
    }
}

pub(crate) fn contains_secret(value: &Value) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| secret_name(key) || contains_secret(value)),
        Value::Array(values) => values.iter().any(contains_secret),
        _ => false,
    }
}

pub(crate) fn secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "password"
            | "passwd"
            | "passcode"
            | "code"
            | "totp"
            | "token"
            | "secret"
            | "credential"
            | "signature"
            | "state"
            | "nonce"
            | "answer"
            | "text"
            | "challenge"
            | "otp"
            | "proof"
            | "offset_x"
            | "angle"
            | "points"
            | "client_data_json"
            | "authenticator_data"
            | "user_handle"
            | "attestation_object"
            | "assertion"
            | "password_hash"
            | "client_secret"
            | "access_token"
            | "refresh_token"
            | "verification_code"
            | "captcha_code"
    ) || name.ends_with("_token")
        || name.ends_with("_secret")
        || name.ends_with("_password")
        || name.ends_with("_credential")
        || name.ends_with("_signature")
}
