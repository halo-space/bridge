use super::{Context, Kind, Node, Output, Runner};
use crate::audit::{AuditEvent, AuditEventType, AuditOutcome};
use crate::error::{Error, Result};
use crate::factor::basic::code::{Email as EmailCode, Sms as SmsCode, Totp as TotpCode};
use crate::factor::basic::password::{Account, Email as EmailPassword, Phone as PhonePassword};
use crate::factor::enterprise::DeviceProof;
use crate::risk::RiskEngine;
use crate::store::{
    Decision, Devices, Events, Factors, Limits, Noop, Passkeys, Rule, Secrets, Users,
};
use crate::types::User;
use crate::validator::issuer::{Captcha as CaptchaIssue, Code, Passkey as PasskeyIssue};
use crate::validator::sender::{Notify, NotifyChannel};
use crate::validator::verifier::Passkey as PasskeyVerify;
use crate::validator::verifier::captcha::{
    Captcha as CaptchaVerify, CaptchaType, CaptchaVerifyReq,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::future::Future;

mod audit;
mod check;
mod device;
mod issue;
mod passkey_issue;
mod passkey_verify;
mod send;
mod verify;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    Check,
    Issue,
    Verify,
    Effect,
}

#[derive(Debug, Clone, Copy)]
enum Handler {
    Check,
    Issue,
    Verify,
    Audit,
    Send,
}

#[derive(Debug, Clone)]
struct Table {
    values: BTreeMap<(Slot, String), Handler>,
}

impl Table {
    /// 进程内的能力绑定表。业务 Pipeline 配置仍由调用方按登录请求加载。
    fn builtins() -> Self {
        let mut table = Self {
            values: BTreeMap::new(),
        };
        table.add(
            Slot::Check,
            &["identity", "present", "risk", "risk.score"],
            Handler::Check,
        );
        table.add(
            Slot::Issue,
            &[
                "device",
                "captcha",
                "captcha.image",
                "captcha.slider",
                "captcha.rotate",
                "captcha.click",
                "sms",
                "code.sms",
                "email",
                "code.email",
                "passkey",
                "webauthn",
            ],
            Handler::Issue,
        );
        table.add(
            Slot::Verify,
            &[
                "captcha",
                "captcha.image",
                "captcha.slider",
                "captcha.rotate",
                "captcha.click",
                "sms",
                "code.sms",
                "email",
                "code.email",
                "totp",
                "password",
                "account.password",
                "email.password",
                "phone.password",
                "passkey",
                "webauthn",
                "device",
            ],
            Handler::Verify,
        );
        table.add(
            Slot::Effect,
            &[
                "audit",
                "auth.success",
                "auth.failed",
                "mfa.challenge",
                "mfa.passed",
                "mfa.failed",
                "passkey.success",
                "passkey.failed",
            ],
            Handler::Audit,
        );
        table.add(
            Slot::Effect,
            &[
                "sms",
                "email",
                "sms.send",
                "email.send",
                "send",
                "send.sms",
                "send.email",
            ],
            Handler::Send,
        );
        table
    }

    fn add(&mut self, slot: Slot, codes: &[&str], handler: Handler) {
        for code in codes {
            self.values.insert((slot, (*code).into()), handler);
        }
    }

    fn get(&self, kind: &Kind) -> Option<Handler> {
        let (slot, code) = match kind {
            Kind::Check(code) => (Slot::Check, code),
            Kind::Issue(code) => (Slot::Issue, code),
            Kind::Verify(code) => (Slot::Verify, code),
            Kind::Effect(code) => (Slot::Effect, code),
            Kind::Input => return None,
        };
        self.values.get(&(slot, code.clone())).copied()
    }
}

/// Pipeline 的内置节点能力。
///
/// Pipeline 负责图和状态，`Services` 负责把节点绑定到已有的 issuer、sender、
/// verifier、factor 和 store。调用方只提供依赖，不需要自己按节点分派认证逻辑。
pub struct Services<S, U, F, P, E, D, L = Noop> {
    pub secrets: S,
    pub users: U,
    pub factors: F,
    pub passkeys: P,
    pub events: E,
    pub devices: D,
    pub limits: L,
    pub risk: Option<RiskEngine>,
    pub notify: Notify,
    pub captcha_issue: CaptchaIssue,
    pub captcha_verify: CaptchaVerify,
    pub passkey_issue: Option<PasskeyIssue>,
    pub passkey_verify: Option<PasskeyVerify>,
    pub code_ttl: u64,
    pub code_digits: usize,
    table: Table,
}

impl<S, U, F, P, E, D> Services<S, U, F, P, E, D, Noop> {
    pub fn new(
        secrets: S,
        users: U,
        factors: F,
        passkeys: P,
        events: E,
        devices: D,
        notify: Notify,
    ) -> Self {
        Self {
            secrets,
            users,
            factors,
            passkeys,
            events,
            devices,
            limits: Noop,
            risk: None,
            notify,
            captcha_issue: CaptchaIssue::default(),
            captcha_verify: CaptchaVerify::default(),
            passkey_issue: None,
            passkey_verify: None,
            code_ttl: 300,
            code_digits: 6,
            table: Table::builtins(),
        }
    }
}

impl<S, U, F, P, E, D, L> Services<S, U, F, P, E, D, L> {
    /// 使用调用方提供的频控和锁定存储。
    pub fn limits<M: Limits>(self, limits: M) -> Services<S, U, F, P, E, D, M> {
        Services {
            secrets: self.secrets,
            users: self.users,
            factors: self.factors,
            passkeys: self.passkeys,
            events: self.events,
            devices: self.devices,
            limits,
            risk: self.risk,
            notify: self.notify,
            captcha_issue: self.captcha_issue,
            captcha_verify: self.captcha_verify,
            passkey_issue: self.passkey_issue,
            passkey_verify: self.passkey_verify,
            code_ttl: self.code_ttl,
            code_digits: self.code_digits,
            table: self.table,
        }
    }

    pub fn captcha_verify(mut self, captcha: CaptchaVerify) -> Self {
        self.captcha_verify = captcha;
        self
    }

    /// 注入可选风险引擎；未注入时，`check(risk)` 会返回不支持。
    pub fn risk(mut self, engine: RiskEngine) -> Self {
        self.risk = Some(engine);
        self
    }

    pub fn captcha_issue(mut self, issuer: CaptchaIssue) -> Self {
        self.captcha_issue = issuer;
        self
    }

    pub fn passkey_issue(mut self, passkey: PasskeyIssue) -> Self {
        self.passkey_issue = Some(passkey);
        self
    }

    pub fn passkey_verify(mut self, passkey: PasskeyVerify) -> Self {
        self.passkey_verify = Some(passkey);
        self
    }

    pub fn code(mut self, ttl: u64, digits: usize) -> Self {
        self.code_ttl = ttl.max(1);
        self.code_digits = digits.clamp(4, 12);
        self.captcha_verify = self.captcha_verify.ttl(self.code_ttl);
        self
    }

    pub(super) fn rule(&self, node: &Node) -> Option<Rule> {
        let args = node.args.as_object()?;
        let limit = args.get("limit").and_then(Value::as_u64)? as u32;
        let window = args.get("window").and_then(Value::as_u64)?;
        if limit == 0 || window == 0 {
            return None;
        }
        Some(
            Rule::new(limit, window)
                .lock(args.get("lock").and_then(Value::as_u64).unwrap_or_default()),
        )
    }

    pub(super) async fn allow(
        &self,
        node: &Node,
        context: &Context,
        data: &Value,
    ) -> Result<Option<(String, Rule)>>
    where
        L: Limits,
    {
        let Some(rule) = self.rule(node) else {
            return Ok(None);
        };
        let key = limit_key(node, context, data);
        if !self.limits.allow(&key, rule.limit, rule.window).await? {
            return Err(Error::AuthFailed("Rate limit exceeded".into()));
        }
        Ok(Some((key, rule)))
    }

    pub(super) async fn finish<T, Fut>(&self, guard: Option<(String, Rule)>, task: Fut) -> Result<T>
    where
        L: Limits,
        Fut: Future<Output = Result<T>>,
    {
        let result = task.await;
        let Some((key, rule)) = guard else {
            return result;
        };
        match result {
            Ok(value) => {
                self.limits.clear(&key).await?;
                Ok(value)
            }
            Err(error) => match self.limits.fail(&key, rule).await? {
                Decision::Allow => Err(error),
                Decision::Deny { retry_after } => Err(Error::AuthFailed(format!(
                    "Authentication is locked; retry after {retry_after} seconds"
                ))),
            },
        }
    }
}

impl<S, U, F, P, E, D, L> Runner for Services<S, U, F, P, E, D, L>
where
    S: Secrets,
    U: Users,
    F: Factors,
    P: Passkeys,
    E: Events,
    D: Devices,
    L: Limits,
{
    fn supports(&self, node: &Node) -> bool {
        match &node.kind {
            Kind::Input => true,
            Kind::Check(_) | Kind::Issue(_) | Kind::Verify(_) | Kind::Effect(_) => self
                .table
                .get(&node.kind)
                .is_some_and(|handler| match handler {
                    Handler::Check => !is_risk(&node.kind) || self.risk.is_some(),
                    Handler::Issue => !is_passkey(&node.kind) || self.passkey_issue.is_some(),
                    Handler::Verify => !is_passkey(&node.kind) || self.passkey_verify.is_some(),
                    _ => true,
                }),
        }
    }

    async fn run(&self, node: &Node, context: &Context) -> Result<Output> {
        let handler = self.table.get(&node.kind);
        match (&node.kind, handler) {
            (Kind::Input, _) => Err(Error::Internal("Input node requires an input event".into())),
            (Kind::Check(kind), Some(Handler::Check)) => self.check(node, context, kind).await,
            (Kind::Issue(kind), Some(Handler::Issue)) => self.issue(node, context, kind).await,
            (Kind::Verify(kind), Some(Handler::Verify)) => self.verify(node, context, kind).await,
            (Kind::Effect(kind), Some(Handler::Audit)) => self.audit(context, kind).await,
            (Kind::Effect(kind), Some(Handler::Send)) => self.send(node, context, kind).await,
            (kind, _) => Err(Error::Unsupported(format!(
                "Unsupported pipeline capability: {kind:?}"
            ))),
        }
    }
}

fn pass(data: Value) -> Output {
    Output::Pass {
        routes: Vec::new(),
        data,
        identity: None,
        at: chrono::Utc::now().timestamp(),
    }
}

fn identity_pass(user: User) -> Output {
    Output::Pass {
        routes: Vec::new(),
        data: json!({ "authenticated": true, "subject": user.id.to_string() }),
        identity: Some(user.identity()),
        at: chrono::Utc::now().timestamp(),
    }
}

fn channel(kind: &str) -> Result<&'static str> {
    if kind == "sms" || kind == "code.sms" {
        Ok("sms")
    } else if kind == "email" || kind == "code.email" {
        Ok("email")
    } else {
        Err(Error::Unsupported(format!(
            "Unsupported pipeline issuer: {kind}"
        )))
    }
}

fn is_passkey(kind: &Kind) -> bool {
    matches!(
        kind,
        Kind::Issue(code) | Kind::Verify(code) if matches!(code.as_str(), "passkey" | "webauthn")
    )
}

fn is_risk(kind: &Kind) -> bool {
    matches!(kind, Kind::Check(code) if matches!(code.as_str(), "risk" | "risk.score"))
}

fn captcha_type(kind: &str) -> Result<CaptchaType> {
    match kind.rsplit('.').next().unwrap_or(kind) {
        "image" => Ok(CaptchaType::Image),
        "slider" => Ok(CaptchaType::Slider),
        "rotate" => Ok(CaptchaType::Rotate),
        "click" => Ok(CaptchaType::Click),
        _ => Err(Error::Unsupported(format!(
            "Unsupported pipeline captcha: {kind}"
        ))),
    }
}

fn node_data<'a>(context: &'a Context, node: &Node) -> Result<&'a Value> {
    context
        .data
        .get(&node.id)
        .ok_or_else(|| Error::AuthFailed(format!("Missing input for node: {}", node.id)))
}

fn string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| Error::AuthFailed(format!("Missing field: {key}")))
}

fn event_string(context: &Context, key: &str) -> Option<String> {
    context
        .data
        .values()
        .find_map(|value| value.get(key).and_then(Value::as_str).map(str::to_string))
}

fn target(context: &Context, node: &Node, channel: &str) -> Result<String> {
    let key = if channel == "email" { "email" } else { "phone" };
    if let Some(value) = context.data.get(&node.id)
        && let Some(target) = value.get(key).and_then(Value::as_str)
    {
        return Ok(target.to_string());
    }
    Err(Error::AuthFailed(format!("Missing field: {key}")))
}

fn limit_key(node: &Node, context: &Context, data: &Value) -> String {
    let subject = ["account", "email", "phone", "subject", "id"]
        .iter()
        .find_map(|field| data.get(*field).and_then(Value::as_str))
        .or_else(|| {
            context
                .identity
                .as_ref()
                .map(|identity| identity.subject.as_str())
        })
        .unwrap_or("anonymous");
    let digest = Sha256::digest(subject.as_bytes());
    let subject = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("pipeline:{}:{subject}", node.id)
}
