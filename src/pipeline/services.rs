use super::{Context, Kind, Node, Output, Runner};
use crate::audit::{AuditEvent, AuditEventType, AuditOutcome};
use crate::error::{Error, Result};
use crate::factor::basic::code::{Email as EmailCode, Sms as SmsCode, Totp as TotpCode};
use crate::factor::basic::password::{Account, Email as EmailPassword, Phone as PhonePassword};
use crate::factor::enterprise::DeviceProof;
use crate::store::{Devices, Events, Factors, Passkeys, Secrets, Users};
use crate::types::User;
use crate::validator::issuer::{Captcha as CaptchaIssue, Code, Passkey as PasskeyIssue};
use crate::validator::sender::{Notify, NotifyChannel};
use crate::validator::verifier::Passkey as PasskeyVerify;
use crate::validator::verifier::captcha::{
    Captcha as CaptchaVerify, CaptchaType, CaptchaVerifyReq,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

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
        table.add(Slot::Check, &["identity", "present"], Handler::Check);
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
                "auth_success",
                "auth.failed",
                "auth_failed",
                "mfa.challenge",
                "mfa_challenged",
                "mfa.passed",
                "mfa_passed",
                "mfa.failed",
                "mfa_failed",
                "passkey.success",
                "passkey_auth_success",
                "passkey.failed",
                "passkey_auth_failed",
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
pub struct Services<S, U, F, P, E, D> {
    pub secrets: S,
    pub users: U,
    pub factors: F,
    pub passkeys: P,
    pub events: E,
    pub devices: D,
    pub notify: Notify,
    pub captcha_issue: CaptchaIssue,
    pub captcha_verify: CaptchaVerify,
    pub passkey_issue: Option<PasskeyIssue>,
    pub passkey_verify: Option<PasskeyVerify>,
    pub code_ttl: u64,
    pub code_digits: usize,
    table: Table,
}

impl<S, U, F, P, E, D> Services<S, U, F, P, E, D> {
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

    pub fn captcha_verify(mut self, captcha: CaptchaVerify) -> Self {
        self.captcha_verify = captcha;
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
        self
    }
}

impl<S, U, F, P, E, D> Runner for Services<S, U, F, P, E, D>
where
    S: Secrets,
    U: Users,
    F: Factors,
    P: Passkeys,
    E: Events,
    D: Devices,
{
    fn supports(&self, node: &Node) -> bool {
        match &node.kind {
            Kind::Input => true,
            Kind::Check(_) | Kind::Issue(_) | Kind::Verify(_) | Kind::Effect(_) => {
                self.table.get(&node.kind).is_some_and(|handler| {
                    !matches!(handler, Handler::Issue | Handler::Verify)
                        || (self.passkey_issue.is_some() && self.passkey_verify.is_some())
                        || !matches!(
                            node.kind,
                            Kind::Issue(ref code) | Kind::Verify(ref code)
                                if matches!(code.as_str(), "passkey" | "webauthn")
                        )
                })
            }
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
        data: json!({ "authenticated": true, "user_id": user.id }),
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

fn find_string(context: &Context, key: &str) -> Option<String> {
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
