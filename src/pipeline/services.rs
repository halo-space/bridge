use super::{Context, Kind, Node, Output, Runner};
use crate::audit::{AuditEvent, AuditEventType, AuditOutcome};
use crate::error::{IdpError, Result};
use crate::factor::basic::code::{Email as EmailCode, Sms as SmsCode, Totp as TotpCode};
use crate::factor::basic::password::{Account, Email as EmailPassword, Phone as PhonePassword};
use crate::factor::enterprise::DeviceProof;
use crate::store::{Devices, Events, Factors, Passkeys, Secrets, Users};
use crate::types::AuthUser;
use crate::validator::issuer::{CaptchaIssuer, CodeIssuer};
use crate::validator::sender::NotificationService;
use crate::validator::verifier::WebAuthn;
use crate::validator::verifier::captcha::{CaptchaType, CaptchaVerifier, CaptchaVerifyReq};
use serde_json::{Map, Value, json};

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
    pub notify: NotificationService,
    pub captcha_issuer: CaptchaIssuer,
    pub captcha: CaptchaVerifier,
    pub webauthn: Option<WebAuthn>,
    pub code_ttl: u64,
    pub code_digits: usize,
}

impl<S, U, F, P, E, D> Services<S, U, F, P, E, D> {
    pub fn new(
        secrets: S,
        users: U,
        factors: F,
        passkeys: P,
        events: E,
        devices: D,
        notify: NotificationService,
    ) -> Self {
        Self {
            secrets,
            users,
            factors,
            passkeys,
            events,
            devices,
            notify,
            captcha_issuer: CaptchaIssuer::default(),
            captcha: CaptchaVerifier::default(),
            webauthn: None,
            code_ttl: 300,
            code_digits: 6,
        }
    }

    pub fn captcha(mut self, captcha: CaptchaVerifier) -> Self {
        self.captcha = captcha;
        self
    }

    pub fn captcha_issuer(mut self, issuer: CaptchaIssuer) -> Self {
        self.captcha_issuer = issuer;
        self
    }

    pub fn webauthn(mut self, webauthn: WebAuthn) -> Self {
        self.webauthn = Some(webauthn);
        self
    }

    pub fn code(mut self, ttl: u64, digits: usize) -> Self {
        self.code_ttl = ttl.max(1);
        self.code_digits = digits.clamp(4, 12);
        self
    }
}

impl<S, U, F, P, E, D> Services<S, U, F, P, E, D>
where
    S: Secrets,
    U: Users,
    F: Factors,
    P: Passkeys,
    E: Events,
    D: Devices,
{
    async fn issue(&self, node: &Node, context: &Context, kind: &str) -> Result<Output> {
        if kind == "captcha" || kind.starts_with("captcha.") {
            let captcha_type = captcha_type(kind)?;
            let challenge = self
                .captcha_issuer
                .issue(&self.secrets, captcha_type)
                .await?;
            return Ok(pass(json!({ "challenge": challenge })));
        }
        if matches!(kind, "passkey" | "webauthn") {
            return self.issue_passkey(context).await;
        }

        let channel = channel(kind)?;
        let target = target(context, node, channel)?;
        let scene = if channel == "email" {
            "login_email"
        } else {
            "login_sms"
        };
        let key = CodeIssuer::key(scene, &target);
        CodeIssuer::issue(&self.secrets, &key, self.code_ttl, self.code_digits).await?;
        Ok(pass(json!({
            "channel": channel,
            "target": target,
            "key": key,
            "scene": scene,
            "ttl": self.code_ttl,
        })))
    }

    async fn send(&self, context: &Context, kind: &str) -> Result<Output> {
        let channel = if kind.contains("email") {
            "email"
        } else if kind.contains("sms") {
            "sms"
        } else {
            latest_issue(context)
                .and_then(|value| value.get("channel"))
                .and_then(Value::as_str)
                .ok_or_else(|| IdpError::Internal("Missing notification channel".into()))?
        };
        let issue = latest_issue(context)
            .ok_or_else(|| IdpError::Internal("Missing code issue result".into()))?;
        let target = issue
            .get("target")
            .and_then(Value::as_str)
            .ok_or_else(|| IdpError::Internal("Missing code target".into()))?;
        let key = issue
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| IdpError::Internal("Missing code key".into()))?;
        let code = self
            .secrets
            .get(key)
            .await?
            .ok_or(IdpError::VerificationCodeExpired)?;
        let scene = issue
            .get("scene")
            .and_then(Value::as_str)
            .unwrap_or("login");
        self.notify
            .send_verification_code(target, &code, scene, self.code_ttl)
            .await?;
        Ok(pass(json!({
            "sent": true,
            "channel": channel,
            "target": target,
        })))
    }

    async fn verify(&self, node: &Node, context: &Context, kind: &str) -> Result<Output> {
        let data = node_data(context, node)?;
        if kind == "captcha" || kind.starts_with("captcha.") {
            let req: CaptchaVerifyReq = serde_json::from_value(data.clone())
                .map_err(|e| IdpError::CaptchaFailed(e.to_string()))?;
            let token = self.captcha.verify(&self.secrets, &req).await?;
            return Ok(pass(json!({ "token": token })));
        }
        if kind == "sms" || kind == "code.sms" {
            let phone = string_or_context(&data, context, "phone")?;
            let code = string(&data, "code")?;
            let user =
                SmsCode::authenticate(&self.users, &self.secrets, context.tenant_id, &phone, &code)
                    .await?;
            return Ok(identity_pass(user));
        }
        if kind == "email" || kind == "code.email" {
            let email = string_or_context(&data, context, "email")?;
            let code = string(&data, "code")?;
            let user = EmailCode::authenticate(
                &self.users,
                &self.secrets,
                context.tenant_id,
                &email,
                &code,
            )
            .await?;
            return Ok(identity_pass(user));
        }
        if kind == "totp" {
            let account = string(&data, "account")?;
            let code = string(&data, "code")?;
            let timestamp = data
                .get("timestamp")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| chrono::Utc::now().timestamp() as u64);
            let user = TotpCode::authenticate(
                &self.users,
                &self.factors,
                context.tenant_id,
                &account,
                &code,
                timestamp,
            )
            .await?;
            return Ok(identity_pass(user));
        }
        if kind == "password"
            || kind == "account.password"
            || kind == "email.password"
            || kind == "phone.password"
        {
            let password = string(&data, "password")?;
            let user = if kind == "email.password" {
                EmailPassword::authenticate(
                    &self.users,
                    context.tenant_id,
                    &string(&data, "email")?,
                    &password,
                )
                .await?
            } else if kind == "phone.password" {
                PhonePassword::authenticate(
                    &self.users,
                    context.tenant_id,
                    &string(&data, "phone")?,
                    &password,
                )
                .await?
            } else {
                Account::authenticate(
                    &self.users,
                    context.tenant_id,
                    &string(&data, "account")?,
                    &password,
                )
                .await?
            };
            return Ok(identity_pass(user));
        }
        if kind == "passkey" || kind == "webauthn" {
            return self.verify_passkey(context, &data).await;
        }
        if kind == "device" {
            return self.verify_device(context, &data).await;
        }
        Err(IdpError::Internal(format!(
            "Unsupported pipeline verifier: {kind}"
        )))
    }

    async fn verify_device(&self, context: &Context, data: &Value) -> Result<Output> {
        let device_id = string(data, "device_id")?;
        let proof = DeviceProof {
            device_id: device_id.clone(),
            nonce: string(data, "nonce")?,
            at: data
                .get("at")
                .and_then(Value::as_i64)
                .ok_or_else(|| IdpError::AuthFailed("Missing field: at".into()))?,
            signature: string(data, "signature")?,
        };
        let now = data
            .get("now")
            .and_then(Value::as_i64)
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        let window = data.get("window").and_then(Value::as_i64).unwrap_or(120);
        let device = self
            .devices
            .find(context.tenant_id, &device_id)
            .await?
            .ok_or_else(|| IdpError::AuthFailed("Device not found".into()))?;
        device.verify(&proof, now, window)?;
        let mut used = device;
        used.last_used_at = Some(proof.at);
        if !self.devices.update(used).await? {
            return Err(IdpError::StoreError("Device update failed".into()));
        }
        Ok(pass(json!({ "verified": true, "device_id": device_id })))
    }

    async fn issue_passkey(&self, context: &Context) -> Result<Output> {
        let webauthn = self.webauthn.as_ref().ok_or_else(|| {
            IdpError::WebAuthnError("Pipeline WebAuthn service is missing".into())
        })?;
        if let Some(data) = context.data.values().rev().find(|value| {
            value.get("user_id").is_some()
                && value.get("name").is_some()
                && value.get("display_name").is_some()
        }) {
            let start = webauthn.issue(
                string(data, "user_id")?.as_str(),
                string(data, "name")?.as_str(),
                string(data, "display_name")?.as_str(),
            )?;
            return Ok(pass(json!({
                "mode": "register",
                "options": start.options,
                "state": start.state,
            })));
        }
        let subject = context
            .identity
            .as_ref()
            .ok_or(IdpError::UserNotFound)?
            .subject
            .clone();
        let passkeys = self
            .passkeys
            .list(&context.tenant_id.to_string(), &subject)
            .await?;
        let start = webauthn.request(&passkeys)?;
        Ok(pass(json!({
            "mode": "request",
            "options": start.options,
            "state": start.state,
        })))
    }

    async fn verify_passkey(&self, context: &Context, data: &Value) -> Result<Output> {
        let webauthn = self.webauthn.as_ref().ok_or_else(|| {
            IdpError::WebAuthnError("Pipeline WebAuthn service is missing".into())
        })?;
        let input = string(data, "input").or_else(|_| string(data, "credential"))?;
        let state = string(data, "state").or_else(|_| {
            find_string(context, "state")
                .ok_or_else(|| IdpError::AuthFailed("Missing field: state".into()))
        })?;
        let auth = webauthn.verify(&input, &state)?;
        let tenant = context.tenant_id.to_string();
        let stored = self
            .passkeys
            .find(&tenant, &auth.credential_id)
            .await?
            .ok_or_else(|| IdpError::WebAuthnError("Passkey is not registered".into()))?;
        if !stored.can_update(auth.counter) {
            return Err(IdpError::WebAuthnError(
                "Passkey counter did not advance".into(),
            ));
        }
        let mut updated = stored.clone();
        updated.sign_count = auth.counter;
        updated.last_used_at = Some(auth.at);
        updated.user_verified = auth.user_verified;
        updated.backup_eligible = auth.backup_eligible;
        updated.backup_state = auth.backup_state;
        if let Some(data) = auth.data {
            updated.data = Some(data);
        }
        if !self
            .passkeys
            .update(&tenant, &auth.credential_id, stored.sign_count, updated)
            .await?
        {
            return Err(IdpError::WebAuthnError(
                "Passkey counter update lost race".into(),
            ));
        }
        Ok(pass(json!({
            "verified": true,
            "credential_id": auth.credential_id,
            "counter": auth.counter,
            "user_verified": auth.user_verified,
        })))
    }

    async fn check(&self, node: &Node, context: &Context, kind: &str) -> Result<Output> {
        if kind == "identity" && context.identity.is_some() {
            return Ok(pass(Value::Null));
        }
        if kind == "present" {
            for field in &node.fields {
                if find_string(context, field).is_none() {
                    return Ok(Output::Fail {
                        reason: format!("Missing field: {field}"),
                        retry: false,
                    });
                }
            }
            return Ok(pass(Value::Null));
        }
        Err(IdpError::Internal(format!(
            "Unsupported pipeline check: {kind}"
        )))
    }

    async fn audit(&self, context: &Context, kind: &str) -> Result<Output> {
        let event_type = match kind {
            "audit" | "auth.success" | "auth_success" => AuditEventType::AuthSuccess,
            "auth.failed" | "auth_failed" => AuditEventType::AuthFailed,
            "mfa.challenge" | "mfa_challenged" => AuditEventType::MfaChallenged,
            "mfa.passed" | "mfa_passed" => AuditEventType::MfaPassed,
            "mfa.failed" | "mfa_failed" => AuditEventType::MfaFailed,
            "passkey.success" | "passkey_auth_success" => AuditEventType::PasskeyAuthSuccess,
            "passkey.failed" | "passkey_auth_failed" => AuditEventType::PasskeyAuthFailed,
            _ => {
                return Err(IdpError::Internal(format!(
                    "Unsupported pipeline audit: {kind}"
                )));
            }
        };
        let event = AuditEvent::new(
            context.tenant_id,
            event_type,
            find_string(context, "client_ip").unwrap_or_default(),
            AuditOutcome::Success,
        )
        .with_metadata(json!({ "pipeline": true }));
        self.events.record_event(&event).await?;
        Ok(pass(json!({ "recorded": true, "event_id": event.id })))
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
    async fn run(&self, node: &Node, context: &Context) -> Result<Output> {
        match &node.kind {
            Kind::Input => Err(IdpError::Internal(
                "Input node requires an input event".into(),
            )),
            Kind::Check(kind) => self.check(node, context, kind).await,
            Kind::Issue(kind) => self.issue(node, context, kind).await,
            Kind::Verify(kind) => self.verify(node, context, kind).await,
            Kind::Effect(kind) if kind == "audit" || kind.starts_with("audit.") => {
                self.audit(context, kind).await
            }
            Kind::Effect(kind)
                if kind.starts_with("send")
                    || kind.ends_with(".send")
                    || kind == "sms"
                    || kind == "email" =>
            {
                self.send(context, kind).await
            }
            Kind::Effect(kind) => Err(IdpError::Internal(format!(
                "Unsupported pipeline effect: {kind}"
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

fn identity_pass(user: AuthUser) -> Output {
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
        Err(IdpError::Internal(format!(
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
        _ => Err(IdpError::Internal(format!(
            "Unsupported pipeline captcha: {kind}"
        ))),
    }
}

fn node_data<'a>(context: &'a Context, node: &Node) -> Result<&'a Value> {
    context
        .data
        .get(&node.id)
        .or_else(|| {
            context.data.values().rev().find(|value| {
                value.get("code").is_some()
                    || value.get("input").is_some()
                    || value.get("credential").is_some()
                    || value.get("id").is_some()
            })
        })
        .ok_or_else(|| IdpError::AuthFailed(format!("Missing input for node: {}", node.id)))
}

fn string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| IdpError::AuthFailed(format!("Missing field: {key}")))
}

fn string_or_context(value: &Value, context: &Context, key: &str) -> Result<String> {
    string(value, key).or_else(|_| {
        find_string(context, key)
            .ok_or_else(|| IdpError::AuthFailed(format!("Missing field: {key}")))
    })
}

fn find_string(context: &Context, key: &str) -> Option<String> {
    context
        .data
        .values()
        .find_map(|value| value.get(key).and_then(Value::as_str).map(str::to_string))
}

fn target(context: &Context, node: &Node, channel: &str) -> Result<String> {
    let key = if channel == "email" { "email" } else { "phone" };
    if let Some(value) = context.data.get(&node.id) {
        if let Some(target) = value.get(key).and_then(Value::as_str) {
            return Ok(target.to_string());
        }
    }
    find_string(context, key).ok_or_else(|| IdpError::AuthFailed(format!("Missing field: {key}")))
}

fn latest_issue(context: &Context) -> Option<&Map<String, Value>> {
    context
        .evidence
        .iter()
        .rev()
        .find_map(|evidence| {
            let object = evidence.data.as_object()?;
            object.get("key")?.as_str()?;
            Some(object)
        })
        .or_else(|| {
            context.data.values().rev().find_map(|value| {
                let object = value.as_object()?;
                object.get("key")?.as_str()?;
                Some(object)
            })
        })
}
