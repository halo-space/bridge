use crate::types::Identity;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// 审计事件类型 (对齐 SOC 2 / 等保 2.0 三级标准)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    /// 身份认证成功
    AuthSuccess,
    /// 身份认证失败
    AuthFailed,
    /// 登出下线
    AuthLogout,
    /// 触发多因素认证核验 (Step-up MFA)
    MfaChallenged,
    /// 多因素认证成功
    MfaPassed,
    /// 多因素认证失败
    MfaFailed,
    /// Passkey 凭据注册
    PasskeyRegistered,
    /// Passkey 生物认证成功
    PasskeyAuthSuccess,
    /// Passkey 生物认证失败
    PasskeyAuthFailed,
    /// 账号安全锁定 (防暴力破解触发)
    AccountLocked,
    /// 账号解锁
    AccountUnlocked,
    /// 风险风控拦截 (高风险阻断)
    RiskBlocked,
    /// 密码变更或重置
    PasswordChanged,
    /// 邮件魔术链接签发
    MagicLinkIssued,
    /// 邮件魔术链接成功消费
    MagicLinkConsumed,
    /// 组织架构与人员同步
    DirectorySyncCompleted,
}

/// 审计操作最终结果
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

/// 标准安全审计事件记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// 事件唯一流水号
    pub id: String,
    /// 请求链路追踪 ID
    #[serde(default)]
    pub trace_id: Option<String>,
    /// 外部请求 ID
    #[serde(default)]
    pub request_id: Option<String>,
    /// 事件类型
    pub event_type: AuditEventType,
    /// 关联的外部身份主体（若已知）。
    pub identity: Option<Identity>,
    /// 来源客户端 IP
    pub client_ip: String,
    /// 来源客户端 User-Agent
    pub user_agent: Option<String>,
    /// 判定结果
    pub outcome: AuditOutcome,
    /// 失败或拦截原因说明
    pub reason: Option<String>,
    /// 扩展上下文字段 (JSON)
    pub metadata: serde_json::Value,
    /// 发生时间戳 (UNIX 秒)
    pub timestamp: i64,
}

impl AuditEvent {
    /// 构造新的安全审计事件
    pub fn new(
        event_type: AuditEventType,
        client_ip: impl Into<String>,
        outcome: AuditOutcome,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            trace_id: None,
            request_id: None,
            event_type,
            identity: None,
            client_ip: client_ip.into(),
            user_agent: None,
            outcome,
            reason: None,
            metadata: serde_json::Value::Null,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    pub fn with_trace(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    pub fn with_request(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn with_metadata(mut self, meta: serde_json::Value) -> Self {
        self.metadata = clean(meta);
        self
    }
}

fn clean(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(mut object) => {
            object.retain(|key, _| !sensitive(key));
            for value in object.values_mut() {
                let current = std::mem::replace(value, serde_json::Value::Null);
                *value = clean(current);
            }
            serde_json::Value::Object(object)
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(clean).collect())
        }
        value => value,
    }
}

fn sensitive(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "password"
            | "passwd"
            | "passcode"
            | "code"
            | "totp"
            | "token"
            | "access_token"
            | "refresh_token"
            | "secret"
            | "state"
            | "nonce"
            | "answer"
            | "credential"
            | "signature"
            | "proof"
            | "client_secret"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_builder() {
        let event = AuditEvent::new(
            AuditEventType::AuthSuccess,
            "127.0.0.1",
            AuditOutcome::Success,
        )
        .with_identity(Identity::new("local", "admin-1").name("admin"))
        .with_user_agent("Mozilla/5.0")
        .with_trace("trace-1")
        .with_request("request-1")
        .with_metadata(serde_json::json!({
            "auth_method": "webauthn",
            "password": "must-not-be-stored",
            "nested": { "access_token": "also-hidden", "risk": "new_device" }
        }));

        assert_eq!(event.event_type, AuditEventType::AuthSuccess);
        assert_eq!(event.outcome, AuditOutcome::Success);
        assert_eq!(
            event
                .identity
                .as_ref()
                .and_then(|value| value.name.as_deref()),
            Some("admin")
        );
        assert_eq!(event.client_ip, "127.0.0.1");
        assert_eq!(event.trace_id.as_deref(), Some("trace-1"));
        assert_eq!(event.request_id.as_deref(), Some("request-1"));
        assert!(event.timestamp > 0);
        assert_eq!(event.metadata["auth_method"], "webauthn");
        assert!(event.metadata.get("password").is_none());
        assert!(event.metadata["nested"].get("access_token").is_none());
    }
}
