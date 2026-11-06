use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    Password,
    Code,
    Totp,
    Passkey,
    Social,
    Enterprise,
    Magic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Level {
    First,
    Second,
}

/// 身份源认证成功后对外返回的统一身份资料。
///
/// 本类型不代表本地用户，也不保存账号绑定关系。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub provider: String,
    pub subject: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub name: Option<String>,
}

impl Identity {
    pub fn new(provider: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            subject: subject.into(),
            email: None,
            phone: None,
            name: None,
        }
    }

    pub fn email(mut self, value: impl Into<String>) -> Self {
        self.email = Some(value.into());
        self
    }

    pub fn phone(mut self, value: impl Into<String>) -> Self {
        self.phone = Some(value.into());
        self
    }

    pub fn name(mut self, value: impl Into<String>) -> Self {
        self.name = Some(value.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub identity: Identity,
    pub method: Method,
    pub level: Level,
    pub at: i64,
}

impl AuthResult {
    pub fn new(identity: Identity, method: Method, level: Level) -> Self {
        Self {
            identity,
            method,
            level,
            at: chrono::Utc::now().timestamp(),
        }
    }
}
