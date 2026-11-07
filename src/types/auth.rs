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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Level {
    First,
    Second,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub identity: super::Identity,
    pub method: Method,
    pub level: Level,
    pub at: i64,
}

impl AuthResult {
    pub fn new(identity: super::Identity, method: Method, level: Level) -> Self {
        Self {
            identity,
            method,
            level,
            at: chrono::Utc::now().timestamp(),
        }
    }
}
