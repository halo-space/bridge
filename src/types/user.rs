use crate::types::Identity;
use serde::{Deserialize, Serialize};

/// 认证通过后的标准用户载荷。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: i64,
    pub tenant_id: i64,
    pub username: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password_hash: Option<String>,
    #[serde(default)]
    pub password_algorithm: Option<u16>,
    pub is_active: bool,
}

impl AuthUser {
    pub fn identity(&self) -> Identity {
        let mut identity = Identity::new("local", self.id.to_string()).name(&self.username);
        if let Some(email) = &self.email {
            identity = identity.email(email);
        }
        if let Some(phone) = &self.phone {
            identity = identity.phone(phone);
        }
        identity
    }
}
