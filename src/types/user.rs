use crate::types::Identity;
use serde::{Deserialize, Serialize};

/// 调用方提供的账号凭证记录。
///
/// bridge 不保存此记录；`Users` 只负责在认证时读取它，业务范围和持久化由调用方决定。
#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    #[serde(default, skip_serializing)]
    pub password_hash: Option<String>,
    #[serde(default)]
    pub password_algorithm: Option<u16>,
    pub is_active: bool,
}

impl User {
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
