use serde::{Deserialize, Serialize};

/// 企业设备登录因子。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub subject: String,
    pub name: String,
    pub public_key: String,
    pub enabled: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}
