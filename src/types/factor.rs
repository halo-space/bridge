use serde::{Deserialize, Serialize};

/// 用户已绑定的 TOTP 信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpBinding {
    #[serde(skip_serializing)]
    pub secret: String,
    pub enabled: bool,
}
