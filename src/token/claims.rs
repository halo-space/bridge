use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub kind: String,
    pub sub: String,
    pub iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub jti: String,
    pub username: String,
    /// 自定义扩展声明 (对齐 Authing 3.18 IdToken 扩展字段)
    #[serde(default, flatten)]
    pub custom: serde_json::Map<String, serde_json::Value>,
}
