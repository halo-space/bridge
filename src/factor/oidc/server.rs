use serde::{Deserialize, Serialize};

/// OIDC 标准元数据发现文档 (RFC 8414 / OpenID Connect Discovery 1.0)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub revocation_endpoint: String,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

impl OidcDiscovery {
    pub fn new(issuer: impl Into<String>) -> Self {
        let iss = issuer.into();
        Self {
            authorization_endpoint: format!("{iss}/oauth/authorize"),
            token_endpoint: format!("{iss}/oauth/token"),
            jwks_uri: format!("{iss}/oauth/jwks.json"),
            revocation_endpoint: format!("{iss}/oauth/revoke"),
            issuer: iss,
            response_types_supported: vec!["code".into()],
            subject_types_supported: vec!["public".into()],
            id_token_signing_alg_values_supported: vec!["HS256".into(), "RS256".into()],
            scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
            token_endpoint_auth_methods_supported: vec!["client_secret_post".into(), "none".into()],
            claims_supported: vec![
                "sub".into(),
                "iss".into(),
                "aud".into(),
                "exp".into(),
                "iat".into(),
                "username".into(),
                "name".into(),
                "email".into(),
                "nonce".into(),
            ],
            code_challenge_methods_supported: vec!["S256".into(), "plain".into()],
        }
    }
}

/// OIDC 标准令牌换发响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// OIDC 标准 UserInfo 响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

/// RFC 7009 Token 吊销请求参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// RFC 7662 Token 内省请求参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type_hint: Option<String>,
}

/// RFC 7662 Token 内省响应结构 (供 API 网关验证 Token)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
}
