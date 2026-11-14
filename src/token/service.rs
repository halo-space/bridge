use super::claims::Claims;
use crate::error::{Error, Result};
use crate::store::Secrets;
use crate::types::{Identity, User};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

pub struct Token {
    secret: String,
    rsa_private_pem: Option<String>,
    rsa_public_pem: Option<String>,
    issuer: String,
    access_token_ttl: i64,
    refresh_token_ttl: i64,
    key_id: Option<String>,
}

impl Token {
    pub fn new(
        secret: impl Into<String>,
        issuer: impl Into<String>,
        access_token_ttl: i64,
        refresh_token_ttl: i64,
    ) -> Self {
        Self {
            secret: secret.into(),
            rsa_private_pem: None,
            rsa_public_pem: None,
            issuer: issuer.into(),
            access_token_ttl,
            refresh_token_ttl,
            key_id: None,
        }
    }

    /// 构造支持 RS256 非对称签名的 Token
    pub fn with_rsa_pem(
        issuer: impl Into<String>,
        access_token_ttl: i64,
        refresh_token_ttl: i64,
        private_pem: impl Into<String>,
        public_pem: impl Into<String>,
    ) -> Self {
        Self {
            secret: String::new(),
            rsa_private_pem: Some(private_pem.into()),
            rsa_public_pem: Some(public_pem.into()),
            issuer: issuer.into(),
            access_token_ttl,
            refresh_token_ttl,
            key_id: None,
        }
    }

    /// 为 RS256 Token 设置与 JWKS 对应的密钥编号。
    pub fn kid(mut self, value: impl Into<String>) -> Self {
        self.key_id = Some(value.into());
        self
    }

    pub fn access_ttl(&self) -> i64 {
        self.access_token_ttl
    }

    pub fn refresh_ttl(&self) -> i64 {
        self.refresh_token_ttl
    }

    /// 为认证通过的用户签发标准 Access Token 与 Refresh Token (自动匹配 HS256 或 RS256)
    pub fn issue_tokens(&self, user: &User, audience: Option<String>) -> Result<(String, String)> {
        self.issue_tokens_with_claims(user, audience, None)
    }

    /// 签发携带自定义扩展 Claims 字段的 Tokens (支持工号、部门等动态 Claims)
    pub fn issue_tokens_with_claims(
        &self,
        user: &User,
        audience: Option<String>,
        custom_claims: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<(String, String)> {
        self.issue_identity_with_claims(&user.identity(), audience, None, custom_claims)
    }

    /// 为调用方提供的统一身份签发 Access Token 和 Refresh Token。
    pub fn issue_identity(
        &self,
        identity: &Identity,
        audience: Option<String>,
        scope: Option<String>,
    ) -> Result<(String, String)> {
        self.issue_identity_with_claims(identity, audience, scope, None)
    }

    /// 只签发 Access Token，不创建 Refresh Token。
    pub fn issue_access(
        &self,
        identity: &Identity,
        audience: Option<String>,
        scope: Option<String>,
    ) -> Result<String> {
        self.issue_identity(identity, audience, scope)
            .map(|tokens| tokens.0)
    }

    /// 为统一身份签发带扩展 Claims 的 Access Token 和 Refresh Token。
    pub fn issue_identity_with_claims(
        &self,
        identity: &Identity,
        audience: Option<String>,
        scope: Option<String>,
        custom_claims: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<(String, String)> {
        self.issue_subject(
            &identity.subject,
            identity.name.as_deref().or(identity.email.as_deref()),
            audience,
            scope,
            custom_claims,
        )
    }

    fn issue_subject(
        &self,
        subject: &str,
        username: Option<&str>,
        audience: Option<String>,
        scope: Option<String>,
        custom_claims: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<(String, String)> {
        self.validate_config()?;
        if subject.trim().is_empty() {
            return Err(Error::TokenError("Token subject cannot be empty".into()));
        }
        let now = Utc::now().timestamp();
        let username = username.unwrap_or(subject).to_string();

        // 1. Access Token（携带身份载荷和自定义扩展字段）
        let access_claims = Claims {
            kind: "access".into(),
            sub: subject.to_string(),
            iss: self.issuer.clone(),
            aud: audience.clone(),
            exp: now + self.access_token_ttl,
            iat: now,
            nbf: now,
            jti: uuid::Uuid::new_v4().to_string(),
            username: username.clone(),
            scope: scope.clone(),
            custom: custom_claims.unwrap_or_default(),
        };

        // 2. Refresh Token
        let refresh_claims = Claims {
            kind: "refresh".into(),
            sub: subject.to_string(),
            iss: self.issuer.clone(),
            aud: audience,
            exp: now + self.refresh_token_ttl,
            iat: now,
            nbf: now,
            jti: uuid::Uuid::new_v4().to_string(),
            username,
            scope,
            custom: serde_json::Map::new(),
        };

        let (access_token, refresh_token) = if let Some(ref priv_pem) = self.rsa_private_pem {
            let key = EncodingKey::from_rsa_pem(priv_pem.as_bytes())
                .map_err(|e| Error::TokenError(format!("Invalid RSA private key: {e}")))?;
            let mut header = Header::new(Algorithm::RS256);
            header.kid = self.key_id.clone();

            let at = encode(&header, &access_claims, &key)
                .map_err(|e| Error::TokenError(e.to_string()))?;
            let rt = encode(&header, &refresh_claims, &key)
                .map_err(|e| Error::TokenError(e.to_string()))?;
            (at, rt)
        } else {
            let key = EncodingKey::from_secret(self.secret.as_bytes());
            let header = Header::default();

            let at = encode(&header, &access_claims, &key)
                .map_err(|e| Error::TokenError(e.to_string()))?;
            let rt = encode(&header, &refresh_claims, &key)
                .map_err(|e| Error::TokenError(e.to_string()))?;
            (at, rt)
        };

        Ok((access_token, refresh_token))
    }

    /// 校验并解析 Access Token (自适应 HS256 或 RS256)
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let claims = self.verify(token)?;
        if claims.kind != "access" {
            return Err(Error::TokenError("Expected access token".into()));
        }
        Ok(claims)
    }

    pub fn verify_refresh(&self, token: &str) -> Result<Claims> {
        let claims = self.verify(token)?;
        if claims.kind != "refresh" {
            return Err(Error::TokenError("Expected refresh token".into()));
        }
        Ok(claims)
    }

    pub fn issue_id_token(
        &self,
        user: &User,
        audience: String,
        nonce: Option<String>,
    ) -> Result<String> {
        self.issue_id_identity(&user.identity(), audience, nonce, None)
    }

    /// 为调用方提供的统一身份签发 ID Token。
    pub fn issue_id_identity(
        &self,
        identity: &Identity,
        audience: String,
        nonce: Option<String>,
        scope: Option<String>,
    ) -> Result<String> {
        self.issue_id_subject(
            &identity.subject,
            identity.name.as_deref().or(identity.email.as_deref()),
            audience,
            nonce,
            scope,
        )
    }

    fn issue_id_subject(
        &self,
        subject: &str,
        username: Option<&str>,
        audience: String,
        nonce: Option<String>,
        scope: Option<String>,
    ) -> Result<String> {
        self.validate_config()?;
        if subject.trim().is_empty() {
            return Err(Error::TokenError("Token subject cannot be empty".into()));
        }
        let now = Utc::now().timestamp();
        let mut custom = serde_json::Map::new();
        if let Some(nonce) = nonce {
            custom.insert("nonce".into(), serde_json::Value::String(nonce));
        }
        let claims = Claims {
            kind: "id".into(),
            sub: subject.to_string(),
            iss: self.issuer.clone(),
            aud: Some(audience),
            exp: now + self.access_token_ttl,
            iat: now,
            nbf: now,
            jti: uuid::Uuid::new_v4().to_string(),
            username: username.unwrap_or(subject).to_string(),
            scope,
            custom,
        };
        if let Some(ref private) = self.rsa_private_pem {
            let key = EncodingKey::from_rsa_pem(private.as_bytes())
                .map_err(|e| Error::TokenError(format!("Invalid RSA private key: {e}")))?;
            let mut header = Header::new(Algorithm::RS256);
            header.kid = self.key_id.clone();
            encode(&header, &claims, &key).map_err(|e| Error::TokenError(e.to_string()))
        } else {
            encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(self.secret.as_bytes()),
            )
            .map_err(|e| Error::TokenError(e.to_string()))
        }
    }

    pub fn verify_id(&self, token: &str, audience: &str, nonce: Option<&str>) -> Result<Claims> {
        let claims = self.verify(token)?;
        if claims.kind != "id" || claims.aud.as_deref() != Some(audience) {
            return Err(Error::TokenError("Invalid ID token".into()));
        }
        if let Some(expected) = nonce {
            let actual = claims.custom.get("nonce").and_then(|v| v.as_str());
            if actual != Some(expected) {
                return Err(Error::TokenError("Invalid ID token nonce".into()));
            }
        }
        Ok(claims)
    }

    /// 根据已经验证的 Claims 重新签发 ID Token。
    pub fn issue_id_claims(&self, claims: &Claims, audience: String) -> Result<String> {
        let nonce = claims
            .custom
            .get("nonce")
            .and_then(|value| value.as_str())
            .map(str::to_string);
        self.issue_id_subject(
            &claims.sub,
            Some(&claims.username),
            audience,
            nonce,
            claims.scope.clone(),
        )
    }

    pub async fn verify_live<K: Secrets>(&self, kv: &K, token: &str) -> Result<Claims> {
        let claims = self.verify_token(token)?;
        if kv.get(&crate::token::revoke_key(token)).await?.is_some() {
            return Err(Error::TokenError("Token revoked".into()));
        }
        Ok(claims)
    }

    pub fn renew(&self, token: &str) -> Result<(String, String)> {
        let claims = self.verify_refresh(token)?;
        self.renew_claims(&claims)
    }

    /// 根据已经验证的 Refresh Token Claims 重新签发 Token。
    pub fn renew_claims(&self, claims: &Claims) -> Result<(String, String)> {
        if claims.kind != "refresh" {
            return Err(Error::TokenError("Expected refresh claims".into()));
        }
        self.issue_subject(
            &claims.sub,
            Some(&claims.username),
            claims.aud.clone(),
            claims.scope.clone(),
            None,
        )
    }

    fn verify(&self, token: &str) -> Result<Claims> {
        self.validate_config()?;
        let alg = if self.rsa_public_pem.is_some() {
            Algorithm::RS256
        } else {
            Algorithm::HS256
        };

        let mut validation = Validation::new(alg);
        validation.set_issuer(&[&self.issuer]);
        validation.validate_exp = true;
        validation.validate_aud = false;

        let token_data = if let Some(ref pub_pem) = self.rsa_public_pem {
            let key = DecodingKey::from_rsa_pem(pub_pem.as_bytes())
                .map_err(|e| Error::TokenError(format!("Invalid RSA public key: {e}")))?;
            decode::<Claims>(token, &key, &validation)
        } else {
            let key = DecodingKey::from_secret(self.secret.as_bytes());
            decode::<Claims>(token, &key, &validation)
        }
        .map_err(|e| Error::TokenError(e.to_string()))?;

        Ok(token_data.claims)
    }

    /// 校验并解析 Access Token 并精确验证 Audience
    pub fn verify_audience(&self, token: &str, audience: &str) -> Result<Claims> {
        self.validate_config()?;
        let alg = if self.rsa_public_pem.is_some() {
            Algorithm::RS256
        } else {
            Algorithm::HS256
        };

        let mut validation = Validation::new(alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[audience]);
        validation.validate_exp = true;

        let token_data = if let Some(ref pub_pem) = self.rsa_public_pem {
            let key = DecodingKey::from_rsa_pem(pub_pem.as_bytes())
                .map_err(|e| Error::TokenError(format!("Invalid RSA public key: {e}")))?;
            decode::<Claims>(token, &key, &validation)
        } else {
            let key = DecodingKey::from_secret(self.secret.as_bytes());
            decode::<Claims>(token, &key, &validation)
        }
        .map_err(|e| Error::TokenError(e.to_string()))?;

        if token_data.claims.kind != "access" {
            return Err(Error::TokenError("Expected access token".into()));
        }
        Ok(token_data.claims)
    }

    fn validate_config(&self) -> Result<()> {
        if self.issuer.trim().is_empty() {
            return Err(Error::TokenError("Token issuer cannot be empty".into()));
        }
        if self.access_token_ttl <= 0 || self.refresh_token_ttl <= 0 {
            return Err(Error::TokenError("Token TTL must be positive".into()));
        }
        match (&self.rsa_private_pem, &self.rsa_public_pem) {
            (Some(_), Some(_)) => Ok(()),
            (Some(_), None) | (None, Some(_)) => Err(Error::TokenError(
                "RSA private and public keys must be provided together".into(),
            )),
            (None, None) if self.secret.trim().len() < 32 => Err(Error::TokenError(
                "HS256 secret must contain at least 32 characters".into(),
            )),
            (None, None) => Ok(()),
        }
    }
}
