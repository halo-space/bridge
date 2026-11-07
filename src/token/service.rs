use super::claims::Claims;
use crate::error::{IdpError, Result};
use crate::store::Secrets;
use crate::types::AuthUser;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};

pub struct TokenService {
    secret: String,
    rsa_private_pem: Option<String>,
    rsa_public_pem: Option<String>,
    issuer: String,
    access_token_ttl: i64,
    refresh_token_ttl: i64,
}

impl TokenService {
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
        }
    }

    /// 构造支持 RS256 非对称签名的 TokenService
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
        }
    }

    /// 为认证通过的用户签发标准 Access Token 与 Refresh Token (自动匹配 HS256 或 RS256)
    pub fn issue_tokens(
        &self,
        user: &AuthUser,
        audience: Option<String>,
    ) -> Result<(String, String)> {
        self.issue_tokens_with_claims(user, audience, None)
    }

    /// 签发携带自定义扩展 Claims 字段的 Tokens (支持工号、部门等动态 Claims)
    pub fn issue_tokens_with_claims(
        &self,
        user: &AuthUser,
        audience: Option<String>,
        custom_claims: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<(String, String)> {
        let now = Utc::now().timestamp();

        // 1. Access Token（携带身份载荷和自定义扩展字段）
        let access_claims = Claims {
            kind: "access".into(),
            sub: user.id.to_string(),
            iss: self.issuer.clone(),
            aud: audience.clone(),
            exp: now + self.access_token_ttl,
            iat: now,
            nbf: now,
            jti: uuid::Uuid::new_v4().to_string(),
            tenant_id: user.tenant_id,
            username: user.username.clone(),
            custom: custom_claims.unwrap_or_default(),
        };

        // 2. Refresh Token
        let refresh_claims = Claims {
            kind: "refresh".into(),
            sub: user.id.to_string(),
            iss: self.issuer.clone(),
            aud: audience,
            exp: now + self.refresh_token_ttl,
            iat: now,
            nbf: now,
            jti: uuid::Uuid::new_v4().to_string(),
            tenant_id: user.tenant_id,
            username: user.username.clone(),
            custom: serde_json::Map::new(),
        };

        let (access_token, refresh_token) = if let Some(ref priv_pem) = self.rsa_private_pem {
            let key = EncodingKey::from_rsa_pem(priv_pem.as_bytes())
                .map_err(|e| IdpError::TokenError(format!("Invalid RSA private key: {e}")))?;
            let header = Header::new(Algorithm::RS256);

            let at = encode(&header, &access_claims, &key)
                .map_err(|e| IdpError::TokenError(e.to_string()))?;
            let rt = encode(&header, &refresh_claims, &key)
                .map_err(|e| IdpError::TokenError(e.to_string()))?;
            (at, rt)
        } else {
            let key = EncodingKey::from_secret(self.secret.as_bytes());
            let header = Header::default();

            let at = encode(&header, &access_claims, &key)
                .map_err(|e| IdpError::TokenError(e.to_string()))?;
            let rt = encode(&header, &refresh_claims, &key)
                .map_err(|e| IdpError::TokenError(e.to_string()))?;
            (at, rt)
        };

        Ok((access_token, refresh_token))
    }

    /// 校验并解析 Access Token (自适应 HS256 或 RS256)
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let claims = self.verify(token)?;
        if claims.kind != "access" {
            return Err(IdpError::TokenError("Expected access token".into()));
        }
        Ok(claims)
    }

    pub fn verify_refresh(&self, token: &str) -> Result<Claims> {
        let claims = self.verify(token)?;
        if claims.kind != "refresh" {
            return Err(IdpError::TokenError("Expected refresh token".into()));
        }
        Ok(claims)
    }

    pub fn issue_id_token(
        &self,
        user: &AuthUser,
        audience: String,
        nonce: Option<String>,
    ) -> Result<String> {
        let now = Utc::now().timestamp();
        let mut custom = serde_json::Map::new();
        if let Some(nonce) = nonce {
            custom.insert("nonce".into(), serde_json::Value::String(nonce));
        }
        let claims = Claims {
            kind: "id".into(),
            sub: user.id.to_string(),
            iss: self.issuer.clone(),
            aud: Some(audience),
            exp: now + self.access_token_ttl,
            iat: now,
            nbf: now,
            jti: uuid::Uuid::new_v4().to_string(),
            tenant_id: user.tenant_id,
            username: user.username.clone(),
            custom,
        };
        if let Some(ref private) = self.rsa_private_pem {
            let key = EncodingKey::from_rsa_pem(private.as_bytes())
                .map_err(|e| IdpError::TokenError(format!("Invalid RSA private key: {e}")))?;
            encode(&Header::new(Algorithm::RS256), &claims, &key)
                .map_err(|e| IdpError::TokenError(e.to_string()))
        } else {
            encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(self.secret.as_bytes()),
            )
            .map_err(|e| IdpError::TokenError(e.to_string()))
        }
    }

    pub fn verify_id(&self, token: &str, audience: &str, nonce: Option<&str>) -> Result<Claims> {
        let claims = self.verify(token)?;
        if claims.kind != "id" || claims.aud.as_deref() != Some(audience) {
            return Err(IdpError::TokenError("Invalid ID token".into()));
        }
        if let Some(expected) = nonce {
            let actual = claims.custom.get("nonce").and_then(|v| v.as_str());
            if actual != Some(expected) {
                return Err(IdpError::TokenError("Invalid ID token nonce".into()));
            }
        }
        Ok(claims)
    }

    pub async fn verify_live<K: Secrets>(&self, kv: &K, token: &str) -> Result<Claims> {
        let claims = self.verify_token(token)?;
        if kv.get(&format!("token:revoked:{token}")).await?.is_some() {
            return Err(IdpError::TokenError("Token revoked".into()));
        }
        Ok(claims)
    }

    pub fn renew(&self, token: &str) -> Result<(String, String)> {
        let claims = self.verify_refresh(token)?;
        let user = AuthUser {
            id: claims
                .sub
                .parse()
                .map_err(|_| IdpError::TokenError("Invalid subject".into()))?,
            tenant_id: claims.tenant_id,
            username: claims.username,
            email: None,
            phone: None,
            password_hash: None,
            password_algorithm: None,
            is_active: true,
        };
        self.issue_tokens(&user, claims.aud)
    }

    fn verify(&self, token: &str) -> Result<Claims> {
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
                .map_err(|e| IdpError::TokenError(format!("Invalid RSA public key: {e}")))?;
            decode::<Claims>(token, &key, &validation)
        } else {
            let key = DecodingKey::from_secret(self.secret.as_bytes());
            decode::<Claims>(token, &key, &validation)
        }
        .map_err(|e| IdpError::TokenError(e.to_string()))?;

        Ok(token_data.claims)
    }

    /// 校验并解析 Access Token 并精确验证 Audience
    pub fn verify_token_with_audience(&self, token: &str, audience: &str) -> Result<Claims> {
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
                .map_err(|e| IdpError::TokenError(format!("Invalid RSA public key: {e}")))?;
            decode::<Claims>(token, &key, &validation)
        } else {
            let key = DecodingKey::from_secret(self.secret.as_bytes());
            decode::<Claims>(token, &key, &validation)
        }
        .map_err(|e| IdpError::TokenError(e.to_string()))?;

        if token_data.claims.kind != "access" {
            return Err(IdpError::TokenError("Expected access token".into()));
        }
        Ok(token_data.claims)
    }
}
