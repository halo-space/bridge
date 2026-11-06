use super::pkce::Pkce;
use crate::error::{IdpError, Result};
use crate::store::{AuthCode, ClientStore, KvStore, OAuthClient};
use crate::token::TokenService;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

pub struct OidcFlow;

impl OidcFlow {
    /// 校验 PKCE code_verifier 与 code_challenge (RFC 7636)
    pub fn verify_pkce(verifier: &str, challenge: &str, method: Option<&str>) -> Result<()> {
        Pkce::check(verifier, challenge, method)
    }

    /// 校验授权请求参数及客户端合法性
    pub async fn validate_authorize_request<C: ClientStore>(
        client_store: &C,
        req: &AuthorizeRequest,
    ) -> Result<OAuthClient> {
        if req.response_type != "code" {
            return Err(IdpError::AuthFailed(format!(
                "Unsupported response_type: {}",
                req.response_type
            )));
        }

        let client = client_store
            .find_client(&req.client_id)
            .await?
            .ok_or_else(|| IdpError::InvalidClient(req.client_id.clone()))?;

        if !client.response_types.iter().any(|kind| kind == "code") {
            return Err(IdpError::InvalidClient(
                "Authorization code response is disabled".into(),
            ));
        }

        if !client
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
        {
            return Err(IdpError::InvalidClient(
                "Authorization code grant is disabled".into(),
            ));
        }

        // 验证重定向 URI
        let matched = client
            .redirect_uris
            .iter()
            .any(|allowed| allowed == &req.redirect_uri);

        if !matched {
            return Err(IdpError::InvalidRedirectUri(format!(
                "Redirect URI '{}' is not registered for client '{}'",
                req.redirect_uri, req.client_id
            )));
        }

        let requested_scope = req.scope.as_deref().unwrap_or("openid");
        let allowed_scopes: std::collections::HashSet<&str> =
            client.scope.split_whitespace().collect();
        if requested_scope
            .split_whitespace()
            .any(|scope| !allowed_scopes.contains(scope))
        {
            return Err(IdpError::AuthFailed(
                "Requested scope is not allowed".into(),
            ));
        }

        if client.is_public && req.code_challenge.is_none() {
            return Err(IdpError::InvalidPkce);
        }

        if req.code_challenge.is_none() && req.code_challenge_method.is_some() {
            return Err(IdpError::InvalidPkce);
        }

        if let Some(method) = req.code_challenge_method.as_deref() {
            if !matches!(method, "S256" | "plain") {
                return Err(IdpError::InvalidPkce);
            }
        }

        Ok(client)
    }

    /// 生成授权码并存入缓存
    pub async fn issue_code<K: KvStore>(
        kv: &K,
        client_id: &str,
        user_id: i64,
        tenant_id: i64,
        redirect_uri: &str,
        scope: &str,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
        ttl: u64,
    ) -> Result<String> {
        Self::issue_code_with_nonce(
            kv,
            client_id,
            user_id,
            tenant_id,
            redirect_uri,
            scope,
            code_challenge,
            code_challenge_method,
            None,
            ttl,
        )
        .await
    }

    /// 生成带 OIDC nonce 的授权码。
    pub async fn issue_code_with_nonce<K: KvStore>(
        kv: &K,
        client_id: &str,
        user_id: i64,
        tenant_id: i64,
        redirect_uri: &str,
        scope: &str,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
        nonce: Option<String>,
        ttl: u64,
    ) -> Result<String> {
        let code = format!("code_{}", uuid::Uuid::new_v4().simple());
        let expires_at = chrono::Utc::now().timestamp() + (ttl as i64);

        let auth_code = AuthCode {
            code: code.clone(),
            client_id: client_id.to_string(),
            user_id,
            tenant_id,
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_string(),
            code_challenge,
            code_challenge_method,
            nonce,
            expires_at,
        };

        let val =
            serde_json::to_string(&auth_code).map_err(|e| IdpError::Internal(e.to_string()))?;
        kv.set(&format!("code:{}", code), &val, ttl).await?;
        Ok(code)
    }

    /// 授权码换 Token 校验（单次使用消费 + PKCE 校验 + Client 密钥校验）
    pub async fn exchange_code<CS: ClientStore, K: KvStore>(
        client_store: &CS,
        kv: &K,
        req: &TokenRequest,
    ) -> Result<AuthCode> {
        let code_str = req.code.as_deref().ok_or(IdpError::InvalidCode)?;

        if req.grant_type != "authorization_code" {
            return Err(IdpError::TokenError(
                "Invalid grant_type, expected authorization_code".into(),
            ));
        }

        let key = format!("code:{code_str}");
        // 先读取并完成所有校验，最后再消费，避免错误请求提前销毁授权码。
        let val = kv.get(&key).await?.ok_or(IdpError::InvalidCode)?;

        let auth_code: AuthCode =
            serde_json::from_str(&val).map_err(|e| IdpError::Internal(e.to_string()))?;

        // 2. 检查客户端匹配
        if auth_code.client_id != req.client_id {
            return Err(IdpError::InvalidClient("Client mismatch".to_string()));
        }

        // 3. 检查重定向地址一致性
        if req.redirect_uri.as_deref() != Some(auth_code.redirect_uri.as_str()) {
            return Err(IdpError::InvalidRedirectUri(
                "Redirect URI mismatch".to_string(),
            ));
        }

        // 4. 验证客户端凭证 (机密客户端需验证 secret，公共客户端需走 PKCE)
        let client = client_store
            .find_client(&req.client_id)
            .await?
            .ok_or_else(|| IdpError::InvalidClient(req.client_id.clone()))?;

        if !client.is_public {
            match (client.client_secret, &req.client_secret) {
                (Some(expected), Some(actual)) if expected == *actual => {}
                _ => return Err(IdpError::InvalidClient("Client secret invalid".to_string())),
            }
        }

        // 5. PKCE 校验
        if let Some(challenge) = &auth_code.code_challenge {
            let verifier = req.code_verifier.as_deref().ok_or(IdpError::InvalidPkce)?;
            Self::verify_pkce(
                verifier,
                challenge,
                auth_code.code_challenge_method.as_deref(),
            )?;
        } else if client.is_public {
            return Err(IdpError::InvalidPkce);
        }

        if !kv.take_if(&key, &val).await? {
            return Err(IdpError::InvalidCode);
        }

        Ok(auth_code)
    }

    /// 校验并处理 Refresh Token 换发 (grant_type=refresh_token)
    pub async fn exchange_refresh_token<C: ClientStore, K: KvStore>(
        client_store: &C,
        token_service: &TokenService,
        kv: &K,
        req: &TokenRequest,
    ) -> Result<(String, String)> {
        if req.grant_type != "refresh_token" {
            return Err(IdpError::TokenError(
                "Invalid grant_type, expected refresh_token".to_string(),
            ));
        }

        let refresh_token = req
            .refresh_token
            .as_deref()
            .ok_or_else(|| IdpError::TokenError("Missing refresh_token parameter".to_string()))?;

        // 验证客户端合法性与凭证
        let client = client_store
            .find_client(&req.client_id)
            .await?
            .ok_or_else(|| IdpError::InvalidClient(req.client_id.clone()))?;

        if !client.is_public {
            match (client.client_secret, &req.client_secret) {
                (Some(expected), Some(actual)) if expected == *actual => {}
                _ => return Err(IdpError::InvalidClient("Client secret invalid".to_string())),
            }
        }

        if !client
            .grant_types
            .iter()
            .any(|grant| grant == "refresh_token")
        {
            return Err(IdpError::InvalidClient(
                "Refresh token grant is disabled".into(),
            ));
        }

        if Self::is_token_revoked(kv, refresh_token).await? {
            return Err(IdpError::TokenError("Refresh token revoked".into()));
        }

        let claims = token_service.verify_refresh(refresh_token)?;
        if claims.aud.as_deref() != Some(req.client_id.as_str()) {
            return Err(IdpError::InvalidClient(
                "Refresh token client mismatch".into(),
            ));
        }

        let tokens = token_service.renew(refresh_token)?;
        Self::revoke_token(
            kv,
            refresh_token,
            (claims.exp - chrono::Utc::now().timestamp()).max(1) as u64,
        )
        .await?;
        Ok(tokens)
    }

    /// 撤销 Token (RFC 7009 Token Revocation)
    pub async fn revoke_token<K: KvStore>(kv: &K, token: &str, ttl_secs: u64) -> Result<()> {
        let key = format!("token:revoked:{}", token);
        kv.set(&key, "1", ttl_secs).await
    }

    /// 检查 Token 是否已被撤销
    pub async fn is_token_revoked<K: KvStore>(kv: &K, token: &str) -> Result<bool> {
        let key = format!("token:revoked:{}", token);
        let val = kv.get(&key).await?;
        Ok(val.is_some())
    }
}
