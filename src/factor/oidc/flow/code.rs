use super::*;
use sha2::{Digest, Sha256};

impl Flow {
    /// 生成授权码并存入缓存
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_code<K: Secrets>(
        kv: &K,
        client_id: &str,
        identity: Identity,
        redirect_uri: &str,
        scope: &str,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
        ttl: u64,
    ) -> Result<String> {
        Self::issue_code_with_nonce(
            kv,
            client_id,
            identity,
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
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_code_with_nonce<K: Secrets>(
        kv: &K,
        client_id: &str,
        identity: Identity,
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
            identity,
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_string(),
            code_challenge,
            code_challenge_method,
            nonce,
            expires_at,
        };

        let val = serde_json::to_string(&auth_code).map_err(|e| Error::Internal(e.to_string()))?;
        kv.set(&key(&code), &val, ttl).await?;
        Ok(code)
    }
    /// 授权码换 Token 校验（单次使用消费 + PKCE 校验 + Client 密钥校验）
    pub async fn exchange_code<CS: Clients, K: Secrets>(
        client_store: &CS,
        kv: &K,
        req: &TokenRequest,
    ) -> Result<AuthCode> {
        let code_str = req.code.as_deref().ok_or(Error::InvalidCode)?;

        if req.grant_type != "authorization_code" {
            return Err(Error::TokenError(
                "Invalid grant_type, expected authorization_code".into(),
            ));
        }

        let key = key(code_str);
        // 先读取并完成所有校验，最后再消费，避免错误请求提前销毁授权码。
        let val = kv.get(&key).await?.ok_or(Error::InvalidCode)?;

        let auth_code: AuthCode =
            serde_json::from_str(&val).map_err(|e| Error::Internal(e.to_string()))?;

        if auth_code.expires_at <= chrono::Utc::now().timestamp() {
            return Err(Error::InvalidCode);
        }

        // 2. 检查客户端匹配
        if auth_code.client_id != req.client_id {
            return Err(Error::InvalidClient("Client mismatch".to_string()));
        }

        // 3. 检查重定向地址一致性
        if req.redirect_uri.as_deref() != Some(auth_code.redirect_uri.as_str()) {
            return Err(Error::InvalidRedirectUri(
                "Redirect URI mismatch".to_string(),
            ));
        }

        // 4. 验证客户端凭证 (机密客户端需验证 secret，公共客户端需走 PKCE)
        let client = client_store
            .find_client(&req.client_id)
            .await?
            .ok_or_else(|| Error::InvalidClient(req.client_id.clone()))?;

        if !client.is_public {
            match (client.client_secret, &req.client_secret) {
                (Some(expected), Some(actual)) if super::secret_eq(&expected, actual) => {}
                _ => return Err(Error::InvalidClient("Client secret invalid".to_string())),
            }
        }

        if !client
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
        {
            return Err(Error::InvalidClient(
                "Authorization code grant is disabled".into(),
            ));
        }

        let allowed_scopes: std::collections::HashSet<&str> =
            client.scope.split_whitespace().collect();
        if auth_code
            .scope
            .split_whitespace()
            .any(|scope| !allowed_scopes.contains(scope))
        {
            return Err(Error::InvalidClient(
                "Authorization scope is not allowed".into(),
            ));
        }

        // 5. PKCE 校验
        if let Some(challenge) = &auth_code.code_challenge {
            let verifier = req.code_verifier.as_deref().ok_or(Error::InvalidPkce)?;
            Self::verify_pkce(
                verifier,
                challenge,
                auth_code.code_challenge_method.as_deref(),
            )?;
        } else if client.is_public {
            return Err(Error::InvalidPkce);
        }

        if !kv.take_if(&key, &val).await? {
            return Err(Error::InvalidCode);
        }

        Ok(auth_code)
    }

    /// 将授权码或 Refresh Token 兑换为标准 OIDC TokenResponse。
    pub async fn exchange<CS: Clients, K: Secrets>(
        client_store: &CS,
        token: &Token,
        kv: &K,
        req: &TokenRequest,
    ) -> Result<TokenResponse> {
        if req.grant_type == "refresh_token" {
            return Self::exchange_refresh_token(client_store, token, kv, req).await;
        }

        let auth_code = Self::exchange_code(client_store, kv, req).await?;
        let client = client_store
            .find_client(&req.client_id)
            .await?
            .ok_or_else(|| Error::InvalidClient(req.client_id.clone()))?;
        let (access_token, refresh_token) = if client
            .grant_types
            .iter()
            .any(|grant| grant == "refresh_token")
        {
            let (access, refresh) = token.issue_identity(
                &auth_code.identity,
                Some(req.client_id.clone()),
                Some(auth_code.scope.clone()),
            )?;
            (access, Some(refresh))
        } else {
            (
                token.issue_access(
                    &auth_code.identity,
                    Some(req.client_id.clone()),
                    Some(auth_code.scope.clone()),
                )?,
                None,
            )
        };
        let id_token = if auth_code
            .scope
            .split_whitespace()
            .any(|scope| scope == "openid")
        {
            Some(token.issue_id_identity(
                &auth_code.identity,
                req.client_id.clone(),
                auth_code.nonce.clone(),
                Some(auth_code.scope.clone()),
            )?)
        } else {
            None
        };
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in: token.access_ttl(),
            refresh_token,
            id_token,
            scope: Some(auth_code.scope),
        })
    }
}

fn key(code: &str) -> String {
    let digest = Sha256::digest(code.as_bytes());
    let value = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("code:{value}")
}
