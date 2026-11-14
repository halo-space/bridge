use super::*;
use crate::factor::oidc::server::TokenResponse;
use uuid::Uuid;

impl Flow {
    /// 校验并处理 Refresh Token 换发 (grant_type=refresh_token)
    pub async fn exchange_refresh_token<C: Clients, K: Secrets>(
        client_store: &C,
        token: &Token,
        kv: &K,
        req: &TokenRequest,
    ) -> Result<TokenResponse> {
        if req.grant_type != "refresh_token" {
            return Err(Error::TokenError(
                "Invalid grant_type, expected refresh_token".to_string(),
            ));
        }

        let refresh_token = req
            .refresh_token
            .as_deref()
            .ok_or_else(|| Error::TokenError("Missing refresh_token parameter".to_string()))?;

        // 验证客户端合法性与凭证
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
            .any(|grant| grant == "refresh_token")
        {
            return Err(Error::InvalidClient(
                "Refresh token grant is disabled".into(),
            ));
        }

        let claims = token.verify_refresh(refresh_token)?;
        if claims.aud.as_deref() != Some(req.client_id.as_str()) {
            return Err(Error::InvalidClient("Refresh token client mismatch".into()));
        }
        if Self::is_token_revoked(kv, refresh_token).await? {
            return Err(Error::TokenError("Refresh token revoked".into()));
        }

        let remaining = (claims.exp - chrono::Utc::now().timestamp()).max(1) as u64;
        let key = crate::token::refresh_key(refresh_token);
        if !kv
            .claim(&key, &Uuid::new_v4().to_string(), remaining)
            .await?
        {
            return Err(Error::TokenError("Refresh token already used".into()));
        }

        let tokens = match token.renew_claims(&claims) {
            Ok(tokens) => tokens,
            Err(error) => {
                let _ = kv.del(&key).await;
                return Err(error);
            }
        };
        Self::revoke_token(kv, refresh_token, remaining).await?;
        let id_token = if claims
            .scope
            .as_deref()
            .is_some_and(|scope| scope.split_whitespace().any(|value| value == "openid"))
        {
            Some(token.issue_id_claims(&claims, req.client_id.clone())?)
        } else {
            None
        };
        Ok(TokenResponse {
            access_token: tokens.0,
            token_type: "Bearer".into(),
            expires_in: token.access_ttl(),
            refresh_token: Some(tokens.1),
            id_token,
            scope: claims.scope,
        })
    }
}
