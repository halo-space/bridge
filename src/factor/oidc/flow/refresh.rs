use super::*;

impl OidcFlow {
    /// 校验并处理 Refresh Token 换发 (grant_type=refresh_token)
    pub async fn exchange_refresh_token<C: Clients, U: Users, K: Secrets>(
        client_store: &C,
        user_store: &U,
        token_service: &TokenService,
        kv: &K,
        req: &TokenRequest,
    ) -> Result<(String, String)> {
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
                (Some(expected), Some(actual)) if expected == *actual => {}
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

        if Self::is_token_revoked(kv, refresh_token).await? {
            return Err(Error::TokenError("Refresh token revoked".into()));
        }

        let claims = token_service.verify_refresh(refresh_token)?;
        if claims.aud.as_deref() != Some(req.client_id.as_str()) {
            return Err(Error::InvalidClient("Refresh token client mismatch".into()));
        }

        let user_id = claims
            .sub
            .parse()
            .map_err(|_| Error::TokenError("Invalid subject".into()))?;
        let user = user_store
            .find_by_id(user_id)
            .await?
            .ok_or(Error::UserNotFound)?;
        if !user.is_active {
            return Err(Error::UserDisabled);
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
}
