use super::*;

impl Flow {
    /// 校验 PKCE code_verifier 与 code_challenge (RFC 7636)
    pub fn verify_pkce(verifier: &str, challenge: &str, method: Option<&str>) -> Result<()> {
        Pkce::check(verifier, challenge, method)
    }
    /// 校验授权请求参数及客户端合法性
    pub async fn validate_authorize_request<C: Clients>(
        client_store: &C,
        req: &AuthorizeRequest,
    ) -> Result<OAuthClient> {
        if req.response_type != "code" {
            return Err(Error::AuthFailed(format!(
                "Unsupported response_type: {}",
                req.response_type
            )));
        }

        let client = client_store
            .find_client(&req.client_id)
            .await?
            .ok_or_else(|| Error::InvalidClient(req.client_id.clone()))?;

        if !client.response_types.iter().any(|kind| kind == "code") {
            return Err(Error::InvalidClient(
                "Authorization code response is disabled".into(),
            ));
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

        // 验证重定向 URI
        let matched = client
            .redirect_uris
            .iter()
            .any(|allowed| allowed == &req.redirect_uri);

        if !matched {
            return Err(Error::InvalidRedirectUri(format!(
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
            return Err(Error::AuthFailed("Requested scope is not allowed".into()));
        }

        if client.is_public && req.code_challenge.is_none() {
            return Err(Error::InvalidPkce);
        }

        if req.code_challenge.is_none() && req.code_challenge_method.is_some() {
            return Err(Error::InvalidPkce);
        }

        if let Some(method) = req.code_challenge_method.as_deref()
            && !matches!(method, "S256" | "plain")
        {
            return Err(Error::InvalidPkce);
        }

        Ok(client)
    }
}
