use super::SocialProfile;
use crate::error::{IdpError, Result};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleConfig {
    pub client_id: String,
    pub client_secret: String,
    pub scope: Option<String>,
}

pub struct GoogleProvider {
    config: GoogleConfig,
}

impl GoogleProvider {
    pub fn new(config: GoogleConfig) -> Self {
        Self { config }
    }

    /// 构造 Google OAuth2 授权跳转链接
    pub fn get_authorize_url(&self, state: &str, redirect_uri: &str) -> Result<String> {
        let mut u = Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
            .map_err(|e| IdpError::Internal(e.to_string()))?;

        let scope = self
            .config
            .scope
            .as_deref()
            .unwrap_or("openid email profile");
        u.query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", scope)
            .append_pair("state", state)
            .append_pair("access_type", "offline");

        Ok(u.to_string())
    }

    /// 从 Google userinfo 响应解析为标准化 SocialProfile
    pub fn parse_user_json(user_json: &serde_json::Value) -> Result<SocialProfile> {
        let sub = user_json["sub"]
            .as_str()
            .ok_or_else(|| IdpError::OAuthError("Missing Google sub identifier".into()))?
            .to_string();

        let name = user_json["name"].as_str().map(|s| s.to_string());
        let email = user_json["email"].as_str().map(|s| s.to_string());
        let avatar = user_json["picture"].as_str().map(|s| s.to_string());

        Ok(SocialProfile {
            provider: "google".into(),
            openid: sub,
            unionid: None,
            username: email.clone(),
            nickname: name,
            email,
            phone: None,
            avatar,
            raw: Some(user_json.clone()),
        })
    }

    /// 使用 authorization_code 换取 access_token 并读取 Google userinfo。
    pub async fn exchange_code_for_profile(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<SocialProfile> {
        let http = reqwest::Client::new();
        let token_resp = http
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Google token exchange error: {e}")))?;

        let token_json: serde_json::Value = token_resp
            .json()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Invalid Google token JSON: {e}")))?;
        let access_token = token_json
            .get("access_token")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                let message = token_json
                    .get("error_description")
                    .or_else(|| token_json.get("error"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("missing access_token");
                IdpError::OAuthError(format!("Google token exchange failed: {message}"))
            })?;

        let user_resp = http
            .get("https://openidconnect.googleapis.com/v1/userinfo")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Google userinfo error: {e}")))?;
        let user_json: serde_json::Value = user_resp
            .json()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Invalid Google userinfo JSON: {e}")))?;
        Self::parse_user_json(&user_json)
    }
}
