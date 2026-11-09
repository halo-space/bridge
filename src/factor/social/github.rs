use super::SocialProfile;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubConfig {
    pub client_id: String,
    #[serde(default, skip_serializing)]
    pub client_secret: String,
    pub scope: Option<String>,
}

pub struct GithubProvider {
    config: GithubConfig,
    endpoint: String,
    api_endpoint: String,
    timeout: Duration,
}

impl GithubProvider {
    pub fn new(config: GithubConfig) -> Self {
        Self {
            config,
            endpoint: "https://github.com".into(),
            api_endpoint: "https://api.github.com".into(),
            timeout: crate::pkg::http::DEFAULT_TIMEOUT,
        }
    }

    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub fn api_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.api_endpoint = endpoint.into();
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout.max(Duration::from_secs(1));
        self
    }

    /// 构造 GitHub OAuth 授权重定向跳转 URL
    pub fn authorize_url(&self, state: &str, redirect_uri: &str) -> Result<String> {
        let mut u = Url::parse(&format!(
            "{}/login/oauth/authorize",
            self.endpoint.trim_end_matches('/')
        ))
        .map_err(|e| Error::Internal(e.to_string()))?;

        let scope = self
            .config
            .scope
            .as_deref()
            .unwrap_or("read:user,user:email");
        u.query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", scope)
            .append_pair("state", state);

        Ok(u.to_string())
    }

    /// 从 GitHub API 返回的用户信息解析为标准化 SocialProfile
    pub fn parse(user_json: &serde_json::Value) -> Result<SocialProfile> {
        let id = user_json["id"]
            .as_i64()
            .map(|i| i.to_string())
            .or_else(|| user_json["id"].as_str().map(|s| s.to_string()))
            .ok_or_else(|| Error::OAuthError("Missing GitHub user id".into()))?;

        let login = user_json["login"].as_str().map(|s| s.to_string());
        let name = user_json["name"].as_str().map(|s| s.to_string());
        let email = user_json["email"].as_str().map(|s| s.to_string());
        let avatar = user_json["avatar_url"].as_str().map(|s| s.to_string());

        Ok(SocialProfile {
            provider: "github".into(),
            openid: id,
            unionid: None,
            username: login.clone(),
            nickname: name.or(login),
            email,
            phone: None,
            avatar,
            raw: Some(user_json.clone()),
        })
    }

    /// 使用 authorization_code 向 GitHub 换取 access_token 并拉取用户信息返回标准化 Profile
    pub async fn exchange_code_for_profile(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<SocialProfile> {
        let http = crate::pkg::http::client(self.timeout)?;

        // 1. 换取 access_token
        let token_url = format!(
            "{}/login/oauth/access_token",
            self.endpoint.trim_end_matches('/')
        );
        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ];

        let token_resp = http
            .post(token_url)
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(|e| Error::OAuthError(format!("GitHub token exchange network error: {e}")))?;

        let token_json: serde_json::Value = token_resp
            .error_for_status()
            .map_err(|e| Error::OAuthError(format!("GitHub token HTTP error: {e}")))?
            .json()
            .await
            .map_err(|e| Error::OAuthError(format!("Invalid GitHub token JSON: {e}")))?;

        let access_token = token_json["access_token"].as_str().ok_or_else(|| {
            let err = token_json["error_description"]
                .as_str()
                .or_else(|| token_json["error"].as_str())
                .unwrap_or("missing access_token");
            Error::OAuthError(format!("GitHub token error: {err}"))
        })?;

        // 2. 拉取用户信息
        let user_resp = http
            .get(format!("{}/user", self.api_endpoint.trim_end_matches('/')))
            .header("Authorization", format!("Bearer {access_token}"))
            .header("User-Agent", "Halo-IdP")
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::OAuthError(format!("GitHub user fetch network error: {e}")))?;

        let mut user_json: serde_json::Value = user_resp
            .error_for_status()
            .map_err(|e| Error::OAuthError(format!("GitHub user HTTP error: {e}")))?
            .json()
            .await
            .map_err(|e| Error::OAuthError(format!("Invalid GitHub user JSON: {e}")))?;

        // 若用户公开邮箱为空，尝试拉取 primary 邮箱
        if user_json["email"].is_null()
            && let Ok(emails_resp) = http
                .get(format!(
                    "{}/user/emails",
                    self.api_endpoint.trim_end_matches('/')
                ))
                .header("Authorization", format!("Bearer {access_token}"))
                .header("User-Agent", "Halo-IdP")
                .header("Accept", "application/json")
                .send()
                .await
            && let Ok(emails_resp) = emails_resp.error_for_status()
            && let Ok(emails_json) = emails_resp.json::<serde_json::Value>().await
            && let Some(arr) = emails_json.as_array()
        {
            let primary_email = arr
                .iter()
                .find(|e| e["primary"].as_bool().unwrap_or(false))
                .and_then(|e| e["email"].as_str())
                .or_else(|| arr.first().and_then(|e| e["email"].as_str()));
            if let Some(em) = primary_email {
                user_json["email"] = serde_json::json!(em);
            }
        }

        Self::parse(&user_json)
    }
}
