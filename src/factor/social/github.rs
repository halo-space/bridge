use super::SocialProfile;
use crate::error::{IdpError, Result};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubConfig {
    pub client_id: String,
    pub client_secret: String,
    pub scope: Option<String>,
}

pub struct GithubProvider {
    config: GithubConfig,
}

impl GithubProvider {
    pub fn new(config: GithubConfig) -> Self {
        Self { config }
    }

    /// 构造 GitHub OAuth 授权重定向跳转 URL
    pub fn get_authorize_url(&self, state: &str, redirect_uri: &str) -> Result<String> {
        let mut u = Url::parse("https://github.com/login/oauth/authorize")
            .map_err(|e| IdpError::Internal(e.to_string()))?;

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
    pub fn parse_user_json(user_json: &serde_json::Value) -> Result<SocialProfile> {
        let id = user_json["id"]
            .as_i64()
            .map(|i| i.to_string())
            .or_else(|| user_json["id"].as_str().map(|s| s.to_string()))
            .ok_or_else(|| IdpError::OAuthError("Missing GitHub user id".into()))?;

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
        let http = reqwest::Client::new();

        // 1. 换取 access_token
        let token_url = "https://github.com/login/oauth/access_token";
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
            .map_err(|e| {
                IdpError::OAuthError(format!("GitHub token exchange network error: {e}"))
            })?;

        let token_json: serde_json::Value = token_resp
            .json()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Invalid GitHub token JSON: {e}")))?;

        let access_token = token_json["access_token"].as_str().ok_or_else(|| {
            let err = token_json["error_description"]
                .as_str()
                .or_else(|| token_json["error"].as_str())
                .unwrap_or("missing access_token");
            IdpError::OAuthError(format!("GitHub token error: {err}"))
        })?;

        // 2. 拉取用户信息
        let user_resp = http
            .get("https://api.github.com/user")
            .header("Authorization", format!("Bearer {access_token}"))
            .header("User-Agent", "Halo-IdP")
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| IdpError::OAuthError(format!("GitHub user fetch network error: {e}")))?;

        let mut user_json: serde_json::Value = user_resp
            .json()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Invalid GitHub user JSON: {e}")))?;

        // 若用户公开邮箱为空，尝试拉取 primary 邮箱
        if user_json["email"].is_null() {
            if let Ok(emails_resp) = http
                .get("https://api.github.com/user/emails")
                .header("Authorization", format!("Bearer {access_token}"))
                .header("User-Agent", "Halo-IdP")
                .header("Accept", "application/json")
                .send()
                .await
            {
                if let Ok(emails_json) = emails_resp.json::<serde_json::Value>().await {
                    if let Some(arr) = emails_json.as_array() {
                        let primary_email = arr
                            .iter()
                            .find(|e| e["primary"].as_bool().unwrap_or(false))
                            .and_then(|e| e["email"].as_str())
                            .or_else(|| arr.first().and_then(|e| e["email"].as_str()));
                        if let Some(em) = primary_email {
                            user_json["email"] = serde_json::json!(em);
                        }
                    }
                }
            }
        }

        Self::parse_user_json(&user_json)
    }
}
