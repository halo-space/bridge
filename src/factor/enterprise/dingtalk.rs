use crate::error::{Error, Result};
use crate::types::Identity;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

#[derive(Clone, Serialize, Deserialize)]
pub struct DingtalkConfig {
    pub client_id: String,
    #[serde(default, skip_serializing)]
    pub client_secret: String,
}

pub struct Dingtalk {
    config: DingtalkConfig,
    api: String,
    timeout: Duration,
}

impl Dingtalk {
    pub fn new(config: DingtalkConfig) -> Self {
        Self {
            config,
            api: "https://api.dingtalk.com".into(),
            timeout: crate::pkg::http::DEFAULT_TIMEOUT,
        }
    }

    pub fn api(mut self, endpoint: impl Into<String>) -> Self {
        self.api = endpoint.into();
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout.max(Duration::from_secs(1));
        self
    }

    /// 构造钉钉 OAuth2.0 统一登录授权链接
    pub fn authorize_url(&self, state: &str, redirect_uri: &str) -> Result<String> {
        let mut u = Url::parse("https://login.dingtalk.com/oauth2/auth")
            .map_err(|e| Error::Internal(e.to_string()))?;

        u.query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid corpid")
            .append_pair("state", state)
            .append_pair("prompt", "consent");

        Ok(u.to_string())
    }

    /// 使用 authorization_code 向钉钉换取 userAccessToken 并拉取用户信息
    pub async fn exchange_code_for_user(&self, code: &str) -> Result<serde_json::Value> {
        let http = crate::pkg::http::client(self.timeout)?;
        let token_url = format!(
            "{}/v1.0/oauth2/userAccessToken",
            self.api.trim_end_matches('/')
        );

        let body = serde_json::json!({
            "clientId": self.config.client_id,
            "clientSecret": self.config.client_secret,
            "code": code,
            "grantType": "authorization_code"
        });

        let resp =
            http.post(token_url).json(&body).send().await.map_err(|e| {
                crate::pkg::http::provider(e, "Dingtalk token exchange network error")
            })?;

        let token_json: serde_json::Value = crate::pkg::http::json(
            resp.error_for_status()
                .map_err(|e| crate::pkg::http::provider(e, "Dingtalk token HTTP error"))?,
            "Dingtalk token",
        )
        .await?;

        let access_token = token_json["accessToken"].as_str().ok_or_else(|| {
            let msg = token_json["message"]
                .as_str()
                .unwrap_or("missing accessToken");
            Error::OAuthError(format!("Dingtalk token error: {msg}"))
        })?;

        // 拉取用户信息
        let user_url = format!("{}/v1.0/contact/users/me", self.api.trim_end_matches('/'));
        let user_resp = http
            .get(user_url)
            .header("x-acs-dingtalk-access-token", access_token)
            .send()
            .await
            .map_err(|e| crate::pkg::http::provider(e, "Dingtalk user fetch network error"))?;

        let user_json: serde_json::Value = crate::pkg::http::json(
            user_resp
                .error_for_status()
                .map_err(|e| crate::pkg::http::provider(e, "Dingtalk user HTTP error"))?,
            "Dingtalk user",
        )
        .await?;

        Ok(user_json)
    }

    pub fn identity(value: &serde_json::Value) -> Result<Identity> {
        let subject = value
            .get("unionId")
            .or_else(|| value.get("openId"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::AuthFailed("Dingtalk identity is missing subject".into()))?;
        let mut identity = Identity::new("dingtalk", subject);
        if let Some(email) = value.get("email").and_then(|v| v.as_str()) {
            identity = identity.email(email);
        }
        if let Some(phone) = value.get("mobile").and_then(|v| v.as_str()) {
            identity = identity.phone(phone);
        }
        if let Some(name) = value.get("nick").and_then(|v| v.as_str()) {
            identity = identity.name(name);
        }
        Ok(identity)
    }
}
