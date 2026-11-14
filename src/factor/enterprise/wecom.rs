use crate::error::{Error, Result};
use crate::types::Identity;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WecomConfig {
    pub corp_id: String,
    pub agent_id: String,
    #[serde(default, skip_serializing)]
    pub corp_secret: String,
}

pub struct Wecom {
    config: WecomConfig,
    api: String,
    timeout: Duration,
}

impl Wecom {
    pub fn new(config: WecomConfig) -> Self {
        Self {
            config,
            api: "https://qyapi.weixin.qq.com".into(),
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

    /// 构造企业微信 Web 扫码授权或企业微信内静默授权链接
    pub fn authorize_url(&self, state: &str, redirect_uri: &str) -> Result<String> {
        let mut u = Url::parse("https://open.work.weixin.qq.com/wwopen/sso/qrConnect")
            .map_err(|e| Error::Internal(e.to_string()))?;

        u.query_pairs_mut()
            .append_pair("appid", &self.config.corp_id)
            .append_pair("agentid", &self.config.agent_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state);

        Ok(u.to_string())
    }

    /// 使用 code 换取企微内部成员 userid
    pub async fn exchange_code_for_user(&self, code: &str) -> Result<serde_json::Value> {
        let http = crate::pkg::http::client(self.timeout)?;

        // 1. 获取 access_token
        let token_url = format!(
            "{}/cgi-bin/gettoken?corpid={}&corpsecret={}",
            self.api.trim_end_matches('/'),
            self.config.corp_id,
            self.config.corp_secret
        );
        let token_resp = http
            .get(&token_url)
            .send()
            .await
            .map_err(|e| crate::pkg::http::provider(e, "WeCom access_token network error"))?;

        let token_json: serde_json::Value = crate::pkg::http::json(
            token_resp
                .error_for_status()
                .map_err(|e| crate::pkg::http::provider(e, "WeCom token HTTP error"))?,
            "WeCom token",
        )
        .await?;

        let access_token = token_json["access_token"].as_str().ok_or_else(|| {
            let err = token_json["errmsg"]
                .as_str()
                .unwrap_or("missing access_token");
            Error::OAuthError(format!("WeCom token error: {err}"))
        })?;

        // 2. 根据 code 获取 user_info
        let user_url = format!(
            "{}/cgi-bin/auth/getuserinfo?access_token={}&code={}",
            self.api.trim_end_matches('/'),
            access_token,
            code
        );
        let user_resp = http
            .get(&user_url)
            .send()
            .await
            .map_err(|e| crate::pkg::http::provider(e, "WeCom user_info network error"))?;

        let user_json: serde_json::Value = crate::pkg::http::json(
            user_resp
                .error_for_status()
                .map_err(|e| crate::pkg::http::provider(e, "WeCom user HTTP error"))?,
            "WeCom user",
        )
        .await?;

        Ok(user_json)
    }

    pub fn identity(value: &serde_json::Value) -> Result<Identity> {
        let subject = value
            .get("UserId")
            .or_else(|| value.get("userid"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::AuthFailed("WeCom identity is missing subject".into()))?;
        let mut identity = Identity::new("wecom", subject);
        if let Some(email) = value.get("email").and_then(|v| v.as_str()) {
            identity = identity.email(email);
        }
        if let Some(phone) = value.get("mobile").and_then(|v| v.as_str()) {
            identity = identity.phone(phone);
        }
        if let Some(name) = value.get("name").and_then(|v| v.as_str()) {
            identity = identity.name(name);
        }
        Ok(identity)
    }
}
