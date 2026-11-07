use crate::error::{IdpError, Result};
use crate::types::Identity;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WecomConfig {
    pub corp_id: String,
    pub agent_id: String,
    pub corp_secret: String,
}

pub struct WecomProvider {
    config: WecomConfig,
    endpoint: String,
}

impl WecomProvider {
    pub fn new(config: WecomConfig) -> Self {
        Self {
            config,
            endpoint: "https://qyapi.weixin.qq.com".into(),
        }
    }

    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// 构造企业微信 Web 扫码授权或企业微信内静默授权链接
    pub fn get_authorize_url(&self, state: &str, redirect_uri: &str) -> Result<String> {
        let mut u = Url::parse("https://open.work.weixin.qq.com/wwopen/sso/qrConnect")
            .map_err(|e| IdpError::Internal(e.to_string()))?;

        u.query_pairs_mut()
            .append_pair("appid", &self.config.corp_id)
            .append_pair("agentid", &self.config.agent_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state);

        Ok(u.to_string())
    }

    /// 使用 code 换取企微内部成员 userid
    pub async fn exchange_code_for_user(&self, code: &str) -> Result<serde_json::Value> {
        let http = reqwest::Client::new();

        // 1. 获取 access_token
        let token_url = format!(
            "{}/cgi-bin/gettoken?corpid={}&corpsecret={}",
            self.endpoint.trim_end_matches('/'),
            self.config.corp_id,
            self.config.corp_secret
        );
        let token_resp =
            http.get(&token_url).send().await.map_err(|e| {
                IdpError::OAuthError(format!("WeCom access_token network error: {e}"))
            })?;

        let token_json: serde_json::Value = token_resp
            .json()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Invalid WeCom token JSON: {e}")))?;

        let access_token = token_json["access_token"].as_str().ok_or_else(|| {
            let err = token_json["errmsg"]
                .as_str()
                .unwrap_or("missing access_token");
            IdpError::OAuthError(format!("WeCom token error: {err}"))
        })?;

        // 2. 根据 code 获取 user_info
        let user_url = format!(
            "{}/cgi-bin/auth/getuserinfo?access_token={}&code={}",
            self.endpoint.trim_end_matches('/'),
            access_token,
            code
        );
        let user_resp = http
            .get(&user_url)
            .send()
            .await
            .map_err(|e| IdpError::OAuthError(format!("WeCom user_info network error: {e}")))?;

        let user_json: serde_json::Value = user_resp
            .json()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Invalid WeCom user JSON: {e}")))?;

        Ok(user_json)
    }

    pub fn identity(value: &serde_json::Value) -> Result<Identity> {
        let subject = value
            .get("UserId")
            .or_else(|| value.get("userid"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdpError::AuthFailed("WeCom identity is missing subject".into()))?;
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
