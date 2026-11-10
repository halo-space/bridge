use super::SocialProfile;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WechatConfig {
    pub app_id: String,
    #[serde(default, skip_serializing)]
    pub app_secret: String,
    pub scope: Option<String>,
}

pub struct Wechat {
    config: WechatConfig,
    api: String,
    timeout: Duration,
}

impl Wechat {
    pub fn new(config: WechatConfig) -> Self {
        Self {
            config,
            api: "https://api.weixin.qq.com".into(),
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

    /// 构造微信扫码登录跳转链接 (PC 网站应用 snsapi_login)
    pub fn authorize_url(&self, state: &str, redirect_uri: &str) -> Result<String> {
        let mut u = Url::parse("https://open.weixin.qq.com/connect/qrconnect")
            .map_err(|e| Error::Internal(e.to_string()))?;

        let scope = self.config.scope.as_deref().unwrap_or("snsapi_login");
        u.query_pairs_mut()
            .append_pair("appid", &self.config.app_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", scope)
            .append_pair("state", state);

        Ok(format!("{}#wechat_redirect", u))
    }

    /// 从微信 sns/userinfo 响应解析为标准化 SocialProfile
    pub fn parse(user_json: &serde_json::Value) -> Result<SocialProfile> {
        let openid = user_json["openid"]
            .as_str()
            .ok_or_else(|| Error::OAuthError("Missing WeChat openid".into()))?
            .to_string();

        let unionid = user_json["unionid"].as_str().map(|s| s.to_string());
        let nickname = user_json["nickname"].as_str().map(|s| s.to_string());
        let avatar = user_json["headimgurl"].as_str().map(|s| s.to_string());

        Ok(SocialProfile {
            provider: "wechat".into(),
            openid,
            unionid,
            username: None,
            nickname,
            email: None,
            phone: None,
            avatar,
            raw: Some(user_json.clone()),
        })
    }

    /// 使用 authorization_code 换取 access_token 并读取微信用户资料。
    pub async fn exchange_code_for_profile(&self, code: &str) -> Result<SocialProfile> {
        let http = crate::pkg::http::client(self.timeout)?;
        let mut token_url = Url::parse(&format!(
            "{}/sns/oauth2/access_token",
            self.api.trim_end_matches('/')
        ))
        .map_err(|e| Error::Internal(e.to_string()))?;
        token_url
            .query_pairs_mut()
            .append_pair("appid", &self.config.app_id)
            .append_pair("secret", &self.config.app_secret)
            .append_pair("code", code)
            .append_pair("grant_type", "authorization_code");
        let token_resp = http
            .get(token_url)
            .send()
            .await
            .map_err(|e| Error::OAuthError(format!("WeChat token exchange error: {e}")))?;

        let token_json: serde_json::Value = token_resp
            .error_for_status()
            .map_err(|e| Error::OAuthError(format!("WeChat token HTTP error: {e}")))?
            .json()
            .await
            .map_err(|e| Error::OAuthError(format!("Invalid WeChat token JSON: {e}")))?;
        if token_json
            .get("errcode")
            .and_then(|value| value.as_i64())
            .unwrap_or(0)
            != 0
        {
            let message = token_json
                .get("errmsg")
                .and_then(|value| value.as_str())
                .unwrap_or("token exchange failed");
            return Err(Error::OAuthError(format!(
                "WeChat token exchange failed: {message}"
            )));
        }

        let access_token = token_json
            .get("access_token")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error::OAuthError("Missing WeChat access_token".into()))?;
        let openid = token_json
            .get("openid")
            .and_then(|value| value.as_str())
            .ok_or_else(|| Error::OAuthError("Missing WeChat openid".into()))?;

        let mut user_url = Url::parse(&format!("{}/sns/userinfo", self.api.trim_end_matches('/')))
            .map_err(|e| Error::Internal(e.to_string()))?;
        user_url
            .query_pairs_mut()
            .append_pair("access_token", access_token)
            .append_pair("openid", openid)
            .append_pair("lang", "zh_CN");
        let user_resp = http
            .get(user_url)
            .send()
            .await
            .map_err(|e| Error::OAuthError(format!("WeChat userinfo error: {e}")))?;
        let user_json: serde_json::Value = user_resp
            .error_for_status()
            .map_err(|e| Error::OAuthError(format!("WeChat userinfo HTTP error: {e}")))?
            .json()
            .await
            .map_err(|e| Error::OAuthError(format!("Invalid WeChat userinfo JSON: {e}")))?;
        if user_json
            .get("errcode")
            .and_then(|value| value.as_i64())
            .unwrap_or(0)
            != 0
        {
            let message = user_json
                .get("errmsg")
                .and_then(|value| value.as_str())
                .unwrap_or("userinfo request failed");
            return Err(Error::OAuthError(format!(
                "WeChat userinfo failed: {message}"
            )));
        }
        Self::parse(&user_json)
    }
}
