use super::SocialProfile;
use crate::error::{IdpError, Result};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeishuConfig {
    pub app_id: String,
    pub app_secret: String,
}

pub struct FeishuProvider {
    config: FeishuConfig,
}

impl FeishuProvider {
    pub fn new(config: FeishuConfig) -> Self {
        Self { config }
    }

    /// 构造飞书网页登录跳转链接
    pub fn get_authorize_url(&self, state: &str, redirect_uri: &str) -> Result<String> {
        let mut u = Url::parse("https://passport.feishu.cn/suite/pas/oauth/authorize")
            .map_err(|e| IdpError::Internal(e.to_string()))?;

        u.query_pairs_mut()
            .append_pair("app_id", &self.config.app_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state);

        Ok(u.to_string())
    }

    /// 从飞书 authen/v1/user_info 解析为标准化 SocialProfile
    pub fn parse_user_json(user_json: &serde_json::Value) -> Result<SocialProfile> {
        let data = if user_json.get("data").is_some() {
            &user_json["data"]
        } else {
            user_json
        };

        let open_id = data["open_id"]
            .as_str()
            .ok_or_else(|| IdpError::OAuthError("Missing Feishu open_id".into()))?
            .to_string();

        let union_id = data["union_id"].as_str().map(|s| s.to_string());
        let name = data["name"].as_str().map(|s| s.to_string());
        let email = data["email"].as_str().map(|s| s.to_string());
        let phone = data["mobile"].as_str().map(|s| s.to_string());
        let avatar = data["avatar_url"].as_str().map(|s| s.to_string());

        Ok(SocialProfile {
            provider: "feishu".into(),
            openid: open_id,
            unionid: union_id,
            username: None,
            nickname: name,
            email,
            phone,
            avatar,
            raw: Some(user_json.clone()),
        })
    }

    /// 使用 authorization_code 向飞书换取 user_access_token 并拉取用户信息返回标准化 Profile
    pub async fn exchange_code_for_profile(
        &self,
        code: &str,
        _redirect_uri: &str,
    ) -> Result<SocialProfile> {
        let http = reqwest::Client::new();

        // 1. 获取 app_access_token
        let app_token_url = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal";
        let app_body = serde_json::json!({
            "app_id": self.config.app_id,
            "app_secret": self.config.app_secret,
        });

        let app_resp = http
            .post(app_token_url)
            .json(&app_body)
            .send()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Feishu app_access_token error: {e}")))?;

        let app_json: serde_json::Value = app_resp
            .json()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Invalid Feishu app_token JSON: {e}")))?;

        let app_access_token = app_json["app_access_token"]
            .as_str()
            .ok_or_else(|| IdpError::OAuthError("Missing Feishu app_access_token".into()))?;

        // 2. 换取 user_access_token
        let user_token_url = "https://open.feishu.cn/open-apis/authen/v1/access_token";
        let user_token_body = serde_json::json!({
            "grant_type": "authorization_code",
            "code": code,
        });

        let token_resp = http
            .post(user_token_url)
            .header("Authorization", format!("Bearer {app_access_token}"))
            .json(&user_token_body)
            .send()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Feishu user token error: {e}")))?;

        let token_json: serde_json::Value = token_resp
            .json()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Invalid Feishu user token JSON: {e}")))?;

        let user_access_token = token_json["data"]["access_token"].as_str().ok_or_else(|| {
            let msg = token_json["msg"]
                .as_str()
                .unwrap_or("missing user access_token");
            IdpError::OAuthError(format!("Feishu token exchange failed: {msg}"))
        })?;

        // 3. 拉取用户信息
        let user_info_url = "https://open.feishu.cn/open-apis/authen/v1/user_info";
        let user_resp = http
            .get(user_info_url)
            .header("Authorization", format!("Bearer {user_access_token}"))
            .send()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Feishu user_info error: {e}")))?;

        let user_json: serde_json::Value = user_resp
            .json()
            .await
            .map_err(|e| IdpError::OAuthError(format!("Invalid Feishu user_info JSON: {e}")))?;

        Self::parse_user_json(&user_json)
    }
}
