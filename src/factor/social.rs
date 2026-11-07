pub mod feishu;
pub mod github;
pub mod google;
pub mod wechat;

pub use feishu::{FeishuConfig, FeishuProvider};
pub use github::{GithubConfig, GithubProvider};
pub use google::{GoogleConfig, GoogleProvider};
pub use wechat::{WechatConfig, WechatProvider};

use crate::types::{AuthResult, Identity, Level, Method};
use serde::{Deserialize, Serialize};

/// 社交平台返回的标准身份资料。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialProfile {
    pub provider: String,
    pub openid: String,
    pub unionid: Option<String>,
    pub username: Option<String>,
    pub nickname: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub avatar: Option<String>,
    pub raw: Option<serde_json::Value>,
}

impl From<SocialProfile> for Identity {
    fn from(profile: SocialProfile) -> Self {
        Self {
            provider: profile.provider,
            subject: profile.openid,
            email: profile.email,
            phone: profile.phone,
            name: profile.nickname.or(profile.username),
        }
    }
}

pub struct SocialAuth;

impl SocialAuth {
    pub fn identity(profile: SocialProfile) -> Identity {
        profile.into()
    }

    pub fn result(profile: SocialProfile) -> AuthResult {
        AuthResult::new(Self::identity(profile), Method::Social, Level::First)
    }
}
