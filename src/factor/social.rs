pub mod feishu;
pub mod github;
pub mod google;
pub mod wechat;

pub use feishu::{Feishu, FeishuConfig};
pub use github::{Github, GithubConfig};
pub use google::{Google, GoogleConfig};
pub use wechat::{Wechat, WechatConfig};

use crate::types::Identity;
use serde::{Deserialize, Serialize};

/// 社交平台返回的标准身份资料。
#[derive(Clone, Serialize, Deserialize)]
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
