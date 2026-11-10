use crate::error::{Error, Result};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// 邮件免密魔术链接配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkConfig {
    /// 前端消费魔术链接的基础回调地址，如 `<https://auth.halo.com/api/v1/auth/magic-callback>`。
    pub base_url: String,
    /// 签名密钥 (建议 32 字节以上随机强密钥)
    #[serde(default = "default_signing_secret", skip_serializing)]
    pub signing_secret: String,
    /// 魔术链接有效期 (秒), 默认 900 秒 (15 分钟)
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
}

fn default_ttl() -> u64 {
    900
}

fn default_signing_secret() -> String {
    use base64::Engine;
    use rand_core::{OsRng, RngCore};
    let mut secret = [0_u8; 32];
    OsRng.fill_bytes(&mut secret);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret)
}

impl Default for MagicLinkConfig {
    fn default() -> Self {
        Self {
            base_url: "https://halo.local/auth/magic-verify".to_string(),
            signing_secret: default_signing_secret(),
            ttl_seconds: 900,
        }
    }
}

/// 魔术链接载荷信息
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MagicLinkPayload {
    /// 唯一标识 JTI, 便于单次消费防重放标记
    pub jti: String,
    /// 目标用户邮箱
    pub email: String,
    /// 用户 ID (若用户已存在)
    pub user_id: Option<String>,
    /// 操作目的: "login" | "reset_password" | "bind_email" 等
    pub action: String,
    /// 最终跳转页面
    pub redirect_to: Option<String>,
    /// 签发时间戳 (UNIX 秒)
    pub iat: u64,
    /// 过期时间戳 (UNIX 秒)
    pub exp: u64,
}

/// 生成已签名的 Magic Link。
pub(crate) fn issue(
    config: &MagicLinkConfig,
    email: &str,
    user_id: Option<&str>,
    action: &str,
    redirect_to: Option<&str>,
) -> Result<(String, String, MagicLinkPayload)> {
    if config.signing_secret.trim().len() < 32 {
        return Err(Error::MagicLinkError(
            "Magic link signing secret must contain at least 32 characters".into(),
        ));
    }
    if email.trim().is_empty() {
        return Err(Error::MagicLinkError("Email cannot be empty".to_string()));
    }

    let now = now();
    let payload = MagicLinkPayload {
        jti: Uuid::new_v4().to_string(),
        email: email.trim().to_lowercase(),
        user_id: user_id.map(str::to_string),
        action: action.to_string(),
        redirect_to: redirect_to.map(str::to_string),
        iat: now,
        exp: now + config.ttl_seconds,
    };
    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| Error::MagicLinkError(format!("Serialize payload failed: {e}")))?;
    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let mut mac = HmacSha256::new_from_slice(config.signing_secret.as_bytes())
        .map_err(|e| Error::MagicLinkError(format!("Invalid signing secret: {e}")))?;
    mac.update(payload_b64.as_bytes());
    let signature = mac.finalize().into_bytes();
    let token = format!(
        "{}.{}",
        payload_b64,
        BASE64_URL_SAFE_NO_PAD.encode(signature)
    );
    let sep = if config.base_url.contains('?') {
        "&"
    } else {
        "?"
    };
    Ok((
        token.clone(),
        format!("{}{}token={token}", config.base_url, sep),
        payload,
    ))
}

/// 校验已签名 Magic Link 并返回载荷。
pub(crate) fn verify(config: &MagicLinkConfig, token: &str) -> Result<MagicLinkPayload> {
    if config.signing_secret.trim().len() < 32 {
        return Err(Error::MagicLinkError(
            "Magic link signing secret must contain at least 32 characters".into(),
        ));
    }
    let parts = token.split('.').collect::<Vec<_>>();
    let [payload_b64, sig_b64] = parts.as_slice() else {
        return Err(Error::MagicLinkError("Malformed magic token format".into()));
    };
    let provided_sig = BASE64_URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| Error::MagicLinkError("Invalid base64 in signature".into()))?;
    let mut mac = HmacSha256::new_from_slice(config.signing_secret.as_bytes())
        .map_err(|e| Error::MagicLinkError(format!("Invalid signing secret: {e}")))?;
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&provided_sig)
        .map_err(|_| Error::MagicLinkError("Magic link signature mismatch / tampered".into()))?;
    let payload_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| Error::MagicLinkError("Invalid base64 in payload".into()))?;
    let payload: MagicLinkPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::MagicLinkError(format!("Invalid magic token payload: {e}")))?;
    if now() > payload.exp {
        return Err(Error::MagicLinkError("Magic link has expired".into()));
    }
    Ok(payload)
}

pub(crate) fn ttl(payload: &MagicLinkPayload) -> u64 {
    payload.exp.saturating_sub(now()).max(1)
}

pub(crate) fn key(payload: &MagicLinkPayload) -> String {
    format!("magic:{}", payload.jti)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
