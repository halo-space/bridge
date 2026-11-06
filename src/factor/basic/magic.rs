use crate::error::{IdpError, Result};
use crate::store::KvStore;
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
    /// 前端消费魔术链接的基础回调地址, 如 "https://auth.halo.com/api/v1/auth/magic-callback"
    pub base_url: String,
    /// 签名密钥 (建议 32 字节以上随机强密钥)
    pub signing_secret: String,
    /// 魔术链接有效期 (秒), 默认 900 秒 (15 分钟)
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
}

fn default_ttl() -> u64 {
    900
}

impl Default for MagicLinkConfig {
    fn default() -> Self {
        Self {
            base_url: "https://halo.local/auth/magic-verify".to_string(),
            signing_secret: "halo_magic_link_default_insecure_secret_key_32b!".to_string(),
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

/// 魔术链接管理服务
pub struct MagicLinkService {
    config: MagicLinkConfig,
}

impl MagicLinkService {
    pub fn new(config: MagicLinkConfig) -> Self {
        Self { config }
    }

    /// 当前系统时间戳 (秒)
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// 签发单次免密登录/重置魔术链接
    ///
    /// 返回 `(token, full_magic_url)`
    pub fn create_magic_link(
        &self,
        email: &str,
        user_id: Option<&str>,
        action: &str,
        redirect_to: Option<&str>,
    ) -> Result<(String, String)> {
        if email.trim().is_empty() {
            return Err(IdpError::MagicLinkError(
                "Email cannot be empty".to_string(),
            ));
        }

        let now = Self::current_timestamp();
        let payload = MagicLinkPayload {
            jti: Uuid::new_v4().to_string(),
            email: email.trim().to_lowercase(),
            user_id: user_id.map(|s| s.to_string()),
            action: action.to_string(),
            redirect_to: redirect_to.map(|s| s.to_string()),
            iat: now,
            exp: now + self.config.ttl_seconds,
        };

        let payload_json = serde_json::to_string(&payload)
            .map_err(|e| IdpError::MagicLinkError(format!("Serialize payload failed: {}", e)))?;
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        // 计算 HMAC-SHA256 签名
        let mut mac = HmacSha256::new_from_slice(self.config.signing_secret.as_bytes())
            .map_err(|e| IdpError::MagicLinkError(format!("Invalid signing secret: {}", e)))?;
        mac.update(payload_b64.as_bytes());
        let signature = mac.finalize().into_bytes();
        let sig_b64 = BASE64_URL_SAFE_NO_PAD.encode(&signature);

        let token = format!("{}.{}", payload_b64, sig_b64);

        // 构造完整跳转 URL
        let sep = if self.config.base_url.contains('?') {
            "&"
        } else {
            "?"
        };
        let full_url = format!("{}{}token={}", self.config.base_url, sep, token);

        Ok((token, full_url))
    }

    /// 校验并解密魔术链接 Token
    pub fn verify_token(&self, token: &str) -> Result<MagicLinkPayload> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Err(IdpError::MagicLinkError(
                "Malformed magic token format".to_string(),
            ));
        }

        let payload_b64 = parts[0];
        let sig_b64 = parts[1];

        // 验证签名
        let provided_sig = BASE64_URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| IdpError::MagicLinkError("Invalid base64 in signature".to_string()))?;

        let mut check = HmacSha256::new_from_slice(self.config.signing_secret.as_bytes())
            .map_err(|e| IdpError::MagicLinkError(format!("Invalid signing secret: {}", e)))?;
        check.update(payload_b64.as_bytes());
        if check.verify_slice(&provided_sig).is_err() {
            return Err(IdpError::MagicLinkError(
                "Magic link signature mismatch / tampered".to_string(),
            ));
        }

        // 解析 Payload
        let payload_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| IdpError::MagicLinkError("Invalid base64 in payload".to_string()))?;

        let payload: MagicLinkPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| IdpError::MagicLinkError(format!("Invalid magic token payload: {}", e)))?;

        // 校验过期时间
        let now = Self::current_timestamp();
        if now > payload.exp {
            return Err(IdpError::MagicLinkError(
                "Magic link has expired".to_string(),
            ));
        }

        Ok(payload)
    }

    /// 将魔术链接登记到外部存储，供后续单次消费。
    pub async fn create<K: KvStore>(
        &self,
        kv: &K,
        email: &str,
        user_id: Option<&str>,
        action: &str,
        redirect_to: Option<&str>,
    ) -> Result<(String, String)> {
        let (token, url) = self.create_magic_link(email, user_id, action, redirect_to)?;
        let payload = self.verify_token(&token)?;
        let ttl = payload.exp.saturating_sub(Self::current_timestamp()).max(1);
        kv.set(&format!("magic:{}", payload.jti), &token, ttl)
            .await?;
        Ok((token, url))
    }

    /// 校验并原子消费魔术链接，避免同一链接被重复使用。
    pub async fn take<K: KvStore>(&self, kv: &K, token: &str) -> Result<MagicLinkPayload> {
        let payload = self.verify_token(token)?;
        let key = format!("magic:{}", payload.jti);
        if !kv.take_if(&key, token).await? {
            return Err(IdpError::MagicLinkError(
                "Magic link already used or not issued".into(),
            ));
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_link_create_and_verify_success() {
        let config = MagicLinkConfig {
            base_url: "https://auth.halo.com/verify".to_string(),
            signing_secret: "super-secret-key-1234567890-secure!".to_string(),
            ttl_seconds: 600,
        };
        let service = MagicLinkService::new(config);

        let (token, full_url) = service
            .create_magic_link(
                "User@Example.com",
                Some("u_10001"),
                "login",
                Some("/workspace/dashboard"),
            )
            .expect("Failed to create magic link");

        assert!(full_url.starts_with("https://auth.halo.com/verify?token="));

        let verified = service
            .verify_token(&token)
            .expect("Token verification failed");
        assert_eq!(verified.email, "user@example.com");
        assert_eq!(verified.user_id.as_deref(), Some("u_10001"));
        assert_eq!(verified.action, "login");
        assert_eq!(
            verified.redirect_to.as_deref(),
            Some("/workspace/dashboard")
        );
        assert!(verified.exp > verified.iat);
    }

    #[test]
    fn test_magic_link_tampered_fails() {
        let config = MagicLinkConfig::default();
        let service = MagicLinkService::new(config);

        let (token, _) = service
            .create_magic_link("test@halo.com", None, "login", None)
            .unwrap();

        let tampered = format!("{}tampered", token);
        let res = service.verify_token(&tampered);
        assert!(res.is_err());
    }

    #[test]
    fn test_magic_link_expired_fails() {
        let config = MagicLinkConfig {
            base_url: "https://auth.halo.com/verify".to_string(),
            signing_secret: "secret".to_string(),
            ttl_seconds: 0, // 立即过期
        };
        let service = MagicLinkService::new(config);

        let (token, _) = service
            .create_magic_link("expired@halo.com", None, "login", None)
            .unwrap();

        // 稍微等待 1 秒确保当前时间戳大于 exp
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let res = service.verify_token(&token);
        assert!(res.is_err());
    }
}
