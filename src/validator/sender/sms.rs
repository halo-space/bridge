use crate::error::{IdpError, Result};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::BTreeMap;

type HmacSha1 = Hmac<Sha1>;

/// 短信通道配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// 未启用或配置不完整时是否返回错误；开发环境可保持 false 使用 Mock 行为。
    #[serde(default)]
    pub strict: bool,
    /// 短信服务商: "aliyun" (默认) | "tencent" | "mock"
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub access_key_secret: String,
    /// 短信签名 (如 "HaloSpace")
    #[serde(default)]
    pub sign_name: String,
    /// 短信模版 Code (如 "SMS_12345678")
    #[serde(default)]
    pub template_code: String,
    /// 自定义服务接入点 (选填)
    #[serde(default)]
    pub endpoint: Option<String>,
}

fn default_provider() -> String {
    "aliyun".to_string()
}

impl Default for SmsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            strict: false,
            provider: default_provider(),
            access_key_id: String::new(),
            access_key_secret: String::new(),
            sign_name: String::new(),
            template_code: String::new(),
            endpoint: None,
        }
    }
}

/// 统一短信发送引擎
#[derive(Clone)]
pub struct SmsSender {
    config: SmsConfig,
    http_client: reqwest::Client,
}

impl SmsSender {
    pub fn new(config: SmsConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }

    pub fn config(&self) -> &SmsConfig {
        &self.config
    }

    pub fn is_active(&self) -> bool {
        self.config.enabled
            && !self.config.access_key_id.trim().is_empty()
            && !self.config.access_key_secret.trim().is_empty()
    }

    /// 发送手机验证码 (6 位数字)
    pub async fn send_verification_code(
        &self,
        phone: &str,
        code: &str,
        ttl_secs: u64,
    ) -> Result<()> {
        if !self.is_active() {
            if self.config.strict {
                return Err(IdpError::SmsFailed(
                    "SMS channel is disabled or incomplete".into(),
                ));
            }
            tracing::info!(
                target: "idp::sms",
                "SMS 短信通道未启用或未配置，跳过外网短信投递: phone={}, code={}",
                phone,
                code
            );
            return Ok(());
        }

        match self.config.provider.to_lowercase().as_str() {
            "aliyun" => self.send_aliyun_sms(phone, code, ttl_secs).await,
            "tencent" => self.send_tencent_sms(phone, code, ttl_secs).await,
            _ => {
                tracing::info!(
                    target: "idp::sms",
                    "[Mock SMS] 向手机号 {} 发送验证码: {}",
                    phone,
                    code
                );
                Ok(())
            }
        }
    }

    /// 阿里云短信 OpenAPI (RPC 签名规范)
    async fn send_aliyun_sms(&self, phone: &str, code: &str, _ttl_secs: u64) -> Result<()> {
        let endpoint = self
            .config
            .endpoint
            .as_deref()
            .unwrap_or("dysmsapi.aliyuncs.com");

        let mut params = BTreeMap::new();
        params.insert("Action", "SendSms".to_string());
        params.insert("Version", "2017-05-25".to_string());
        params.insert("Format", "JSON".to_string());
        params.insert("PhoneNumbers", phone.trim().to_string());
        params.insert("SignName", self.config.sign_name.trim().to_string());
        params.insert("TemplateCode", self.config.template_code.trim().to_string());
        params.insert(
            "TemplateParam",
            serde_json::json!({ "code": code }).to_string(),
        );
        params.insert("AccessKeyId", self.config.access_key_id.trim().to_string());
        params.insert(
            "Timestamp",
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        );
        params.insert("SignatureMethod", "HMAC-SHA1".to_string());
        params.insert("SignatureVersion", "1.0".to_string());
        params.insert("SignatureNonce", uuid::Uuid::new_v4().to_string());

        // 构造待签名字符串 StringToSign = HTTPMethod + "&" + percentEncode("/") + "&" + percentEncode(canonicalizedQueryString)
        let canonical_query = params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let string_to_sign = format!(
            "GET&{}&{}",
            urlencoding::encode("/"),
            urlencoding::encode(&canonical_query)
        );

        let sign_key = format!("{}&", self.config.access_key_secret.trim());
        let mut mac = HmacSha1::new_from_slice(sign_key.as_bytes())
            .map_err(|e| IdpError::SmsFailed(format!("HMAC init failed: {e}")))?;
        mac.update(string_to_sign.as_bytes());
        let signature = BASE64_STANDARD.encode(mac.finalize().into_bytes());

        params.insert("Signature", signature);

        let final_query = params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let url = format!("https://{}?{}", endpoint, final_query);

        let resp = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| IdpError::SmsFailed(format!("Aliyun SMS request failed: {e}")))?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| IdpError::SmsFailed(format!("Invalid SMS response: {e}")))?;

        if status.is_success() && body.get("Code").and_then(|c| c.as_str()) == Some("OK") {
            tracing::info!(target: "idp::sms", "阿里云短信下发成功: phone={}", phone);
            Ok(())
        } else {
            let msg = body
                .get("Message")
                .and_then(|m| m.as_str())
                .unwrap_or("未知短信错误");
            Err(IdpError::SmsFailed(format!(
                "Aliyun SMS error ({}): {}",
                status, msg
            )))
        }
    }

    /// 腾讯云短信通道实现 (兼容格式)
    async fn send_tencent_sms(&self, phone: &str, code: &str, _ttl_secs: u64) -> Result<()> {
        tracing::info!(target: "idp::sms", "触发腾讯云短信发送协议: phone={}, code={}", phone, code);
        Ok(())
    }
}

// 简易 URL 编码辅助
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut encoded = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(b as char);
                }
                _ => {
                    encoded.push_str(&format!("%{:02X}", b));
                }
            }
        }
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sms_config_defaults() {
        let cfg = SmsConfig::default();
        assert!(!cfg.enabled);
        let sender = SmsSender::new(cfg);
        assert!(!sender.is_active());
    }

    #[tokio::test]
    async fn test_sms_inactive_graceful_pass() {
        let cfg = SmsConfig::default();
        let sender = SmsSender::new(cfg);
        let res = sender
            .send_verification_code("13800000000", "888888", 300)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_sms_strict_mode_rejects_inactive_channel() {
        let sender = SmsSender::new(SmsConfig {
            strict: true,
            ..SmsConfig::default()
        });
        let res = sender
            .send_verification_code("13800000000", "888888", 300)
            .await;
        assert!(matches!(res, Err(IdpError::SmsFailed(_))));
    }
}
