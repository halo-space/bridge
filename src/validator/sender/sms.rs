use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

mod aliyun;
mod tencent;
mod unknown;

use aliyun::Aliyun;
use tencent::Tencent;
use unknown::Unknown;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub strict: bool,
    #[serde(default = "default_provider")]
    pub provider: String,
    pub access_key_id: String,
    #[serde(default, skip_serializing)]
    pub access_key_secret: String,
    pub sign_name: String,
    pub template_code: String,
    #[serde(default)]
    pub sdk_app_id: String,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub retries: u32,
}

fn default_provider() -> String {
    "aliyun".to_string()
}
fn default_timeout() -> u64 {
    8
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
            sdk_app_id: String::new(),
            region: None,
            endpoint: None,
            timeout_secs: default_timeout(),
            retries: 0,
        }
    }
}

pub type BoxFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// 短信供应商适配器。新增供应商只需实现该接口。
pub trait Sender: Send + Sync {
    fn send<'a>(&'a self, phone: &'a str, code: &'a str, ttl_secs: u64) -> BoxFuture<'a>;
}

#[derive(Clone)]
pub struct SmsSender {
    config: SmsConfig,
    sender: Arc<dyn Sender>,
    custom: bool,
    unsupported: bool,
}

impl SmsSender {
    pub fn new(config: SmsConfig) -> Self {
        let (sender, unsupported): (Arc<dyn Sender>, bool) =
            match config.provider.to_lowercase().as_str() {
                "aliyun" => (Arc::new(Aliyun::new(config.clone())), false),
                "tencent" => (Arc::new(Tencent::new(config.clone())), false),
                _ => (Arc::new(Unknown::new(config.provider.clone())), true),
            };
        Self {
            config,
            sender,
            custom: false,
            unsupported,
        }
    }

    /// 使用自定义供应商适配器，不改动短信生命周期和上层 Pipeline。
    pub fn with(config: SmsConfig, sender: impl Sender + 'static) -> Self {
        Self {
            config,
            sender: Arc::new(sender),
            custom: true,
            unsupported: false,
        }
    }

    pub fn config(&self) -> &SmsConfig {
        &self.config
    }

    pub fn is_active(&self) -> bool {
        if self.custom {
            return self.config.enabled;
        }
        self.config.enabled
            && !self.config.access_key_id.trim().is_empty()
            && !self.config.access_key_secret.trim().is_empty()
    }

    pub async fn send_verification_code(
        &self,
        phone: &str,
        code: &str,
        ttl_secs: u64,
    ) -> Result<()> {
        if self.unsupported {
            return Err(Error::SmsFailed(format!(
                "Unsupported SMS provider: {}",
                self.config.provider
            )));
        }
        if !self.is_active() {
            if self.config.strict {
                return Err(Error::SmsFailed(
                    "SMS channel is disabled or incomplete".into(),
                ));
            }
            tracing::info!(target: "bridge::sms", "SMS channel is disabled or incomplete, skip delivery: phone={phone}");
            return Ok(());
        }
        self.sender.send(phone, code, ttl_secs).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_mainland_phone() {
        assert_eq!(tencent::normalize_phone("13800138000"), "+8613800138000");
        assert_eq!(tencent::normalize_phone("8613800138000"), "+8613800138000");
        assert_eq!(tencent::normalize_phone("+8613800138000"), "+8613800138000");
    }

    #[tokio::test]
    async fn tencent_requires_reviewed_template_config() {
        let sender = SmsSender::new(SmsConfig {
            enabled: true,
            provider: "tencent".into(),
            access_key_id: "id".into(),
            access_key_secret: "secret".into(),
            ..SmsConfig::default()
        });
        let error = sender
            .send_verification_code("13800138000", "123456", 300)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::SmsFailed(message) if message.contains("sdk_app_id")));
    }

    #[tokio::test]
    async fn custom_sender_reuses_sms_facade() {
        struct Test;
        impl Sender for Test {
            fn send<'a>(
                &'a self,
                _phone: &'a str,
                _code: &'a str,
                _ttl_secs: u64,
            ) -> BoxFuture<'a> {
                Box::pin(async { Ok(()) })
            }
        }
        let sender = SmsSender::with(
            SmsConfig {
                enabled: true,
                access_key_id: "id".into(),
                access_key_secret: "secret".into(),
                ..SmsConfig::default()
            },
            Test,
        );
        assert!(
            sender
                .send_verification_code("13800138000", "123456", 300)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn unknown_provider_is_rejected_even_when_disabled() {
        let sender = SmsSender::new(SmsConfig {
            provider: "other".into(),
            ..SmsConfig::default()
        });
        let error = sender
            .send_verification_code("13800138000", "123456", 300)
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::SmsFailed(message) if message.contains("Unsupported SMS provider"))
        );
    }

    #[tokio::test]
    async fn tencent_uses_api3_request_and_parses_success() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 16 * 1024];
            let size = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..size]).to_ascii_lowercase();
            assert!(request.contains("x-tc-action: sendsms"));
            assert!(request.contains("authorization: tc3-hmac-sha256"));
            let body = r#"{"Response":{"SendStatusSet":[{"Code":"Ok","Message":"send success"}],"RequestId":"test"}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });

        let sender = SmsSender::new(SmsConfig {
            enabled: true,
            provider: "tencent".into(),
            access_key_id: "secret-id".into(),
            access_key_secret: "secret-key".into(),
            sign_name: "Halo".into(),
            template_code: "1234".into(),
            sdk_app_id: "1400000000".into(),
            endpoint: Some(format!("http://{address}")),
            ..SmsConfig::default()
        });
        sender
            .send_verification_code("13800138000", "123456", 300)
            .await
            .unwrap();
        server.await.unwrap();
    }
}
