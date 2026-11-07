use crate::error::{IdpError, Result};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use hmac::{Hmac, Mac};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub strict: bool,
    #[serde(default = "default_provider")]
    pub provider: String,
    pub access_key_id: String,
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
}

impl SmsSender {
    pub fn new(config: SmsConfig) -> Self {
        let sender: Arc<dyn Sender> = match config.provider.to_lowercase().as_str() {
            "aliyun" => Arc::new(Aliyun::new(config.clone())),
            "tencent" => Arc::new(Tencent::new(config.clone())),
            _ => Arc::new(Mock),
        };
        Self { config, sender }
    }

    /// 使用自定义供应商适配器，不改动短信生命周期和上层 Pipeline。
    pub fn with(config: SmsConfig, sender: impl Sender + 'static) -> Self {
        Self {
            config,
            sender: Arc::new(sender),
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
            tracing::info!(target: "idp::sms", "SMS channel is disabled or incomplete, skip delivery: phone={phone}");
            return Ok(());
        }
        self.sender.send(phone, code, ttl_secs).await
    }
}

struct Mock;
impl Sender for Mock {
    fn send<'a>(&'a self, phone: &'a str, code: &'a str, _ttl_secs: u64) -> BoxFuture<'a> {
        Box::pin(async move {
            tracing::info!(target: "idp::sms", "[Mock SMS] phone={phone}, code={code}");
            Ok(())
        })
    }
}

struct Aliyun {
    config: SmsConfig,
    client: reqwest::Client,
}
impl Aliyun {
    fn new(config: SmsConfig) -> Self {
        Self {
            client: client(&config),
            config,
        }
    }
}
impl Sender for Aliyun {
    fn send<'a>(&'a self, phone: &'a str, code: &'a str, _ttl_secs: u64) -> BoxFuture<'a> {
        Box::pin(async move {
            let endpoint = self
                .config
                .endpoint
                .as_deref()
                .unwrap_or("dysmsapi.aliyuncs.com");
            let mut params = std::collections::BTreeMap::new();
            params.insert("Action", "SendSms".to_string());
            params.insert("Version", "2017-05-25".to_string());
            params.insert("Format", "JSON".to_string());
            params.insert("PhoneNumbers", phone.trim().to_string());
            params.insert("SignName", self.config.sign_name.trim().to_string());
            params.insert("TemplateCode", self.config.template_code.trim().to_string());
            params.insert(
                "TemplateParam",
                serde_json::json!({"code": code}).to_string(),
            );
            params.insert("AccessKeyId", self.config.access_key_id.trim().to_string());
            params.insert(
                "Timestamp",
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            );
            params.insert("SignatureMethod", "HMAC-SHA1".to_string());
            params.insert("SignatureVersion", "1.0".to_string());
            params.insert("SignatureNonce", uuid::Uuid::new_v4().to_string());
            let canonical = params
                .iter()
                .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            let mut mac = HmacSha1::new_from_slice(
                format!("{}&", self.config.access_key_secret.trim()).as_bytes(),
            )
            .map_err(|e| IdpError::SmsFailed(format!("HMAC init failed: {e}")))?;
            mac.update(format!("GET&{}&{}", encode("/"), encode(&canonical)).as_bytes());
            params.insert(
                "Signature",
                BASE64_STANDARD.encode(mac.finalize().into_bytes()),
            );
            let query = params
                .iter()
                .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            let response = self
                .client
                .get(format!("https://{endpoint}?{query}"))
                .send()
                .await
                .map_err(|e| IdpError::SmsFailed(format!("Aliyun SMS request failed: {e}")))?;
            let status = response.status();
            let body: Value = response
                .json()
                .await
                .map_err(|e| IdpError::SmsFailed(format!("Invalid SMS response: {e}")))?;
            if status.is_success() && body.get("Code").and_then(Value::as_str) == Some("OK") {
                Ok(())
            } else {
                Err(IdpError::SmsFailed(format!(
                    "Aliyun SMS error ({status}): {}",
                    body.get("Message")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown error")
                )))
            }
        })
    }
}

struct Tencent {
    config: SmsConfig,
    client: reqwest::Client,
}
impl Tencent {
    fn new(config: SmsConfig) -> Self {
        Self {
            client: client(&config),
            config,
        }
    }
}
impl Tencent {
    fn endpoint(&self) -> Result<(String, String)> {
        let raw = self
            .config
            .endpoint
            .as_deref()
            .unwrap_or("sms.tencentcloudapi.com");
        if raw.starts_with("http://") || raw.starts_with("https://") {
            let url = Url::parse(raw)
                .map_err(|e| IdpError::SmsFailed(format!("Invalid Tencent endpoint: {e}")))?;
            let host = url
                .host_str()
                .ok_or_else(|| IdpError::SmsFailed("Tencent endpoint has no host".into()))?;
            let host = url
                .port()
                .map_or_else(|| host.to_string(), |port| format!("{host}:{port}"));
            Ok((raw.trim_end_matches('/').to_string(), host))
        } else {
            Ok((format!("https://{raw}"), raw.to_string()))
        }
    }

    async fn send_once(&self, phone: &str, code: &str) -> Result<()> {
        if self.config.sdk_app_id.trim().is_empty()
            || self.config.template_code.trim().is_empty()
            || self.config.sign_name.trim().is_empty()
        {
            return Err(IdpError::SmsFailed(
                "Tencent SMS requires sdk_app_id, template_code and sign_name".into(),
            ));
        }
        let (endpoint, host) = self.endpoint()?;
        let timestamp = chrono::Utc::now().timestamp();
        let date = chrono::DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| IdpError::SmsFailed("Invalid timestamp".into()))?
            .format("%Y-%m-%d")
            .to_string();
        let body = serde_json::to_string(&serde_json::json!({
            "PhoneNumberSet": [normalize_phone(phone)],
            "SmsSdkAppid": self.config.sdk_app_id.trim(),
            "Sign": self.config.sign_name.trim(),
            "TemplateID": self.config.template_code.trim(),
            "TemplateParamSet": [code],
        }))
        .map_err(|e| IdpError::SmsFailed(format!("Serialize Tencent request failed: {e}")))?;
        let content_type = "application/json; charset=utf-8";
        let hashed_body = hex(&Sha256::digest(body.as_bytes()));
        let canonical_headers = format!("content-type:{content_type}\nhost:{host}\n");
        let signed_headers = "content-type;host";
        let canonical_request =
            format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{hashed_body}");
        let scope = format!("{date}/sms/tc3_request");
        let string_to_sign = format!(
            "TC3-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            hex(&Sha256::digest(canonical_request.as_bytes()))
        );
        let date_key = hmac(
            format!("TC3{}", self.config.access_key_secret.trim()).as_bytes(),
            date.as_bytes(),
        );
        let service_key = hmac(&date_key, b"sms");
        let signing_key = hmac(&service_key, b"tc3_request");
        let signature = hex(&hmac(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "TC3-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.config.access_key_id.trim()
        );
        let mut request = self
            .client
            .post(format!("{endpoint}/"))
            .header(HOST, host)
            .header(CONTENT_TYPE, content_type)
            .header(AUTHORIZATION, authorization)
            .header("X-TC-Action", "SendSms")
            .header("X-TC-Version", "2019-07-11")
            .header("X-TC-Timestamp", timestamp.to_string());
        if let Some(region) = &self.config.region {
            request = request.header("X-TC-Region", region);
        }
        let response = request
            .body(body)
            .send()
            .await
            .map_err(|e| IdpError::SmsFailed(format!("Tencent SMS request failed: {e}")))?;
        let status = response.status();
        let body: Value = response
            .json()
            .await
            .map_err(|e| IdpError::SmsFailed(format!("Invalid Tencent SMS response: {e}")))?;
        if !status.is_success() {
            return Err(IdpError::SmsFailed(format!(
                "Tencent SMS HTTP error: {status}"
            )));
        }
        if let Some(error) = body.pointer("/Response/Error") {
            return Err(IdpError::SmsFailed(format!(
                "Tencent SMS {}: {}",
                error
                    .get("Code")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                error
                    .get("Message")
                    .and_then(Value::as_str)
                    .unwrap_or("request failed")
            )));
        }
        let statuses = body
            .pointer("/Response/SendStatusSet")
            .and_then(Value::as_array)
            .ok_or_else(|| IdpError::SmsFailed("Tencent SMS response has no status".into()))?;
        if statuses.iter().all(|item| {
            item.get("Code")
                .and_then(Value::as_str)
                .is_some_and(|code| code.eq_ignore_ascii_case("ok"))
        }) {
            Ok(())
        } else {
            let item = statuses.first().cloned().unwrap_or(Value::Null);
            Err(IdpError::SmsFailed(format!(
                "Tencent SMS {}: {}",
                item.get("Code")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                item.get("Message")
                    .and_then(Value::as_str)
                    .unwrap_or("delivery failed")
            )))
        }
    }
}
impl Sender for Tencent {
    fn send<'a>(&'a self, phone: &'a str, code: &'a str, _ttl_secs: u64) -> BoxFuture<'a> {
        Box::pin(async move {
            let mut last = None;
            for attempt in 0..=self.config.retries {
                match self.send_once(phone, code).await {
                    Ok(()) => return Ok(()),
                    Err(error) => {
                        let retryable = matches!(error, IdpError::SmsFailed(ref text) if text.contains("request failed") || text.contains("HTTP error"));
                        last = Some(error);
                        if !retryable || attempt == self.config.retries {
                            break;
                        }
                    }
                }
            }
            Err(last.unwrap_or_else(|| IdpError::SmsFailed("Tencent SMS failed".into())))
        })
    }
}

fn client(config: &SmsConfig) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs.max(1)))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}
fn normalize_phone(phone: &str) -> String {
    let phone = phone.trim();
    if phone.starts_with('+') {
        phone.to_string()
    } else if phone.starts_with("86") {
        format!("+{phone}")
    } else {
        format!("+86{phone}")
    }
}
fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_mainland_phone() {
        assert_eq!(normalize_phone("13800138000"), "+8613800138000");
        assert_eq!(normalize_phone("8613800138000"), "+8613800138000");
        assert_eq!(normalize_phone("+8613800138000"), "+8613800138000");
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
        assert!(matches!(error, IdpError::SmsFailed(message) if message.contains("sdk_app_id")));
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
