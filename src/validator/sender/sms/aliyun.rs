use super::{BoxFuture, Sender, SmsConfig};
use crate::error::Error;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha1::Sha1;
use std::time::Duration;

type HmacSha1 = Hmac<Sha1>;

pub(crate) struct Aliyun {
    config: SmsConfig,
    client: reqwest::Client,
}
impl Aliyun {
    pub(crate) fn new(config: SmsConfig) -> Self {
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
            .map_err(|e| Error::SmsFailed(format!("HMAC init failed: {e}")))?;
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
                .map_err(|e| Error::SmsFailed(format!("Aliyun SMS request failed: {e}")))?;
            let status = response.status();
            let body: Value = response
                .json()
                .await
                .map_err(|e| Error::SmsFailed(format!("Invalid SMS response: {e}")))?;
            if status.is_success() && body.get("Code").and_then(Value::as_str) == Some("OK") {
                Ok(())
            } else {
                Err(Error::SmsFailed(format!(
                    "Aliyun SMS error ({status}): {}",
                    body.get("Message")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown error")
                )))
            }
        })
    }
}

fn client(config: &SmsConfig) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout.max(1)))
        .build()
        .expect("positive SMS timeout must build an HTTP client")
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
