use super::{BoxFuture, Sender, SmsConfig};
use crate::error::{Error, Result};
use hmac::{Hmac, Mac};
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct Tencent {
    config: SmsConfig,
    client: reqwest::Client,
}
impl Tencent {
    pub(crate) fn new(config: SmsConfig) -> Self {
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
                .map_err(|e| Error::SmsFailed(format!("Invalid Tencent endpoint: {e}")))?;
            let host = url
                .host_str()
                .ok_or_else(|| Error::SmsFailed("Tencent endpoint has no host".into()))?;
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
            return Err(Error::SmsFailed(
                "Tencent SMS requires sdk_app_id, template_code and sign_name".into(),
            ));
        }
        let (endpoint, host) = self.endpoint()?;
        let timestamp = chrono::Utc::now().timestamp();
        let date = chrono::DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| Error::SmsFailed("Invalid timestamp".into()))?
            .format("%Y-%m-%d")
            .to_string();
        let body = serde_json::to_string(&serde_json::json!({
            "PhoneNumberSet": [normalize_phone(phone)],
            "SmsSdkAppid": self.config.sdk_app_id.trim(),
            "Sign": self.config.sign_name.trim(),
            "TemplateID": self.config.template_code.trim(),
            "TemplateParamSet": [code],
        }))
        .map_err(|e| Error::SmsFailed(format!("Serialize Tencent request failed: {e}")))?;
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
            .map_err(|e| Error::SmsFailed(format!("Tencent SMS request failed: {e}")))?;
        let status = response.status();
        let body: Value = response
            .json()
            .await
            .map_err(|e| Error::SmsFailed(format!("Invalid Tencent SMS response: {e}")))?;
        if !status.is_success() {
            return Err(Error::SmsFailed(format!(
                "Tencent SMS HTTP error: {status}"
            )));
        }
        if let Some(error) = body.pointer("/Response/Error") {
            return Err(Error::SmsFailed(format!(
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
            .ok_or_else(|| Error::SmsFailed("Tencent SMS response has no status".into()))?;
        if statuses.iter().all(|item| {
            item.get("Code")
                .and_then(Value::as_str)
                .is_some_and(|code| code.eq_ignore_ascii_case("ok"))
        }) {
            Ok(())
        } else {
            let item = statuses.first().cloned().unwrap_or(Value::Null);
            Err(Error::SmsFailed(format!(
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
                        let retryable = matches!(error, Error::SmsFailed(ref text) if text.contains("request failed") || text.contains("HTTP error"));
                        last = Some(error);
                        if !retryable || attempt == self.config.retries {
                            break;
                        }
                    }
                }
            }
            Err(last.unwrap_or_else(|| Error::SmsFailed("Tencent SMS failed".into())))
        })
    }
}

fn client(config: &SmsConfig) -> Client {
    Client::builder()
        .timeout(Duration::from_secs(config.timeout.max(1)))
        .build()
        .expect("positive SMS timeout must build an HTTP client")
}
pub(crate) fn normalize_phone(phone: &str) -> String {
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
