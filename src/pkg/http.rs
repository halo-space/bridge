use crate::error::{Error, Result};
use serde::de::DeserializeOwned;
use std::time::Duration;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

pub fn client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()
        .map_err(|error| Error::Internal(format!("Build HTTP client failed: {error}")))
}

/// 把 Provider 的网络失败和业务拒绝分开，供 Pipeline 决定是否重试。
pub fn provider(error: reqwest::Error, message: &str) -> Error {
    let text = format!("{message}: {error}");
    let transient = error.is_timeout()
        || error.is_connect()
        || error.is_request()
        || error
            .status()
            .is_some_and(|status| status.is_server_error());
    if transient {
        Error::Transient(text)
    } else {
        Error::OAuthError(text)
    }
}

/// 在解析 Provider JSON 前限制响应大小，避免把异常大的原始资料带入内存。
pub async fn json<T: DeserializeOwned>(response: reqwest::Response, name: &str) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(Error::OAuthError(format!(
            "{name} response exceeds {} bytes",
            MAX_RESPONSE_BYTES
        )));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| provider(error, &format!("Read {name} response failed")))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::OAuthError(format!(
            "{name} response exceeds {} bytes",
            MAX_RESPONSE_BYTES
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| Error::OAuthError(format!("Invalid {name} JSON: {error}")))
}

pub async fn body(response: reqwest::Response, name: &str) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(Error::OAuthError(format!(
            "{name} response exceeds {} bytes",
            MAX_RESPONSE_BYTES
        )));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| provider(error, &format!("Read {name} response failed")))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::OAuthError(format!(
            "{name} response exceeds {} bytes",
            MAX_RESPONSE_BYTES
        )));
    }
    Ok(bytes.to_vec())
}
