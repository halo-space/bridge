mod config;
mod profile;

use crate::error::{Error, Result};
use crate::types::Identity;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use url::Url;

pub use config::Config;
pub use profile::Profile;

/// 外部 OIDC Provider 的 Discovery 文档和已读取的签名密钥。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(skip)]
    pub jwks: crate::token::JwksResponse,
}

pub struct Provider {
    pub config: Config,
    timeout: Duration,
}

impl Provider {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            timeout: Duration::from_secs(15),
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout.max(Duration::from_secs(1));
        self
    }

    /// 构造第三方 OIDC 授权地址。state、nonce 和 PKCE verifier 由调用方保存。
    pub fn authorize_url(
        &self,
        state: &str,
        redirect_uri: &str,
        nonce: Option<&str>,
        code_challenge: Option<&str>,
        code_challenge_method: Option<&str>,
    ) -> Result<String> {
        let endpoint = self
            .config
            .authorization_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/authorize", self.config.issuer.trim_end_matches('/')));
        let mut url =
            Url::parse(&endpoint).map_err(|error| Error::OAuthError(error.to_string()))?;
        let scope = self
            .config
            .scope
            .as_deref()
            .unwrap_or("openid profile email");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", scope)
            .append_pair("state", state);
        if let Some(value) = nonce {
            url.query_pairs_mut().append_pair("nonce", value);
        }
        if let Some(value) = code_challenge {
            url.query_pairs_mut().append_pair("code_challenge", value);
        }
        if let Some(value) = code_challenge_method {
            url.query_pairs_mut()
                .append_pair("code_challenge_method", value);
        }
        Ok(url.to_string())
    }

    /// 使用已读取的 Discovery 文档构造授权地址。
    pub fn authorize_url_with(
        &self,
        discovery: &Discovery,
        state: &str,
        redirect_uri: &str,
        nonce: Option<&str>,
        code_challenge: Option<&str>,
        code_challenge_method: Option<&str>,
    ) -> Result<String> {
        if discovery.issuer != self.config.issuer {
            return Err(Error::OAuthError("OIDC discovery issuer mismatch".into()));
        }
        let mut config = self.config.clone();
        config.authorization_endpoint = Some(discovery.authorization_endpoint.clone());
        Self {
            config,
            timeout: self.timeout,
        }
        .authorize_url(
            state,
            redirect_uri,
            nonce,
            code_challenge,
            code_challenge_method,
        )
    }

    /// 校验第三方 ID Token，并返回已验证的 Profile。
    pub fn verify_id(
        &self,
        token: &str,
        discovery: &Discovery,
        nonce: Option<&str>,
    ) -> Result<Profile> {
        if discovery.issuer != self.config.issuer {
            return Err(Error::OAuthError("OIDC discovery issuer mismatch".into()));
        }
        let header = decode_header(token)
            .map_err(|error| Error::OAuthError(format!("Invalid OIDC ID token header: {error}")))?;
        if header.alg != Algorithm::RS256 {
            return Err(Error::OAuthError("OIDC ID token must use RS256".into()));
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| Error::OAuthError("OIDC ID token missing kid".into()))?;
        let key = discovery
            .jwks
            .keys
            .iter()
            .find(|key| key.kid == kid && key.kty == "RSA" && key.alg == "RS256")
            .ok_or_else(|| Error::OAuthError("OIDC signing key not found".into()))?;
        let n = key
            .n
            .as_deref()
            .ok_or_else(|| Error::OAuthError("OIDC signing key missing modulus".into()))?;
        let e = key
            .e
            .as_deref()
            .ok_or_else(|| Error::OAuthError("OIDC signing key missing exponent".into()))?;
        let decoding = DecodingKey::from_rsa_components(n, e)
            .map_err(|error| Error::OAuthError(format!("Invalid OIDC signing key: {error}")))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[discovery.issuer.as_str()]);
        validation.set_audience(&[self.config.client_id.as_str()]);
        validation.leeway = 0;
        validation.validate_exp = true;
        let data = decode::<Value>(token, &decoding, &validation)
            .map_err(|error| Error::OAuthError(format!("Invalid OIDC ID token: {error}")))?;
        if let Some(expected) = nonce
            && data.claims.get("nonce").and_then(Value::as_str) != Some(expected)
        {
            return Err(Error::OAuthError("OIDC ID token nonce mismatch".into()));
        }
        self.profile(&data.claims)
            .ok_or_else(|| Error::OAuthError("OIDC ID token missing sub".into()))
    }

    /// 读取 Discovery 和 JWKS，供调用方缓存或审计使用。
    #[cfg(feature = "oidc")]
    pub async fn discovery(&self) -> Result<Discovery> {
        let http = crate::pkg::http::client(self.timeout)?;
        let endpoint = self.config.discovery_endpoint.clone().unwrap_or_else(|| {
            format!(
                "{}/.well-known/openid-configuration",
                self.config.issuer.trim_end_matches('/')
            )
        });
        let document: Discovery = crate::pkg::http::json(
            http.get(endpoint)
                .send()
                .await
                .map_err(|error| {
                    crate::pkg::http::provider(error, "OIDC discovery request failed")
                })?
                .error_for_status()
                .map_err(|error| crate::pkg::http::provider(error, "OIDC discovery HTTP error"))?,
            "OIDC discovery",
        )
        .await?;
        if document.issuer != self.config.issuer {
            return Err(Error::OAuthError("OIDC discovery issuer mismatch".into()));
        }
        let jwks_endpoint = self
            .config
            .jwks_endpoint
            .clone()
            .unwrap_or_else(|| document.jwks_uri.clone());
        let jwks: crate::token::JwksResponse = crate::pkg::http::json(
            http.get(jwks_endpoint)
                .send()
                .await
                .map_err(|error| crate::pkg::http::provider(error, "OIDC JWKS request failed"))?
                .error_for_status()
                .map_err(|error| crate::pkg::http::provider(error, "OIDC JWKS HTTP error"))?,
            "OIDC JWKS",
        )
        .await?;
        Ok(Discovery { jwks, ..document })
    }

    /// 使用 authorization code 换取并校验第三方身份。
    #[cfg(feature = "oidc")]
    pub async fn exchange_code_for_profile(
        &self,
        code: &str,
        redirect_uri: &str,
        verifier: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<Profile> {
        let discovery = self.discovery().await?;
        let endpoint = self
            .config
            .token_endpoint
            .clone()
            .unwrap_or_else(|| discovery.token_endpoint.clone());
        let http = crate::pkg::http::client(self.timeout)?;
        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", redirect_uri.to_string()),
            ("client_id", self.config.client_id.clone()),
        ];
        if !self.config.client_secret.is_empty() {
            form.push(("client_secret", self.config.client_secret.clone()));
        }
        if let Some(value) = verifier {
            form.push(("code_verifier", value.to_string()));
        }
        let response: Value = crate::pkg::http::json(
            http.post(endpoint)
                .form(&form)
                .send()
                .await
                .map_err(|error| crate::pkg::http::provider(error, "OIDC token request failed"))?
                .error_for_status()
                .map_err(|error| crate::pkg::http::provider(error, "OIDC token HTTP error"))?,
            "OIDC token",
        )
        .await?;
        let id_token = response
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::OAuthError("OIDC token response missing id_token".into()))?;
        self.verify_id(id_token, &discovery, nonce)
    }

    pub fn profile(&self, claims: &Value) -> Option<Profile> {
        Some(Profile {
            provider: self.config.issuer.clone(),
            subject: claims.get("sub")?.as_str()?.to_string(),
            email: claims
                .get("email")
                .and_then(Value::as_str)
                .map(str::to_string),
            phone: claims
                .get("phone_number")
                .and_then(Value::as_str)
                .map(str::to_string),
            name: claims
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    pub fn identity(&self, claims: &Value) -> Option<Identity> {
        self.profile(claims).map(|profile| profile.identity())
    }
}
