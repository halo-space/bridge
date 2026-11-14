use super::pkce::Pkce;
use super::server::TokenResponse;
use crate::error::{Error, Result};
use crate::store::{Clients, Secrets};
use crate::token::Token;
use crate::types::{AuthCode, Identity, OAuthClient};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: String,
    #[serde(default, skip_serializing)]
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

pub struct Flow;

pub(super) fn secret_eq(expected: &str, actual: &str) -> bool {
    type HmacSha256 = Hmac<Sha256>;
    let mut expected_mac =
        HmacSha256::new_from_slice(b"halo-bridge-client-secret").expect("fixed HMAC key is valid");
    expected_mac.update(expected.as_bytes());
    let expected_digest = expected_mac.finalize().into_bytes();
    let mut actual_mac =
        HmacSha256::new_from_slice(b"halo-bridge-client-secret").expect("fixed HMAC key is valid");
    actual_mac.update(actual.as_bytes());
    actual_mac.verify_slice(&expected_digest).is_ok()
}

mod authorize;
mod code;
mod refresh;
mod revoke;
