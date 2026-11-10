use crate::error::Result;
use crate::pkg::totp::Totp as Algorithm;

/// TOTP Secret 签发。
pub struct Totp;

impl Totp {
    pub fn secret() -> String {
        Algorithm::generate_secret()
    }

    pub fn uri(issuer: &str, account: &str, secret: &str) -> Result<String> {
        Algorithm::generate_otpauth_uri(issuer, account, secret)
    }

    pub fn qr(secret_uri: &str) -> Result<String> {
        Algorithm::generate_qr_data_uri(secret_uri)
    }
}
