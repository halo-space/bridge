use crate::error::Result;
use crate::pkg::totp::Totp;

/// TOTP Secret 签发。
pub struct TotpIssuer;

impl TotpIssuer {
    pub fn secret() -> String {
        Totp::generate_secret()
    }

    pub fn uri(issuer: &str, account: &str, secret: &str) -> Result<String> {
        Totp::generate_otpauth_uri(issuer, account, secret)
    }

    pub fn qr(secret_uri: &str) -> Result<String> {
        Totp::generate_qr_data_uri(secret_uri)
    }
}
