use crate::error::Result;
use crate::pkg::totp::Totp as Algorithm;

/// TOTP 认证材料校验。
pub struct Totp;

impl Totp {
    pub fn check(secret: &str, code: &str, timestamp: u64) -> Result<bool> {
        Algorithm::verify_code(secret, code, timestamp)
    }
}
