use crate::error::Result;
use crate::pkg::recovery::RecoveryCode;

/// 恢复码认证材料校验。
pub struct Recovery;

impl Recovery {
    pub fn check(code: &str, hashes: &[String]) -> Result<String> {
        RecoveryCode::verify_and_consume(code, hashes)
    }
}
