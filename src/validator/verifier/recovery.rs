use crate::error::Result;
use crate::pkg::recovery::RecoveryCode;

/// 恢复码认证材料校验。
pub struct Recovery;

impl Recovery {
    pub fn verify(code: &str, hashes: &[String]) -> Result<String> {
        RecoveryCode::verify(code, hashes)
    }
}
