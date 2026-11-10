use crate::pkg::recovery::RecoveryCode;

/// 恢复码签发。
pub struct Recovery;

impl Recovery {
    pub fn codes(count: usize) -> Vec<String> {
        RecoveryCode::generate_batch(count)
    }

    pub fn hashes(codes: &[String]) -> Vec<String> {
        codes
            .iter()
            .map(|code| RecoveryCode::hash_code(code))
            .collect()
    }
}
