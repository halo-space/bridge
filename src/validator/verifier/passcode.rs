use super::same;
use crate::error::{IdpError, Result};
use crate::store::KvStore;

/// 一次性验证码校验。
pub struct Passcode;

impl Passcode {
    pub fn check(expected: &str, actual: &str) -> bool {
        same(expected.trim(), actual.trim())
    }

    pub async fn take<K: KvStore>(kv: &K, key: &str, actual: &str) -> Result<()> {
        let expected = kv
            .get(key)
            .await?
            .ok_or(IdpError::InvalidVerificationCode)?;
        if Self::check(&expected, actual) && kv.take_if(key, &expected).await? {
            Ok(())
        } else {
            Err(IdpError::InvalidVerificationCode)
        }
    }
}
