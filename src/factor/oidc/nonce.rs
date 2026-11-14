use super::same;
use crate::error::{Error, Result};
use crate::store::Secrets;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};

/// OIDC nonce 校验。
pub struct Nonce;

impl Nonce {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> String {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn check(expected: &str, actual: &str) -> Result<()> {
        if expected.is_empty() || !same(expected, actual) {
            return Err(Error::AuthFailed("Invalid nonce".into()));
        }
        Ok(())
    }

    /// 原子校验并消费调用方保存的 nonce。
    pub async fn take<K: Secrets>(kv: &K, key: &str, actual: &str) -> Result<()> {
        if actual.is_empty() || !kv.take_if(key, actual).await? {
            return Err(Error::AuthFailed("Invalid or used nonce".into()));
        }
        Ok(())
    }
}
