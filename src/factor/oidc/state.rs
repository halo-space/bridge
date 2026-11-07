use super::same;
use crate::error::{IdpError, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};

/// OAuth state 校验。
pub struct State;

impl State {
    pub fn new() -> String {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn check(expected: &str, actual: &str) -> Result<()> {
        if expected.is_empty() || !same(expected, actual) {
            return Err(IdpError::AuthFailed("Invalid state".into()));
        }
        Ok(())
    }
}
