use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use super::same;
use crate::error::{IdpError, Result};

/// PKCE 校验。
pub struct Pkce;

impl Pkce {
    pub fn new() -> (String, String) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
        (verifier, challenge)
    }

    pub fn check(verifier: &str, challenge: &str, method: Option<&str>) -> Result<()> {
        if !Self::valid(verifier) {
            return Err(IdpError::InvalidPkce);
        }
        match method.unwrap_or("plain") {
            "S256" => {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                let computed = URL_SAFE_NO_PAD.encode(hasher.finalize());
                if !same(&computed, challenge) {
                    return Err(IdpError::InvalidPkce);
                }
            }
            "plain" if Self::valid(challenge) && same(verifier, challenge) => {}
            _ => return Err(IdpError::InvalidPkce),
        }
        Ok(())
    }

    fn valid(value: &str) -> bool {
        (43..=128).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
    }
}
