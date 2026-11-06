use rand_core::{OsRng, RngCore};

use crate::error::Result;
use crate::store::{Limits, Secrets};

#[derive(Debug, Clone, Copy)]
pub enum Scene {
    Login,
    Register,
    Email,
    Phone,
    Reset,
    Bind,
}

impl Scene {
    pub fn name(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Register => "register",
            Self::Email => "verify_email",
            Self::Phone => "verify_phone",
            Self::Reset => "reset_password",
            Self::Bind => "bind_factor",
        }
    }
}

/// 一次性验证码签发。
pub struct CodeIssuer;

impl CodeIssuer {
    pub fn key(scene: &str, target: &str) -> String {
        format!("code:{scene}:{target}")
    }

    pub fn scene_key(scene: Scene, target: &str) -> String {
        Self::key(scene.name(), target)
    }

    pub fn code(digits: usize) -> String {
        let digits = digits.clamp(4, 12);
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        let value = u64::from_be_bytes(bytes) % 10u64.pow(digits as u32);
        format!("{value:0width$}", width = digits)
    }

    pub async fn issue<K: Secrets>(kv: &K, key: &str, ttl: u64, digits: usize) -> Result<String> {
        let code = Self::code(digits);
        kv.set(key, &code, ttl).await?;
        Ok(code)
    }

    pub async fn issue_with_rate<K: Secrets, R: Limits>(
        kv: &K,
        rate: &R,
        key: &str,
        rate_key: &str,
        ttl: u64,
        digits: usize,
        limit: u32,
        window_secs: u64,
    ) -> Result<String> {
        if !rate.allow(rate_key, limit, window_secs).await? {
            return Err(crate::error::IdpError::AuthFailed(
                "Rate limit exceeded".into(),
            ));
        }
        Self::issue(kv, key, ttl, digits).await
    }

    pub async fn issue_scene_with_rate<K: Secrets, R: Limits>(
        kv: &K,
        rate: &R,
        scene: Scene,
        target: &str,
        ttl: u64,
        digits: usize,
        limit: u32,
        window_secs: u64,
    ) -> Result<String> {
        let key = Self::scene_key(scene, target);
        let rate_key = format!("{}:{target}", scene.name());
        Self::issue_with_rate(kv, rate, &key, &rate_key, ttl, digits, limit, window_secs).await
    }
}
