use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::Engine;
use bcrypt::{DEFAULT_COST, hash as bcrypt_hash, verify as bcrypt_verify};
use pbkdf2::pbkdf2_hmac;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use sm3::Sm3 as Sm3Hash;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::types::User;

/// 密码存储算法。算法标识由应用层随凭证保存，便于逐步升级历史密码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Argon2id,
    Bcrypt,
    Sm3,
    Pbkdf2,
    Custom(u16),
}

impl Algorithm {
    pub fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            1 => Self::Argon2id,
            2 => Self::Bcrypt,
            3 => Self::Sm3,
            4 => Self::Pbkdf2,
            _ => return None,
        })
    }

    pub fn code(self) -> u16 {
        match self {
            Self::Argon2id => 1,
            Self::Bcrypt => 2,
            Self::Sm3 => 3,
            Self::Pbkdf2 => 4,
            Self::Custom(code) => code,
        }
    }
}

/// 密码算法的可插拔实现。
pub trait Codec: Send + Sync {
    fn algorithm(&self) -> Algorithm;
    fn hash(&self, password: &str) -> Result<String>;
    fn verify(&self, password: &str, encoded: &str) -> Result<bool>;
}

/// 可扩展密码算法集合。
///
/// 集合默认注册内置算法；应用可以注册自己的 `Custom(code)`，认证因子
/// 通过 `Password::verify_user_with` 使用同一集合完成校验。
#[derive(Clone)]
pub struct Codecs {
    values: BTreeMap<u16, Arc<dyn Codec>>,
}

impl Codecs {
    pub fn new() -> Self {
        let mut values: BTreeMap<u16, Arc<dyn Codec>> = BTreeMap::new();
        values.insert(Algorithm::Argon2id.code(), Arc::new(Argon2id));
        values.insert(Algorithm::Bcrypt.code(), Arc::new(Bcrypt));
        values.insert(Algorithm::Pbkdf2.code(), Arc::new(Pbkdf2));
        values.insert(Algorithm::Sm3.code(), Arc::new(Sm3));
        Self { values }
    }

    pub fn with<C: Codec + 'static>(mut self, codec: C) -> Self {
        self.values
            .insert(codec.algorithm().code(), Arc::new(codec));
        self
    }

    pub fn register<C: Codec + 'static>(&mut self, codec: C) {
        self.values
            .insert(codec.algorithm().code(), Arc::new(codec));
    }

    pub fn verify(&self, password: &str, encoded: &str, algorithm: Algorithm) -> Result<bool> {
        let codec = self.values.get(&algorithm.code()).ok_or_else(|| {
            Error::AuthFailed(format!(
                "Unsupported password algorithm: {}",
                algorithm.code()
            ))
        })?;
        codec.verify(password, encoded)
    }
}

impl Default for Codecs {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Codecs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Codecs")
            .field("codes", &self.values.keys())
            .finish()
    }
}

/// 当前内置 Argon2id；Bcrypt、SM3、PBKDF2 可按同一接口接入。
#[derive(Debug, Default, Clone, Copy)]
pub struct Argon2id;

impl Codec for Argon2id {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Argon2id
    }

    fn hash(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|err| Error::Internal(format!("Failed to hash password: {err}")))
    }

    fn verify(&self, password: &str, encoded: &str) -> Result<bool> {
        let hash = PasswordHash::new(encoded)
            .map_err(|err| Error::AuthFailed(format!("Invalid password hash: {err}")))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Bcrypt;

impl Codec for Bcrypt {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Bcrypt
    }

    fn hash(&self, password: &str) -> Result<String> {
        bcrypt_hash(password, DEFAULT_COST)
            .map_err(|err| Error::Internal(format!("Failed to hash password: {err}")))
    }

    fn verify(&self, password: &str, encoded: &str) -> Result<bool> {
        bcrypt_verify(password, encoded)
            .map_err(|err| Error::AuthFailed(format!("Invalid password hash: {err}")))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Pbkdf2;

impl Codec for Pbkdf2 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Pbkdf2
    }

    fn hash(&self, password: &str) -> Result<String> {
        const ROUNDS: u32 = 600_000;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut output = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, ROUNDS, &mut output);
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        Ok(format!(
            "$pbkdf2-sha256${ROUNDS}${}${}",
            enc.encode(salt),
            enc.encode(output)
        ))
    }

    fn verify(&self, password: &str, encoded: &str) -> Result<bool> {
        let parts: Vec<&str> = encoded.split('$').collect();
        if parts.len() != 5 || parts[1] != "pbkdf2-sha256" {
            return Err(Error::AuthFailed("Invalid PBKDF2 password hash".into()));
        }
        let rounds: u32 = parts[2]
            .parse()
            .map_err(|_| Error::AuthFailed("Invalid PBKDF2 rounds".into()))?;
        if !(10_000..=5_000_000).contains(&rounds) {
            return Err(Error::AuthFailed("PBKDF2 rounds out of range".into()));
        }
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let salt = enc
            .decode(parts[3])
            .map_err(|_| Error::AuthFailed("Invalid PBKDF2 salt".into()))?;
        if salt.len() != 16 {
            return Err(Error::AuthFailed("Invalid PBKDF2 salt length".into()));
        }
        let expected = enc
            .decode(parts[4])
            .map_err(|_| Error::AuthFailed("Invalid PBKDF2 hash".into()))?;
        if expected.len() != 32 {
            return Err(Error::AuthFailed("Invalid PBKDF2 hash length".into()));
        }
        let mut actual = vec![0u8; expected.len()];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, rounds, &mut actual);
        Ok(same(&actual, &expected))
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Sm3;

impl Codec for Sm3 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Sm3
    }

    fn hash(&self, password: &str) -> Result<String> {
        const ROUNDS: u32 = 100_000;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut digest = [0u8; 32];
        pbkdf2_hmac::<Sm3Hash>(password.as_bytes(), &salt, ROUNDS, &mut digest);
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        Ok(format!(
            "$sm3-pbkdf2${ROUNDS}${}${}",
            enc.encode(salt),
            enc.encode(digest)
        ))
    }

    fn verify(&self, password: &str, encoded: &str) -> Result<bool> {
        let parts: Vec<&str> = encoded.split('$').collect();
        if parts.len() != 5 || parts[1] != "sm3-pbkdf2" {
            return Err(Error::AuthFailed("Invalid SM3 password hash".into()));
        }
        let rounds: u32 = parts[2]
            .parse()
            .map_err(|_| Error::AuthFailed("Invalid SM3 rounds".into()))?;
        if !(10_000..=5_000_000).contains(&rounds) {
            return Err(Error::AuthFailed("SM3 rounds out of range".into()));
        }
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let salt = enc
            .decode(parts[3])
            .map_err(|_| Error::AuthFailed("Invalid SM3 salt".into()))?;
        if salt.len() != 16 {
            return Err(Error::AuthFailed("Invalid SM3 salt length".into()));
        }
        let expected = enc
            .decode(parts[4])
            .map_err(|_| Error::AuthFailed("Invalid SM3 hash".into()))?;
        if expected.len() != 32 {
            return Err(Error::AuthFailed("Invalid SM3 hash length".into()));
        }
        let mut actual = vec![0u8; expected.len()];
        pbkdf2_hmac::<Sm3Hash>(password.as_bytes(), &salt, rounds, &mut actual);
        Ok(same(&actual, &expected))
    }
}

fn same(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for (a, b) in left.iter().zip(right) {
        diff |= usize::from(a ^ b);
    }
    diff == 0
}

pub struct Password;

impl Password {
    pub fn needs_upgrade(stored: Option<u16>, current: Algorithm) -> bool {
        stored != Some(current.code())
    }

    pub fn hash_with<C: Codec>(password: &str, codec: &C) -> Result<String> {
        codec.hash(password)
    }

    pub fn verify_with<C: Codec>(password: &str, encoded: &str, codec: &C) -> Result<bool> {
        codec.verify(password, encoded)
    }

    pub fn hash(password: &str, algorithm: Algorithm) -> Result<String> {
        match algorithm {
            Algorithm::Argon2id => Argon2id.hash(password),
            Algorithm::Bcrypt => Bcrypt.hash(password),
            Algorithm::Pbkdf2 => Pbkdf2.hash(password),
            Algorithm::Sm3 => Sm3.hash(password),
            other => Err(Error::Internal(format!(
                "Password algorithm {} is not registered",
                other.code()
            ))),
        }
    }

    pub fn verify(password: &str, encoded: &str, algorithm: Algorithm) -> Result<bool> {
        match algorithm {
            Algorithm::Argon2id => Argon2id.verify(password, encoded),
            Algorithm::Bcrypt => Bcrypt.verify(password, encoded),
            Algorithm::Pbkdf2 => Pbkdf2.verify(password, encoded),
            Algorithm::Sm3 => Sm3.verify(password, encoded),
            other => Err(Error::Internal(format!(
                "Password algorithm {} is not registered",
                other.code()
            ))),
        }
    }

    pub fn verify_user(password: &str, user: &User) -> Result<bool> {
        let encoded = user
            .password_hash
            .as_deref()
            .ok_or(Error::InvalidCredentials)?;
        let algorithm = match user.password_algorithm {
            None => Algorithm::Argon2id,
            Some(code) => Algorithm::from_code(code).ok_or_else(|| {
                Error::AuthFailed(format!("Unsupported password algorithm: {code}"))
            })?,
        };
        Self::verify(password, encoded, algorithm)
    }

    pub fn verify_user_with(password: &str, user: &User, codecs: &Codecs) -> Result<bool> {
        let encoded = user
            .password_hash
            .as_deref()
            .ok_or(Error::InvalidCredentials)?;
        let algorithm = match user.password_algorithm {
            None => Algorithm::Argon2id,
            Some(code) => Algorithm::from_code(code).unwrap_or(Algorithm::Custom(code)),
        };
        codecs.verify(password, encoded, algorithm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Demo;

    impl Codec for Demo {
        fn algorithm(&self) -> Algorithm {
            Algorithm::Custom(99)
        }

        fn hash(&self, password: &str) -> Result<String> {
            Ok(format!("demo:{password}"))
        }

        fn verify(&self, password: &str, encoded: &str) -> Result<bool> {
            Ok(encoded == format!("demo:{password}"))
        }
    }

    #[test]
    fn custom_codec_can_verify_user() {
        let codecs = Codecs::default().with(Demo);
        let user = User {
            id: 1,
            username: "alice".into(),
            email: None,
            phone: None,
            password_hash: Some("demo:secret".into()),
            password_algorithm: Some(99),
            is_active: true,
        };
        assert!(Password::verify_user_with("secret", &user, &codecs).unwrap());
        assert!(!Password::verify_user_with("wrong", &user, &codecs).unwrap());
    }
}
