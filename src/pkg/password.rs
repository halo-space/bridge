use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::Engine;
use bcrypt::{DEFAULT_COST, hash as bcrypt_hash, verify as bcrypt_verify};
use digest::Digest;
use pbkdf2::pbkdf2_hmac;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use sm3::Sm3 as Sm3Hash;

use crate::error::{IdpError, Result};
use crate::store::AuthUser;

/// 密码存储算法。算法标识由应用层随凭证保存，便于逐步升级历史密码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAlgorithm {
    Argon2id,
    Bcrypt,
    Sm3,
    Pbkdf2,
    Custom(u16),
}

impl PasswordAlgorithm {
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
pub trait PasswordCodec: Send + Sync {
    fn algorithm(&self) -> PasswordAlgorithm;
    fn hash(&self, password: &str) -> Result<String>;
    fn verify(&self, password: &str, encoded: &str) -> Result<bool>;
}

/// 当前内置 Argon2id；Bcrypt、SM3、PBKDF2 可按同一接口接入。
#[derive(Debug, Default, Clone, Copy)]
pub struct Argon2id;

impl PasswordCodec for Argon2id {
    fn algorithm(&self) -> PasswordAlgorithm {
        PasswordAlgorithm::Argon2id
    }

    fn hash(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|err| IdpError::Internal(format!("Failed to hash password: {err}")))
    }

    fn verify(&self, password: &str, encoded: &str) -> Result<bool> {
        let hash = PasswordHash::new(encoded)
            .map_err(|err| IdpError::AuthFailed(format!("Invalid password hash: {err}")))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Bcrypt;

impl PasswordCodec for Bcrypt {
    fn algorithm(&self) -> PasswordAlgorithm {
        PasswordAlgorithm::Bcrypt
    }

    fn hash(&self, password: &str) -> Result<String> {
        bcrypt_hash(password, DEFAULT_COST)
            .map_err(|err| IdpError::Internal(format!("Failed to hash password: {err}")))
    }

    fn verify(&self, password: &str, encoded: &str) -> Result<bool> {
        bcrypt_verify(password, encoded)
            .map_err(|err| IdpError::AuthFailed(format!("Invalid password hash: {err}")))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Pbkdf2;

impl PasswordCodec for Pbkdf2 {
    fn algorithm(&self) -> PasswordAlgorithm {
        PasswordAlgorithm::Pbkdf2
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
            return Err(IdpError::AuthFailed("Invalid PBKDF2 password hash".into()));
        }
        let rounds: u32 = parts[2]
            .parse()
            .map_err(|_| IdpError::AuthFailed("Invalid PBKDF2 rounds".into()))?;
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let salt = enc
            .decode(parts[3])
            .map_err(|_| IdpError::AuthFailed("Invalid PBKDF2 salt".into()))?;
        let expected = enc
            .decode(parts[4])
            .map_err(|_| IdpError::AuthFailed("Invalid PBKDF2 hash".into()))?;
        let mut actual = vec![0u8; expected.len()];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, rounds, &mut actual);
        Ok(actual == expected)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Sm3;

impl PasswordCodec for Sm3 {
    fn algorithm(&self) -> PasswordAlgorithm {
        PasswordAlgorithm::Sm3
    }

    fn hash(&self, password: &str) -> Result<String> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut hash = Sm3Hash::new();
        hash.update(salt);
        hash.update(password.as_bytes());
        let digest = hash.finalize();
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        Ok(format!("$sm3${}${:x}", enc.encode(salt), digest))
    }

    fn verify(&self, password: &str, encoded: &str) -> Result<bool> {
        let parts: Vec<&str> = encoded.split('$').collect();
        if parts.len() != 4 || parts[1] != "sm3" {
            return Err(IdpError::AuthFailed("Invalid SM3 password hash".into()));
        }
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let salt = enc
            .decode(parts[2])
            .map_err(|_| IdpError::AuthFailed("Invalid SM3 salt".into()))?;
        let mut hash = Sm3Hash::new();
        hash.update(&salt);
        hash.update(password.as_bytes());
        Ok(format!("{:x}", hash.finalize()) == parts[3])
    }
}

pub struct Password;

impl Password {
    pub fn needs_upgrade(stored: Option<u16>, current: PasswordAlgorithm) -> bool {
        stored != Some(current.code())
    }

    pub fn hash_with<C: PasswordCodec>(password: &str, codec: &C) -> Result<String> {
        codec.hash(password)
    }

    pub fn verify_with<C: PasswordCodec>(password: &str, encoded: &str, codec: &C) -> Result<bool> {
        codec.verify(password, encoded)
    }

    pub fn hash(password: &str, algorithm: PasswordAlgorithm) -> Result<String> {
        match algorithm {
            PasswordAlgorithm::Argon2id => Argon2id.hash(password),
            PasswordAlgorithm::Bcrypt => Bcrypt.hash(password),
            PasswordAlgorithm::Pbkdf2 => Pbkdf2.hash(password),
            PasswordAlgorithm::Sm3 => Sm3.hash(password),
            other => Err(IdpError::Internal(format!(
                "Password algorithm {} is not registered",
                other.code()
            ))),
        }
    }

    pub fn verify(password: &str, encoded: &str, algorithm: PasswordAlgorithm) -> Result<bool> {
        match algorithm {
            PasswordAlgorithm::Argon2id => Argon2id.verify(password, encoded),
            PasswordAlgorithm::Bcrypt => Bcrypt.verify(password, encoded),
            PasswordAlgorithm::Pbkdf2 => Pbkdf2.verify(password, encoded),
            PasswordAlgorithm::Sm3 => Sm3.verify(password, encoded),
            other => Err(IdpError::Internal(format!(
                "Password algorithm {} is not registered",
                other.code()
            ))),
        }
    }

    pub fn verify_user(password: &str, user: &AuthUser) -> Result<bool> {
        let encoded = user
            .password_hash
            .as_deref()
            .ok_or(IdpError::InvalidCredentials)?;
        let algorithm = match user.password_algorithm {
            None => PasswordAlgorithm::Argon2id,
            Some(code) => PasswordAlgorithm::from_code(code).ok_or_else(|| {
                IdpError::AuthFailed(format!("Unsupported password algorithm: {code}"))
            })?,
        };
        Self::verify(password, encoded, algorithm)
    }
}
