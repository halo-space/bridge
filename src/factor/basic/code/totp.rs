use crate::error::{Error, Result};
use crate::store::{Factors, Users};
use crate::types::User;
use crate::types::{AuthResult, Level, Method};
use crate::validator::verifier::totp::Totp as Verify;

/// 账号 + TOTP 登录。
pub struct Totp;

impl Totp {
    pub async fn result<U: Users, T: Factors>(
        user_store: &U,
        totp_store: &T,
        account: &str,
        code: &str,
        timestamp: u64,
    ) -> Result<AuthResult> {
        let user = Self::authenticate(user_store, totp_store, account, code, timestamp).await?;
        Ok(AuthResult::new(
            user.identity(),
            Method::Totp,
            Level::Second,
        ))
    }

    pub async fn authenticate<U: Users, T: Factors>(
        user_store: &U,
        totp_store: &T,
        account: &str,
        code: &str,
        timestamp: u64,
    ) -> Result<User> {
        let user = user_store
            .find_by_username(account)
            .await?
            .ok_or(Error::InvalidCredentials)?;
        if !user.is_active {
            return Err(Error::UserDisabled);
        }

        let binding = totp_store
            .find_totp(user.id)
            .await?
            .ok_or(Error::InvalidCredentials)?;
        if !binding.enabled || !Verify::check(&binding.secret, code, timestamp)? {
            return Err(Error::InvalidCredentials);
        }

        Ok(user)
    }
}
