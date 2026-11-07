use crate::error::{IdpError, Result};
use crate::store::{Factors, Users};
use crate::types::AuthUser;
use crate::types::{AuthResult, Level, Method};
use crate::validator::verifier::totp::Totp as Verify;

/// 账号 + TOTP 登录。
pub struct Totp;

impl Totp {
    pub async fn result<U: Users, T: Factors>(
        user_store: &U,
        totp_store: &T,
        tenant_id: i64,
        account: &str,
        code: &str,
        timestamp: u64,
    ) -> Result<AuthResult> {
        let user =
            Self::authenticate(user_store, totp_store, tenant_id, account, code, timestamp).await?;
        Ok(AuthResult::new(
            user.identity(),
            Method::Totp,
            Level::Second,
        ))
    }

    pub async fn authenticate<U: Users, T: Factors>(
        user_store: &U,
        totp_store: &T,
        tenant_id: i64,
        account: &str,
        code: &str,
        timestamp: u64,
    ) -> Result<AuthUser> {
        let user = user_store
            .find_by_username(tenant_id, account)
            .await?
            .ok_or(IdpError::InvalidCredentials)?;
        if !user.is_active {
            return Err(IdpError::UserDisabled);
        }

        let binding = totp_store
            .find_totp(tenant_id, user.id)
            .await?
            .ok_or(IdpError::InvalidCredentials)?;
        if !binding.enabled || !Verify::check(&binding.secret, code, timestamp)? {
            return Err(IdpError::InvalidCredentials);
        }

        Ok(user)
    }
}
