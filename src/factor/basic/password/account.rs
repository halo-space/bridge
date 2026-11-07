use crate::error::{IdpError, Result};
use crate::pkg::password::Password;
use crate::store::Users;
use crate::types::AuthUser;
use crate::types::{AuthResult, Level, Method};

/// 账号 + 密码登录。
pub struct Account;

impl Account {
    pub async fn result<S: Users>(
        store: &S,
        tenant_id: i64,
        account: &str,
        password: &str,
    ) -> Result<AuthResult> {
        let user = Self::authenticate(store, tenant_id, account, password).await?;
        Ok(AuthResult::new(
            user.identity(),
            Method::Password,
            Level::First,
        ))
    }

    pub async fn authenticate<S: Users>(
        store: &S,
        tenant_id: i64,
        account: &str,
        password: &str,
    ) -> Result<AuthUser> {
        let user = store
            .find_by_username(tenant_id, account)
            .await?
            .ok_or(IdpError::InvalidCredentials)?;
        if !user.is_active {
            return Err(IdpError::UserDisabled);
        }
        if !Password::verify_user(password, &user)? {
            return Err(IdpError::InvalidCredentials);
        }
        Ok(user)
    }
}
