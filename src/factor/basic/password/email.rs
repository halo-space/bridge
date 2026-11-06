use crate::error::{IdpError, Result};
use crate::pkg::password::Password;
use crate::store::{AuthUser, Users};
use crate::types::{AuthResult, Level, Method};

/// 邮箱 + 密码登录。
pub struct EmailPassword;

impl EmailPassword {
    pub async fn result<S: Users>(
        store: &S,
        tenant_id: i64,
        email: &str,
        password: &str,
    ) -> Result<AuthResult> {
        let user = Self::authenticate(store, tenant_id, email, password).await?;
        Ok(AuthResult::new(
            user.identity(),
            Method::Password,
            Level::First,
        ))
    }

    pub async fn authenticate<S: Users>(
        store: &S,
        tenant_id: i64,
        email: &str,
        password: &str,
    ) -> Result<AuthUser> {
        let user = store
            .find_by_email(tenant_id, email)
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
