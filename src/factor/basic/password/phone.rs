use crate::error::{IdpError, Result};
use crate::pkg::password::Password;
use crate::store::{AuthUser, UserStore};
use crate::types::{AuthResult, Level, Method};

/// 手机号 + 密码登录。
pub struct PhonePassword;

impl PhonePassword {
    pub async fn result<S: UserStore>(
        store: &S,
        tenant_id: i64,
        phone: &str,
        password: &str,
    ) -> Result<AuthResult> {
        let user = Self::authenticate(store, tenant_id, phone, password).await?;
        Ok(AuthResult::new(
            user.identity(),
            Method::Password,
            Level::First,
        ))
    }

    pub async fn authenticate<S: UserStore>(
        store: &S,
        tenant_id: i64,
        phone: &str,
        password: &str,
    ) -> Result<AuthUser> {
        let user = store
            .find_by_phone(tenant_id, phone)
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
