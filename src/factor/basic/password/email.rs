use crate::error::{Error, Result};
use crate::pkg::password::{Codecs, Password};
use crate::store::Users;
use crate::types::User;
use crate::types::{AuthResult, Level, Method};

/// 邮箱 + 密码登录。
pub struct Email;

impl Email {
    pub async fn result<S: Users>(store: &S, email: &str, password: &str) -> Result<AuthResult> {
        let user = Self::authenticate(store, email, password).await?;
        Ok(AuthResult::new(
            user.identity(),
            Method::Password,
            Level::First,
        ))
    }

    pub async fn authenticate<S: Users>(store: &S, email: &str, password: &str) -> Result<User> {
        Self::authenticate_with(store, email, password, &Codecs::default()).await
    }

    pub async fn authenticate_with<S: Users>(
        store: &S,
        email: &str,
        password: &str,
        codecs: &Codecs,
    ) -> Result<User> {
        let user = store
            .find_by_email(email)
            .await?
            .ok_or(Error::InvalidCredentials)?;
        if !user.is_active {
            return Err(Error::UserDisabled);
        }
        if !Password::verify_user_with(password, &user, codecs)? {
            return Err(Error::InvalidCredentials);
        }
        Ok(user)
    }
}
