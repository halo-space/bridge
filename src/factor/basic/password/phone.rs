use crate::error::{Error, Result};
use crate::pkg::password::{Codecs, Password};
use crate::store::Users;
use crate::types::User;
use crate::types::{AuthResult, Level, Method};

/// 手机号 + 密码登录。
pub struct Phone;

impl Phone {
    pub async fn result<S: Users>(store: &S, phone: &str, password: &str) -> Result<AuthResult> {
        let user = Self::authenticate(store, phone, password).await?;
        Ok(AuthResult::new(
            user.identity(),
            Method::Password,
            Level::First,
        ))
    }

    pub async fn authenticate<S: Users>(store: &S, phone: &str, password: &str) -> Result<User> {
        Self::authenticate_with(store, phone, password, &Codecs::default()).await
    }

    pub async fn authenticate_with<S: Users>(
        store: &S,
        phone: &str,
        password: &str,
        codecs: &Codecs,
    ) -> Result<User> {
        let user = store
            .find_by_phone(phone)
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
