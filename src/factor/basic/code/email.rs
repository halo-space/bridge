use crate::error::{Error, Result};
use crate::store::{Secrets, Users};
use crate::types::User;
use crate::types::{AuthResult, Level, Method};
use crate::validator::issuer::Code;
use crate::validator::verifier::passcode::Passcode;

/// 邮箱 + 一次性验证码登录。
pub struct Email;

impl Email {
    pub async fn result<U: Users, K: Secrets>(
        user_store: &U,
        kv: &K,
        email: &str,
        code: &str,
    ) -> Result<AuthResult> {
        let user = Self::authenticate(user_store, kv, email, code).await?;
        Ok(AuthResult::new(user.identity(), Method::Code, Level::First))
    }

    pub const SCENE: &'static str = "login_email";

    pub async fn authenticate<U: Users, K: Secrets>(
        user_store: &U,
        kv: &K,
        email: &str,
        code: &str,
    ) -> Result<User> {
        Self::authenticate_scene(user_store, kv, email, code, Self::SCENE).await
    }

    pub async fn authenticate_scene<U: Users, K: Secrets>(
        user_store: &U,
        kv: &K,
        email: &str,
        code: &str,
        scene: &str,
    ) -> Result<User> {
        let key = Code::key(scene, email);
        Passcode::take(kv, &key, code).await?;

        let user = user_store
            .find_by_email(email)
            .await?
            .ok_or(Error::UserNotFound)?;
        if !user.is_active {
            return Err(Error::UserDisabled);
        }
        Ok(user)
    }
}
