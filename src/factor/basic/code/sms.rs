use crate::error::{Error, Result};
use crate::store::{Secrets, Users};
use crate::types::User;
use crate::types::{AuthResult, Level, Method};
use crate::validator::issuer::CodeIssuer;
use crate::validator::verifier::passcode::Passcode;

/// 手机号 + 短信验证码登录。
pub struct Sms;

impl Sms {
    pub async fn result<U: Users, K: Secrets>(
        user_store: &U,
        kv: &K,
        phone: &str,
        code: &str,
    ) -> Result<AuthResult> {
        let user = Self::authenticate(user_store, kv, phone, code).await?;
        Ok(AuthResult::new(user.identity(), Method::Code, Level::First))
    }

    pub const SCENE: &'static str = "login_sms";

    pub async fn authenticate<U: Users, K: Secrets>(
        user_store: &U,
        kv: &K,
        phone: &str,
        code: &str,
    ) -> Result<User> {
        let key = CodeIssuer::key(Self::SCENE, phone);
        Passcode::take(kv, &key, code).await?;

        let user = user_store
            .find_by_phone(phone)
            .await?
            .ok_or(Error::UserNotFound)?;
        if !user.is_active {
            return Err(Error::UserDisabled);
        }
        Ok(user)
    }
}
