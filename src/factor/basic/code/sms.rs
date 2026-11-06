use crate::error::{IdpError, Result};
use crate::store::{AuthUser, KvStore, UserStore};
use crate::types::{AuthResult, Level, Method};
use crate::validator::issuer::CodeIssuer;
use crate::validator::verifier::passcode::Passcode;

/// 手机号 + 短信验证码登录。
pub struct SmsCode;

impl SmsCode {
    pub async fn result<U: UserStore, K: KvStore>(
        user_store: &U,
        kv: &K,
        tenant_id: i64,
        phone: &str,
        code: &str,
    ) -> Result<AuthResult> {
        let user = Self::authenticate(user_store, kv, tenant_id, phone, code).await?;
        Ok(AuthResult::new(user.identity(), Method::Code, Level::First))
    }

    pub const SCENE: &'static str = "login_sms";

    pub async fn authenticate<U: UserStore, K: KvStore>(
        user_store: &U,
        kv: &K,
        tenant_id: i64,
        phone: &str,
        code: &str,
    ) -> Result<AuthUser> {
        let key = CodeIssuer::key(Self::SCENE, phone);
        Passcode::take(kv, &key, code).await?;

        let user = user_store
            .find_by_phone(tenant_id, phone)
            .await?
            .ok_or(IdpError::UserNotFound)?;
        if !user.is_active {
            return Err(IdpError::UserDisabled);
        }
        Ok(user)
    }
}
