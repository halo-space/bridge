use crate::error::{IdpError, Result};
use crate::store::{AuthUser, Secrets, Users};
use crate::types::{AuthResult, Level, Method};
use crate::validator::issuer::CodeIssuer;
use crate::validator::verifier::passcode::Passcode;

/// 邮箱 + 一次性验证码登录。
pub struct EmailCode;

impl EmailCode {
    pub async fn result<U: Users, K: Secrets>(
        user_store: &U,
        kv: &K,
        tenant_id: i64,
        email: &str,
        code: &str,
    ) -> Result<AuthResult> {
        let user = Self::authenticate(user_store, kv, tenant_id, email, code).await?;
        Ok(AuthResult::new(user.identity(), Method::Code, Level::First))
    }

    pub const SCENE: &'static str = "login_email";

    pub async fn authenticate<U: Users, K: Secrets>(
        user_store: &U,
        kv: &K,
        tenant_id: i64,
        email: &str,
        code: &str,
    ) -> Result<AuthUser> {
        let key = CodeIssuer::key(Self::SCENE, email);
        Passcode::take(kv, &key, code).await?;

        let user = user_store
            .find_by_email(tenant_id, email)
            .await?
            .ok_or(IdpError::UserNotFound)?;
        if !user.is_active {
            return Err(IdpError::UserDisabled);
        }
        Ok(user)
    }
}
