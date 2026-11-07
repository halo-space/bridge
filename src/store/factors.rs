use crate::error::Result;
use crate::types::TotpBinding;
#[allow(async_fn_in_trait)]
pub trait Factors: Send + Sync {
    async fn find_totp(&self, tenant_id: i64, user_id: i64) -> Result<Option<TotpBinding>>;
}
