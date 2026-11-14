use crate::error::Result;
use crate::types::{Identity, TotpBinding};
#[allow(async_fn_in_trait)]
pub trait Factors: Send + Sync {
    async fn find_totp(&self, identity: &Identity) -> Result<Option<TotpBinding>>;
}
