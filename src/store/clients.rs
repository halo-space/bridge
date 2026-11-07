use crate::error::Result;
use crate::types::OAuthClient;
#[allow(async_fn_in_trait)]
pub trait Clients: Send + Sync {
    async fn find_client(&self, tenant_id: i64, client_id: &str) -> Result<Option<OAuthClient>>;
}
