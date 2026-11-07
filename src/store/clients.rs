use crate::error::Result;
use crate::types::OAuthClient;
use async_trait::async_trait;

#[async_trait]
pub trait Clients: Send + Sync {
    async fn find_client(&self, client_id: &str) -> Result<Option<OAuthClient>>;
}
