use crate::error::Result;
#[allow(async_fn_in_trait)]
pub trait Secrets: Send + Sync {
    async fn set(&self, key: &str, val: &str, ttl: u64) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<String>>;
    async fn take(&self, key: &str) -> Result<Option<String>>;
    async fn take_if(&self, key: &str, expected: &str) -> Result<bool>;
    async fn del(&self, key: &str) -> Result<()>;
}
