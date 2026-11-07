use crate::error::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Limits: Send + Sync {
    async fn allow(&self, key: &str, limit: u32, window_secs: u64) -> Result<bool>;
}
