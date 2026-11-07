use crate::error::Result;
#[allow(async_fn_in_trait)]
pub trait Limits: Send + Sync {
    async fn allow(&self, key: &str, limit: u32, window_secs: u64) -> Result<bool>;
}
