use crate::error::{Error, Result};
#[allow(async_fn_in_trait)]
pub trait Secrets: Send + Sync {
    async fn set(&self, key: &str, val: &str, ttl: u64) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<String>>;
    async fn take(&self, key: &str) -> Result<Option<String>>;
    async fn take_if(&self, key: &str, expected: &str) -> Result<bool>;
    async fn del(&self, key: &str) -> Result<()>;

    /// 原子占用一个短期键。只有键不存在时返回 true，并写入值和过期时间。
    async fn claim(&self, _key: &str, _val: &str, _ttl: u64) -> Result<bool> {
        Err(Error::Unsupported("Atomic claim is not supported".into()))
    }

    /// 原子递增短期失败计数。验证码校验依赖这个操作，存储不支持时应返回 `Unsupported`。
    async fn incr(&self, _key: &str, _ttl: u64) -> Result<u32> {
        Err(Error::Unsupported("Atomic counter is not supported".into()))
    }
}
