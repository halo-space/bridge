use crate::error::Result;
use crate::types::Passkey;
#[allow(async_fn_in_trait)]
pub trait Passkeys: Send + Sync {
    async fn save(&self, subject: &str, passkey: Passkey) -> Result<()>;
    async fn find(&self, credential_id: &str) -> Result<Option<Passkey>>;
    async fn list(&self, subject: &str) -> Result<Vec<Passkey>>;
    /// 使用旧计数器做 CAS，并原子保存完整凭证状态。
    async fn update(&self, credential_id: &str, old_count: u32, passkey: Passkey) -> Result<bool>;
}
