use crate::error::Result;
use crate::factor::passkey::Passkey;
#[allow(async_fn_in_trait)]
pub trait Passkeys: Send + Sync {
    async fn save(&self, tenant: &str, subject: &str, passkey: Passkey) -> Result<()>;
    async fn find(&self, tenant: &str, credential_id: &str) -> Result<Option<Passkey>>;
    async fn list(&self, tenant: &str, subject: &str) -> Result<Vec<Passkey>>;
    /// 使用旧计数器做 CAS，并原子保存完整凭证状态。
    async fn update(
        &self,
        tenant: &str,
        credential_id: &str,
        old_count: u32,
        passkey: Passkey,
    ) -> Result<bool>;
}
