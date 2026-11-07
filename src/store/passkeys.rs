use crate::error::Result;
use crate::factor::passkey::Passkey;
use async_trait::async_trait;

#[async_trait]
pub trait Passkeys: Send + Sync {
    async fn save(&self, tenant: &str, subject: &str, passkey: Passkey) -> Result<()>;
    async fn find(&self, tenant: &str, credential_id: &str) -> Result<Option<Passkey>>;
    async fn list(&self, tenant: &str, subject: &str) -> Result<Vec<Passkey>>;
    async fn update(
        &self,
        tenant: &str,
        credential_id: &str,
        old_count: u32,
        new_count: u32,
    ) -> Result<bool>;
}
