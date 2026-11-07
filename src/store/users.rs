use crate::error::Result;
use crate::types::AuthUser;
use async_trait::async_trait;

#[async_trait]
pub trait Users: Send + Sync {
    async fn find_by_username(&self, tenant_id: i64, username: &str) -> Result<Option<AuthUser>>;
    async fn find_by_phone(&self, tenant_id: i64, phone: &str) -> Result<Option<AuthUser>>;
    async fn find_by_email(&self, tenant_id: i64, email: &str) -> Result<Option<AuthUser>>;
    async fn find_by_id(&self, id: i64) -> Result<Option<AuthUser>>;
}
