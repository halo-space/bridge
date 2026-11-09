use crate::error::Result;
use crate::types::User;
#[allow(async_fn_in_trait)]
pub trait Users: Send + Sync {
    async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn find_by_phone(&self, phone: &str) -> Result<Option<User>>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>>;
    async fn find_by_id(&self, id: i64) -> Result<Option<User>>;
}
