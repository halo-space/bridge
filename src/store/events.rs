use crate::audit::AuditEvent;
use crate::error::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Events: Send + Sync {
    async fn record_event(&self, event: &AuditEvent) -> Result<()>;
}
