use crate::audit::AuditEvent;
use crate::error::Result;
#[allow(async_fn_in_trait)]
pub trait Events: Send + Sync {
    /// 持久化安全事件。实现必须以 `event.id` 作为幂等键：重复写入同一 ID
    /// 不得产生重复事件，写入失败必须返回错误供调用方处理。
    async fn record_event(&self, event: &AuditEvent) -> Result<()>;
}
