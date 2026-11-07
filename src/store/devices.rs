use crate::error::Result;
use crate::factor::enterprise::Device;

#[allow(async_fn_in_trait)]
pub trait Devices: Send + Sync {
    async fn save(&self, device: Device) -> Result<()>;
    async fn find(&self, tenant_id: i64, device_id: &str) -> Result<Option<Device>>;
    async fn update(&self, device: Device) -> Result<bool>;
    async fn revoke(&self, tenant_id: i64, device_id: &str) -> Result<bool>;
}
