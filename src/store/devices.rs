use crate::error::Result;
use crate::types::Device;

#[allow(async_fn_in_trait)]
pub trait Devices: Send + Sync {
    async fn save(&self, device: Device) -> Result<()>;
    async fn find(&self, device_id: &str) -> Result<Option<Device>>;
    async fn update(&self, device: Device) -> Result<bool>;
    async fn revoke(&self, device_id: &str) -> Result<bool>;
}
