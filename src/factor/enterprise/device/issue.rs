use super::Device;
use crate::error::Result;
use crate::store::Secrets;

impl Device {
    /// 为设备创建一次性证明 nonce。调用方应把返回值放入认证请求。
    pub async fn issue_nonce<K: Secrets>(&self, kv: &K, ttl_secs: u64) -> Result<String> {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        kv.set(&self.nonce_key(&nonce), "1", ttl_secs.max(1))
            .await?;
        Ok(nonce)
    }
}
