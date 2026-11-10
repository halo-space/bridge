use crate::error::Result;
use crate::factor::basic::magic::{self, MagicLinkConfig};
use crate::store::Secrets;

pub struct Magic;

impl Magic {
    pub fn issue(
        config: MagicLinkConfig,
        email: &str,
        user_id: Option<&str>,
        scene: &str,
    ) -> Result<(String, String)> {
        let (token, url, _) = magic::issue(&config, email, user_id, scene, None)?;
        Ok((token, url))
    }

    pub async fn create<K: Secrets>(
        config: MagicLinkConfig,
        kv: &K,
        email: &str,
        user_id: Option<&str>,
        scene: &str,
    ) -> Result<(String, String)> {
        let (token, url, payload) = magic::issue(&config, email, user_id, scene, None)?;
        kv.set(&magic::key(&payload), &token, magic::ttl(&payload))
            .await?;
        Ok((token, url))
    }
}
