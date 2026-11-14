use crate::error::Result;
use crate::factor::basic::magic::{self, MagicLinkConfig};
use crate::store::Secrets;

pub struct Magic;

impl Magic {
    pub fn issue(
        config: MagicLinkConfig,
        email: &str,
        subject: Option<&str>,
        scene: &str,
    ) -> Result<(String, String)> {
        let (token, url, _) = magic::issue(&config, email, subject, scene, None)?;
        Ok((token, url))
    }

    pub async fn create<K: Secrets>(
        config: MagicLinkConfig,
        kv: &K,
        email: &str,
        subject: Option<&str>,
        scene: &str,
    ) -> Result<(String, String)> {
        let (token, url, payload) = magic::issue(&config, email, subject, scene, None)?;
        kv.set(&magic::key(&payload), &token, magic::ttl(&payload))
            .await?;
        Ok((token, url))
    }
}
