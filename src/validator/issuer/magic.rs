use crate::error::Result;
use crate::factor::basic::magic::{MagicLinkConfig, MagicLinkService};
use crate::store::Secrets;

pub struct Magic;

impl Magic {
    pub fn issue(
        config: MagicLinkConfig,
        email: &str,
        user_id: Option<&str>,
        scene: &str,
    ) -> Result<(String, String)> {
        MagicLinkService::new(config).create_magic_link(email, user_id, scene, None)
    }

    pub async fn create<K: Secrets>(
        config: MagicLinkConfig,
        kv: &K,
        email: &str,
        user_id: Option<&str>,
        scene: &str,
    ) -> Result<(String, String)> {
        MagicLinkService::new(config)
            .create(kv, email, user_id, scene, None)
            .await
    }
}
