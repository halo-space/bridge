use crate::error::Result;
use crate::factor::basic::magic::{MagicLinkConfig, MagicLinkPayload, MagicLinkService};
use crate::store::KvStore;

pub struct Magic;

impl Magic {
    pub fn check(config: MagicLinkConfig, token: &str) -> Result<MagicLinkPayload> {
        MagicLinkService::new(config).verify_token(token)
    }

    pub async fn take<K: KvStore>(
        config: MagicLinkConfig,
        kv: &K,
        token: &str,
    ) -> Result<MagicLinkPayload> {
        MagicLinkService::new(config).take(kv, token).await
    }
}
