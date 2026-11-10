use crate::error::Result;
use crate::factor::basic::magic::{self, MagicLinkConfig, MagicLinkPayload};
use crate::store::Secrets;

pub struct Magic;

impl Magic {
    pub fn verify(config: MagicLinkConfig, token: &str) -> Result<MagicLinkPayload> {
        magic::verify(&config, token)
    }

    pub async fn take<K: Secrets>(
        config: MagicLinkConfig,
        kv: &K,
        token: &str,
    ) -> Result<MagicLinkPayload> {
        let payload = magic::verify(&config, token)?;
        if !kv.take_if(&magic::key(&payload), token).await? {
            return Err(crate::error::Error::MagicLinkError(
                "Magic link already used or not issued".into(),
            ));
        }
        Ok(payload)
    }
}
