use super::*;

impl OidcFlow {
    /// 撤销 Token (RFC 7009 Token Revocation)
    pub async fn revoke_token<K: Secrets>(kv: &K, token: &str, ttl_secs: u64) -> Result<()> {
        let key = format!("token:revoked:{}", token);
        kv.set(&key, "1", ttl_secs).await
    }
    /// 检查 Token 是否已被撤销
    pub async fn is_token_revoked<K: Secrets>(kv: &K, token: &str) -> Result<bool> {
        let key = format!("token:revoked:{}", token);
        let val = kv.get(&key).await?;
        Ok(val.is_some())
    }
}
