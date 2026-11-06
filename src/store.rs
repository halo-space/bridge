use crate::audit::AuditEvent;
use crate::error::Result;
use crate::factor::passkey::Passkey;
use crate::types::Identity;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// 认证通过后的标准用户载荷
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: i64,
    pub tenant_id: i64,
    pub username: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password_hash: Option<String>,
    #[serde(default)]
    pub password_algorithm: Option<u16>,
    pub is_active: bool,
}

impl AuthUser {
    pub fn identity(&self) -> Identity {
        let mut identity = Identity::new("local", self.id.to_string()).name(&self.username);
        if let Some(email) = &self.email {
            identity = identity.email(email);
        }
        if let Some(phone) = &self.phone {
            identity = identity.phone(phone);
        }
        identity
    }
}

/// OIDC / OAuth2 客户端注册信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub scope: String,
    pub is_public: bool,
}

/// 临时授权码（Authorization Code）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCode {
    pub code: String,
    pub client_id: String,
    pub user_id: i64,
    pub tenant_id: i64,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    pub expires_at: i64,
}

/// 用户已绑定的 TOTP 信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpBinding {
    pub secret: String,
    pub enabled: bool,
}

/// 用户存储契约（由具体数据库如 PostgreSQL 实现）
#[async_trait]
pub trait Users: Send + Sync {
    async fn find_by_username(&self, tenant_id: i64, username: &str) -> Result<Option<AuthUser>>;
    async fn find_by_phone(&self, tenant_id: i64, phone: &str) -> Result<Option<AuthUser>>;
    async fn find_by_email(&self, tenant_id: i64, email: &str) -> Result<Option<AuthUser>>;
    async fn find_by_id(&self, id: i64) -> Result<Option<AuthUser>>;
}

/// TOTP 绑定存储契约，由应用层实现具体持久化和 Secret 保护。
#[async_trait]
pub trait Factors: Send + Sync {
    async fn find_totp(&self, tenant_id: i64, user_id: i64) -> Result<Option<TotpBinding>>;
}

/// OAuth 客户端应用存储契约
#[async_trait]
pub trait Clients: Send + Sync {
    async fn find_client(&self, client_id: &str) -> Result<Option<OAuthClient>>;
}

/// 通用键值缓存存储契约 (由 Redis 实现，处理验证码/Token/临时凭证的原子读写与单次消费)
#[async_trait]
pub trait Secrets: Send + Sync {
    /// 存储值并设置超时时间 (秒)
    async fn set(&self, key: &str, val: &str, ttl: u64) -> Result<()>;
    /// 获取值
    async fn get(&self, key: &str) -> Result<Option<String>>;
    /// 取出并立即删除（单次有效防重放）
    async fn take(&self, key: &str) -> Result<Option<String>>;
    /// 按值匹配并单次消费。实现必须提供原子 compare-and-delete 语义。
    async fn take_if(&self, key: &str, expected: &str) -> Result<bool>;
    /// 删除指定键
    async fn del(&self, key: &str) -> Result<()>;
}

/// 频率限制存储契约。
#[async_trait]
pub trait Limits: Send + Sync {
    async fn allow(&self, key: &str, limit: u32, window_secs: u64) -> Result<bool>;
}

/// FIDO2 / Passkey 生物凭据存储契约
#[async_trait]
pub trait Passkeys: Send + Sync {
    /// 保存新注册的 Passkey。实现应对 Credential ID 建立唯一约束。
    async fn save(&self, tenant: &str, subject: &str, passkey: Passkey) -> Result<()>;
    /// 根据租户和 Credential ID 获取 Passkey。
    async fn find(&self, tenant: &str, credential_id: &str) -> Result<Option<Passkey>>;
    /// 获取 subject 的全部 Passkey。
    async fn list(&self, tenant: &str, subject: &str) -> Result<Vec<Passkey>>;
    /// 认证成功后按旧值条件更新签名计数器，避免并发覆盖。
    async fn update(
        &self,
        tenant: &str,
        credential_id: &str,
        old_count: u32,
        new_count: u32,
    ) -> Result<bool>;
}

/// 安全审计事件持久化存储契约
#[async_trait]
pub trait Events: Send + Sync {
    /// 记录单条安全审计事件
    async fn record_event(&self, event: &AuditEvent) -> Result<()>;
}
