use serde::{Deserialize, Serialize};

/// SAML 元数据的信任方式。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Trust {
    /// 使用调用方固定的元数据签名证书。
    Signed { certs: Vec<String> },
    /// 接受未签名元数据，仅用于明确的兼容场景。
    Unsigned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    pub idp_entity_id: String,
    pub idp_sso_url: String,
    pub metadata: String,
    pub trust: Trust,
    pub sp_entity_id: String,
    pub sp_acs_url: String,
}
