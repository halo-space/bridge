use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    pub idp_entity_id: String,
    pub idp_sso_url: String,
    pub metadata: String,
    pub sp_entity_id: String,
    pub sp_acs_url: String,
}
