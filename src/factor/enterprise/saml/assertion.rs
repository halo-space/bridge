use crate::types::Identity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    pub name_id: String,
    pub session_index: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub attributes: serde_json::Value,
    #[serde(default)]
    pub assertion_id: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

impl SamlAssertion {
    pub fn identity(&self) -> Identity {
        let mut identity = Identity::new("saml", &self.name_id);
        if let Some(email) = &self.email {
            identity = identity.email(email);
        }
        if let Some(name) = &self.display_name {
            identity = identity.name(name);
        }
        identity
    }
}
