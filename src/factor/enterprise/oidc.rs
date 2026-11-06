use serde::{Deserialize, Serialize};

use crate::types::Identity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
}

pub struct OidcProvider {
    pub config: OidcConfig,
}

impl OidcProvider {
    pub fn new(config: OidcConfig) -> Self {
        Self { config }
    }

    pub fn profile(&self, claims: &serde_json::Value) -> Option<OidcProfile> {
        Some(OidcProfile {
            provider: self.config.issuer.clone(),
            subject: claims.get("sub")?.as_str()?.to_string(),
            email: claims
                .get("email")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            phone: claims
                .get("phone_number")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            name: claims
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        })
    }

    pub fn identity(&self, claims: &serde_json::Value) -> Option<Identity> {
        self.profile(claims).map(|profile| profile.identity())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProfile {
    pub provider: String,
    pub subject: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub name: Option<String>,
}

impl OidcProfile {
    pub fn identity(&self) -> Identity {
        let mut identity = Identity::new(&self.provider, &self.subject);
        if let Some(email) = &self.email {
            identity = identity.email(email);
        }
        if let Some(phone) = &self.phone {
            identity = identity.phone(phone);
        }
        if let Some(name) = &self.name {
            identity = identity.name(name);
        }
        identity
    }
}
