mod config;
mod profile;

use crate::types::Identity;
use serde_json::Value;

pub use config::OidcConfig;
pub use profile::Profile;

pub struct Provider {
    pub config: OidcConfig,
}

impl Provider {
    pub fn new(config: OidcConfig) -> Self {
        Self { config }
    }

    pub fn profile(&self, claims: &Value) -> Option<Profile> {
        Some(Profile {
            provider: self.config.issuer.clone(),
            subject: claims.get("sub")?.as_str()?.to_string(),
            email: claims
                .get("email")
                .and_then(Value::as_str)
                .map(str::to_string),
            phone: claims
                .get("phone_number")
                .and_then(Value::as_str)
                .map(str::to_string),
            name: claims
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    pub fn identity(&self, claims: &Value) -> Option<Identity> {
        self.profile(claims).map(|profile| profile.identity())
    }
}
