use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    pub issuer: String,
    pub client_id: String,
    #[serde(default, skip_serializing)]
    pub client_secret: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub discovery_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_endpoint: Option<String>,
}
