use crate::types::Identity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub provider: String,
    pub subject: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub name: Option<String>,
}

impl Profile {
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
