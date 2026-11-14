pub mod claims;
pub mod jwks;
pub mod service;

use sha2::{Digest, Sha256};

pub use claims::Claims;
pub use jwks::{JwkKey, JwksResponse};
pub use service::Token;

pub(crate) fn revoke_key(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let value = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("token:revoked:{value}")
}

pub(crate) fn refresh_key(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let value = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("token:refresh:{value}")
}
