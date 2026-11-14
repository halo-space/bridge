pub use crate::types::Device;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod issue;
mod verify;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProof {
    pub device_id: String,
    pub nonce: String,
    pub at: i64,
    pub signature: String,
}

impl Device {
    pub fn new(
        id: impl Into<String>,
        subject: impl Into<String>,
        name: impl Into<String>,
        public_key: impl Into<String>,
        at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            subject: subject.into(),
            name: name.into(),
            public_key: public_key.into(),
            enabled: true,
            created_at: at,
            last_used_at: None,
        }
    }

    pub fn revoke(&mut self) {
        self.enabled = false;
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn nonce_key(&self, nonce: &str) -> String {
        let digest = Sha256::digest(nonce.as_bytes());
        let digest = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("device:nonce:{}:{}", self.id, digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;
    use crate::store::Secrets;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rand_core::OsRng;
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1v15::Pkcs1v15Sign, pkcs8::EncodePublicKey};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Mem(Arc<Mutex<HashMap<String, String>>>);

    impl Secrets for Mem {
        async fn set(&self, key: &str, value: &str, _ttl: u64) -> Result<()> {
            self.0.lock().unwrap().insert(key.into(), value.into());
            Ok(())
        }
        async fn get(&self, key: &str) -> Result<Option<String>> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        async fn take(&self, key: &str) -> Result<Option<String>> {
            Ok(self.0.lock().unwrap().remove(key))
        }
        async fn take_if(&self, key: &str, expected: &str) -> Result<bool> {
            let mut values = self.0.lock().unwrap();
            if values.get(key).map(String::as_str) != Some(expected) {
                return Ok(false);
            }
            values.remove(key);
            Ok(true)
        }
        async fn del(&self, key: &str) -> Result<()> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }

    #[test]
    fn verifies_and_rejects_device_proof() {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public = RsaPublicKey::from(&private)
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let device = Device::new("d1", "u1", "laptop", public, 100);
        let message = "d1:nonce:100";
        let digest = Sha256::digest(message.as_bytes());
        let signature = private
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .unwrap();
        let proof = DeviceProof {
            device_id: "d1".into(),
            nonce: "nonce".into(),
            at: 100,
            signature: URL_SAFE_NO_PAD.encode(signature),
        };
        assert!(device.verify(&proof, 101, 30).is_ok());
        assert!(device.verify(&proof, 200, 30).is_err());
    }

    #[tokio::test]
    async fn issues_a_single_use_nonce() {
        let device = Device::new("d1", "u1", "laptop", "unused", 100);
        let store = Mem::default();
        let nonce = device.issue_nonce(&store, 60).await.unwrap();
        assert!(
            store
                .take(&device.nonce_key(&nonce))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .take(&device.nonce_key(&nonce))
                .await
                .unwrap()
                .is_none()
        );
    }
}
