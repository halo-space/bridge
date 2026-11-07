use crate::error::{IdpError, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::{RsaPublicKey, pkcs1v15::Pkcs1v15Sign, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 企业设备登录因子。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub tenant_id: i64,
    pub subject: String,
    pub name: String,
    pub public_key: String,
    pub enabled: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

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
        tenant_id: i64,
        subject: impl Into<String>,
        name: impl Into<String>,
        public_key: impl Into<String>,
        at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            tenant_id,
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

    /// 校验设备对一次性 nonce 的 RSA-SHA256 签名。
    pub fn verify(&self, proof: &DeviceProof, now: i64, window: i64) -> Result<()> {
        if !self.enabled {
            return Err(IdpError::AuthFailed("Device is disabled".into()));
        }
        if proof.device_id != self.id {
            return Err(IdpError::AuthFailed("Device mismatch".into()));
        }
        if window < 0 || (now - proof.at).abs() > window {
            return Err(IdpError::AuthFailed("Device proof expired".into()));
        }
        let public_key = RsaPublicKey::from_public_key_pem(&self.public_key)
            .map_err(|e| IdpError::AuthFailed(format!("Invalid device public key: {e}")))?;
        let signature = URL_SAFE_NO_PAD
            .decode(proof.signature.trim())
            .map_err(|e| IdpError::AuthFailed(format!("Invalid device signature: {e}")))?;
        let message = format!("{}:{}:{}", self.id, proof.nonce, proof.at);
        let digest = Sha256::digest(message.as_bytes());
        public_key
            .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
            .map_err(|_| IdpError::AuthFailed("Invalid device proof".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use rsa::{RsaPrivateKey, pkcs1v15::Pkcs1v15Sign, pkcs8::EncodePublicKey};

    #[test]
    fn verifies_and_rejects_device_proof() {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public = RsaPublicKey::from(&private)
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let device = Device::new("d1", 1, "u1", "laptop", public, 100);
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
}
