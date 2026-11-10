use super::{Device, DeviceProof};
use crate::error::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::{RsaPublicKey, pkcs1v15::Pkcs1v15Sign, pkcs8::DecodePublicKey};
use sha2::{Digest, Sha256};

impl Device {
    /// 校验设备对一次性 nonce 的 RSA-SHA256 签名。
    pub fn verify(&self, proof: &DeviceProof, now: i64, window: i64) -> Result<()> {
        if !self.enabled {
            return Err(Error::AuthFailed("Device is disabled".into()));
        }
        if proof.device_id != self.id {
            return Err(Error::AuthFailed("Device mismatch".into()));
        }
        if window < 0 || (now - proof.at).abs() > window {
            return Err(Error::AuthFailed("Device proof expired".into()));
        }
        let public_key = RsaPublicKey::from_public_key_pem(&self.public_key)
            .map_err(|e| Error::AuthFailed(format!("Invalid device public key: {e}")))?;
        let signature = URL_SAFE_NO_PAD
            .decode(proof.signature.trim())
            .map_err(|e| Error::AuthFailed(format!("Invalid device signature: {e}")))?;
        let message = format!("{}:{}:{}", self.id, proof.nonce, proof.at);
        let digest = Sha256::digest(message.as_bytes());
        public_key
            .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
            .map_err(|_| Error::AuthFailed("Invalid device proof".into()))
    }
}
