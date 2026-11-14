use super::{Device, DeviceProof};
use crate::error::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::sign::Verifier;

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
        let public_key = PKey::public_key_from_pem(self.public_key.as_bytes())
            .map_err(|e| Error::AuthFailed(format!("Invalid device public key: {e}")))?;
        let signature = URL_SAFE_NO_PAD
            .decode(proof.signature.trim())
            .map_err(|e| Error::AuthFailed(format!("Invalid device signature: {e}")))?;
        let message = format!("{}:{}:{}", self.id, proof.nonce, proof.at);
        let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)
            .map_err(|e| Error::AuthFailed(format!("Invalid device verifier: {e}")))?;
        verifier
            .set_rsa_padding(Padding::PKCS1)
            .map_err(|e| Error::AuthFailed(format!("Invalid device padding: {e}")))?;
        verifier
            .verify_oneshot(&signature, message.as_bytes())
            .map_err(|_| Error::AuthFailed("Invalid device proof".into()))
            .and_then(|valid| {
                valid
                    .then_some(())
                    .ok_or_else(|| Error::AuthFailed("Invalid device proof".into()))
            })
    }
}
