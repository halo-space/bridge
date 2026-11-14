use crate::error::{Error, Result};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use sad_rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use sad_rsa::sha2::Sha256;
use sad_rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

pub struct Rsa {
    private_key: RsaPrivateKey,
    public_key_pem: String,
}

impl Rsa {
    pub fn new() -> Result<Self> {
        let mut rng = rand::rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| Error::Internal(format!("Failed to generate RSA private key: {e}")))?;
        Self::from_private_key(private_key)
    }

    pub fn from_private_pem(pem: &str) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| Error::Internal(format!("Failed to load RSA private key: {e}")))?;
        Self::from_private_key(private_key)
    }

    fn from_private_key(private_key: RsaPrivateKey) -> Result<Self> {
        let public_key_pem = RsaPublicKey::from(&private_key)
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Internal(format!("Failed to export RSA public key: {e}")))?;
        Ok(Self {
            private_key,
            public_key_pem,
        })
    }

    pub fn private_key_pem(&self) -> Result<String> {
        self.private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|e| Error::Internal(format!("Failed to export RSA private key: {e}")))
    }

    pub fn rotate() -> Result<Self> {
        Self::new()
    }

    pub fn public_pem(&self) -> &str {
        &self.public_key_pem
    }

    pub fn decrypt_oaep(&self, base64_ciphertext: &str) -> Result<String> {
        let ciphertext = BASE64_STANDARD
            .decode(base64_ciphertext.trim())
            .map_err(|e| Error::AuthFailed(format!("Invalid base64 payload: {e}")))?;
        let decrypted = self
            .private_key
            .decrypt(Oaep::<Sha256>::new(), &ciphertext)
            .map_err(|e| Error::AuthFailed(format!("RSA decryption failed: {e}")))?;
        String::from_utf8(decrypted)
            .map_err(|e| Error::AuthFailed(format!("Decrypted bytes not valid UTF-8: {e}")))
    }

    pub fn encrypt_oaep(&self, plaintext: &str) -> Result<String> {
        let mut rng = rand::rng();
        let encrypted = RsaPublicKey::from(&self.private_key)
            .encrypt(&mut rng, Oaep::<Sha256>::new(), plaintext.as_bytes())
            .map_err(|e| Error::Internal(format!("RSA encryption failed: {e}")))?;
        Ok(BASE64_STANDARD.encode(encrypted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_and_restores_key_pair() {
        let crypto = Rsa::new().unwrap();
        let pem = crypto.private_key_pem().unwrap();
        let restored = Rsa::from_private_pem(&pem).unwrap();
        assert_eq!(crypto.public_pem(), restored.public_pem());
        let encoded = crypto.encrypt_oaep("secret").unwrap();
        assert_eq!(restored.decrypt_oaep(&encoded).unwrap(), "secret");
        assert_ne!(crypto.public_pem(), Rsa::rotate().unwrap().public_pem());
    }
}
