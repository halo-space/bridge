use crate::error::{Error, Result};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rand_core::OsRng;
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
};
use sha2::Sha256;

pub struct Rsa {
    private_key: RsaPrivateKey,
    #[allow(dead_code)]
    public_key: RsaPublicKey,
    public_key_pem: String,
}

impl Rsa {
    /// 初始化生成 2048 位 RSA 密钥对
    pub fn new() -> Result<Self> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| Error::Internal(format!("Failed to generate RSA private key: {e}")))?;
        let public_key = RsaPublicKey::from(&private_key);
        let public_key_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Internal(format!("Failed to export RSA public key: {e}")))?;

        Ok(Self {
            private_key,
            public_key,
            public_key_pem,
        })
    }

    /// 从 PKCS#8 PEM 恢复密钥，供调用方持久化和启动加载。
    pub fn from_private_pem(pem: &str) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| Error::Internal(format!("Failed to load RSA private key: {e}")))?;
        let public_key = RsaPublicKey::from(&private_key);
        let public_key_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Internal(format!("Failed to export RSA public key: {e}")))?;
        Ok(Self {
            private_key,
            public_key,
            public_key_pem,
        })
    }

    /// 导出 PKCS#8 PEM，调用方应将其放入密钥管理系统。
    pub fn private_key_pem(&self) -> Result<String> {
        self.private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|e| Error::Internal(format!("Failed to export RSA private key: {e}")))
    }

    /// 生成新密钥，用于显式轮换。
    pub fn rotate() -> Result<Self> {
        Self::new()
    }

    /// 获取内部 RSA 公钥引用
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    /// 获取 SPKI 格式的 PEM 公钥字符串
    pub fn public_pem(&self) -> &str {
        &self.public_key_pem
    }

    /// 解密前端 RSA-OAEP (SHA-256) 密文 (Base64 编码)
    pub fn decrypt_oaep(&self, base64_ciphertext: &str) -> Result<String> {
        let ciphertext = BASE64_STANDARD
            .decode(base64_ciphertext.trim())
            .map_err(|e| Error::AuthFailed(format!("Invalid base64 payload: {e}")))?;

        let padding = Oaep::new::<Sha256>();
        let decrypted_bytes = self
            .private_key
            .decrypt(padding, &ciphertext)
            .map_err(|e| Error::AuthFailed(format!("RSA decryption failed: {e}")))?;

        String::from_utf8(decrypted_bytes)
            .map_err(|e| Error::AuthFailed(format!("Decrypted bytes not valid UTF-8: {e}")))
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

        let mut rng = OsRng;
        let cipher = crypto
            .public_key()
            .encrypt(&mut rng, Oaep::new::<Sha256>(), b"secret")
            .unwrap();
        let encoded = BASE64_STANDARD.encode(cipher);
        assert_eq!(restored.decrypt_oaep(&encoded).unwrap(), "secret");
        assert_ne!(crypto.public_pem(), Rsa::rotate().unwrap().public_pem());
    }
}
