use crate::error::{Error, Result};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Padding, Rsa as Key};

pub struct Rsa {
    private_key: Key<Private>,
    public_key_pem: String,
}

impl Rsa {
    /// 初始化生成 2048 位 RSA 密钥对
    pub fn new() -> Result<Self> {
        let private_key = Key::generate(2048)
            .map_err(|e| Error::Internal(format!("Failed to generate RSA private key: {e}")))?;
        let public_key_pem = private_key
            .public_key_to_pem()
            .map_err(|e| Error::Internal(format!("Failed to export RSA public key: {e}")))?;

        Ok(Self {
            private_key,
            public_key_pem: String::from_utf8(public_key_pem)
                .map_err(|e| Error::Internal(format!("Invalid RSA public key: {e}")))?,
        })
    }

    /// 从 PKCS#8 PEM 恢复密钥，供调用方持久化和启动加载。
    pub fn from_private_pem(pem: &str) -> Result<Self> {
        let private_key = PKey::private_key_from_pem(pem.as_bytes())
            .and_then(|key| key.rsa())
            .map_err(|e| Error::Internal(format!("Failed to load RSA private key: {e}")))?;
        let public_key_pem = private_key
            .public_key_to_pem()
            .map_err(|e| Error::Internal(format!("Failed to export RSA public key: {e}")))?;
        Ok(Self {
            private_key,
            public_key_pem: String::from_utf8(public_key_pem)
                .map_err(|e| Error::Internal(format!("Invalid RSA public key: {e}")))?,
        })
    }

    /// 导出 PKCS#8 PEM，调用方应将其放入密钥管理系统。
    pub fn private_key_pem(&self) -> Result<String> {
        let pem = PKey::from_rsa(self.private_key.clone())
            .map_err(|e| Error::Internal(format!("Failed to export RSA private key: {e}")))?
            .private_key_to_pem_pkcs8()
            .map_err(|e| Error::Internal(format!("Failed to export RSA private key: {e}")))?;
        String::from_utf8(pem).map_err(|e| Error::Internal(format!("Invalid RSA private key: {e}")))
    }

    /// 生成新密钥，用于显式轮换。
    pub fn rotate() -> Result<Self> {
        Self::new()
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

        let mut decrypted_bytes = vec![0; self.private_key.size() as usize];
        let size = self
            .private_key
            .private_decrypt(&ciphertext, &mut decrypted_bytes, Padding::PKCS1_OAEP)
            .map_err(|e| Error::AuthFailed(format!("RSA decryption failed: {e}")))?;
        decrypted_bytes.truncate(size);

        String::from_utf8(decrypted_bytes)
            .map_err(|e| Error::AuthFailed(format!("Decrypted bytes not valid UTF-8: {e}")))
    }

    pub fn encrypt_oaep(&self, plaintext: &str) -> Result<String> {
        let public = Key::public_key_from_pem(self.public_key_pem.as_bytes())
            .map_err(|e| Error::Internal(format!("Invalid RSA public key: {e}")))?;
        let mut encrypted = vec![0; public.size() as usize];
        let size = public
            .public_encrypt(plaintext.as_bytes(), &mut encrypted, Padding::PKCS1_OAEP)
            .map_err(|e| Error::Internal(format!("RSA encryption failed: {e}")))?;
        encrypted.truncate(size);
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
