use crate::error::{IdpError, Result};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rand_core::OsRng;
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
};
use sha2::Sha256;
use std::sync::OnceLock;

pub struct RsaCrypto {
    private_key: RsaPrivateKey,
    #[allow(dead_code)]
    public_key: RsaPublicKey,
    public_key_pem: String,
}

static GLOBAL_RSA: OnceLock<RsaCrypto> = OnceLock::new();

impl RsaCrypto {
    /// 初始化生成 2048 位 RSA 密钥对
    pub fn new() -> Result<Self> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| IdpError::Internal(format!("Failed to generate RSA private key: {e}")))?;
        let public_key = RsaPublicKey::from(&private_key);
        let public_key_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| IdpError::Internal(format!("Failed to export RSA public key: {e}")))?;

        Ok(Self {
            private_key,
            public_key,
            public_key_pem,
        })
    }

    /// 从 PKCS#8 PEM 恢复密钥，供调用方持久化和启动加载。
    pub fn from_private_pem(pem: &str) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| IdpError::Internal(format!("Failed to load RSA private key: {e}")))?;
        let public_key = RsaPublicKey::from(&private_key);
        let public_key_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| IdpError::Internal(format!("Failed to export RSA public key: {e}")))?;
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
            .map_err(|e| IdpError::Internal(format!("Failed to export RSA private key: {e}")))
    }

    /// 生成新密钥，用于显式轮换。
    pub fn rotate() -> Result<Self> {
        Self::new()
    }

    /// 获取全局单例密钥对（进程生命周期内一致，避免重启前重复生成）
    pub fn global() -> &'static Self {
        GLOBAL_RSA
            .get_or_init(|| Self::new().expect("Failed to initialize global RSA crypto key pair"))
    }

    /// 获取内部 RSA 公钥引用
    pub fn get_public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    /// 获取 SPKI 格式的 PEM 公钥字符串
    pub fn get_public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    /// 解密前端 RSA-OAEP (SHA-256) 密文 (Base64 编码)
    pub fn decrypt_oaep(&self, base64_ciphertext: &str) -> Result<String> {
        let ciphertext = BASE64_STANDARD
            .decode(base64_ciphertext.trim())
            .map_err(|e| IdpError::AuthFailed(format!("Invalid base64 payload: {e}")))?;

        let padding = Oaep::new::<Sha256>();
        let decrypted_bytes = self
            .private_key
            .decrypt(padding, &ciphertext)
            .map_err(|e| IdpError::AuthFailed(format!("RSA decryption failed: {e}")))?;

        String::from_utf8(decrypted_bytes)
            .map_err(|e| IdpError::AuthFailed(format!("Decrypted bytes not valid UTF-8: {e}")))
    }

    /// 智能解密：如果为 Base64 密文且解密成功则返回解密后的明文；若解密失败或不是密文则原样返回
    pub fn decrypt_or_raw(input: &str) -> String {
        let trimmed = input.trim();
        // RSA-2048 Base64 密文通常为 344 字符或以上
        if trimmed.len() >= 128 {
            if let Ok(plain) = Self::global().decrypt_oaep(trimmed) {
                // 如果前端附带了时间戳防重放，例如 "plainPassword:::1730356800000"
                if let Some((raw_pwd, _ts)) = plain.split_once(":::") {
                    return raw_pwd.to_string();
                }
                return plain;
            }
        }
        input.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_and_restores_key_pair() {
        let crypto = RsaCrypto::new().unwrap();
        let pem = crypto.private_key_pem().unwrap();
        let restored = RsaCrypto::from_private_pem(&pem).unwrap();
        assert_eq!(crypto.get_public_key_pem(), restored.get_public_key_pem());

        let mut rng = OsRng;
        let cipher = crypto
            .get_public_key()
            .encrypt(&mut rng, Oaep::new::<Sha256>(), b"secret")
            .unwrap();
        let encoded = BASE64_STANDARD.encode(cipher);
        assert_eq!(restored.decrypt_oaep(&encoded).unwrap(), "secret");
        assert_ne!(
            crypto.get_public_key_pem(),
            RsaCrypto::rotate().unwrap().get_public_key_pem()
        );
    }
}
