use crate::error::{IdpError, Result};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rand_core::OsRng;
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePublicKey, LineEnding},
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
