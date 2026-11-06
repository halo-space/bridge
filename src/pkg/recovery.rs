use crate::error::{IdpError, Result};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

pub struct RecoveryCode;

impl RecoveryCode {
    const ALPHABET: &'static [u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

    /// 生成一组（例如 10 个）高熵应急恢复码，格式如 `A8B2-C9D4`
    pub fn generate_batch(count: usize) -> Vec<String> {
        let mut codes = Vec::with_capacity(count);
        for _ in 0..count {
            let mut s = String::with_capacity(9);
            for i in 0..8 {
                if i == 4 {
                    s.push('-');
                }
                let idx = (OsRng.next_u32() as usize) % Self::ALPHABET.len();
                s.push(Self::ALPHABET[idx] as char);
            }
            codes.push(s);
        }
        codes
    }

    /// 计算恢复码哈希值（入库存储哈希值，防止数据库被盗）
    pub fn hash_code(raw_code: &str) -> String {
        let clean = raw_code.replace('-', "").to_ascii_uppercase();
        let mut hasher = Sha256::new();
        hasher.update(clean.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// 核验恢复码是否匹配存储哈希列表，成功匹配返回被消费的哈希值
    pub fn verify_and_consume(raw_code: &str, stored_hashes: &[String]) -> Result<String> {
        let input_hash = Self::hash_code(raw_code);
        if let Some(matched) = stored_hashes.iter().find(|&h| h == &input_hash) {
            Ok(matched.clone())
        } else {
            Err(IdpError::AuthFailed("Invalid recovery code".into()))
        }
    }
}
