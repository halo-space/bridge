use crate::error::{IdpError, Result};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;
use url::Url;

type HmacSha1 = Hmac<Sha1>;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for &b in data {
        buffer = (buffer << 8) | (b as u64);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(BASE32_ALPHABET[index] as char);
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(BASE32_ALPHABET[index] as char);
    }

    result
}

fn base32_decode(encoded: &str) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for ch in encoded.to_ascii_uppercase().chars() {
        if ch == ' ' || ch == '-' || ch == '=' {
            continue;
        }
        let val = match ch {
            'A'..='Z' => (ch as u8) - b'A',
            '2'..='7' => (ch as u8) - b'2' + 26,
            _ => {
                return Err(IdpError::AuthFailed(
                    "Invalid Base32 character in TOTP secret".into(),
                ));
            }
        };

        buffer = (buffer << 5) | (val as u64);
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            result.push(((buffer >> bits_left) & 0xFF) as u8);
        }
    }

    Ok(result)
}

/// 基于 RFC 6238 的时间动态口令 (对齐 Authing 3.2.1 TOTP)
pub struct Totp;

impl Totp {
    pub const PERIOD: u64 = 30; // 30 秒步长
    pub const DIGITS: u32 = 6; // 6 位数字

    /// 生成 160-bit (20-byte) 随机高强度 Base32 TOTP 秘钥
    pub fn generate_secret() -> String {
        let mut bytes = [0u8; 20];
        OsRng.fill_bytes(&mut bytes);
        base32_encode(&bytes)
    }

    /// 根据用户专属 Salt 和用户 ID 派生生成强绑定的 TOTP 秘钥 (RFC 6238 Base32)
    pub fn derive_secret_with_salt(user_id: i64, user_salt: &str) -> String {
        use sha2::{Digest, Sha256};
        let seed = format!("halo:totp:salt_bound:{}:{}", user_id, user_salt);
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        let hash = hasher.finalize();
        base32_encode(&hash[..20])
    }

    /// 构造标准绑定跳转 URI（兼容 Google Authenticator, 微软 Authenticator）
    pub fn generate_otpauth_uri(issuer: &str, account: &str, secret: &str) -> Result<String> {
        let label = format!("{issuer}:{account}");
        let mut u = Url::parse(&format!("otpauth://totp/{label}"))
            .map_err(|e| IdpError::Internal(e.to_string()))?;

        u.query_pairs_mut()
            .append_pair("secret", secret)
            .append_pair("issuer", issuer)
            .append_pair("algorithm", "SHA1")
            .append_pair("digits", &Self::DIGITS.to_string())
            .append_pair("period", &Self::PERIOD.to_string());

        Ok(u.to_string())
    }

    /// 生成可供用户在 App 中扫码绑定的标准矢量 SVG 二维码内容
    pub fn generate_qr_svg(otpauth_uri: &str) -> Result<String> {
        let code = qrcode::QrCode::new(otpauth_uri.as_bytes())
            .map_err(|e| IdpError::Internal(format!("二维码生成失败: {e}")))?;

        let svg = code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(200, 200)
            .build();
        Ok(svg)
    }

    /// 生成直接嵌入 HTML/Img 的 Data-URI 格式二维码 (SVG base64)
    pub fn generate_qr_data_uri(otpauth_uri: &str) -> Result<String> {
        let svg = Self::generate_qr_svg(otpauth_uri)?;
        use base64::Engine;
        let b64 = base64::prelude::BASE64_STANDARD.encode(svg.as_bytes());
        Ok(format!("data:image/svg+xml;base64,{b64}"))
    }

    /// 计算指定时间戳的 6 位数字口令
    pub fn generate_code(secret: &str, timestamp: u64) -> Result<String> {
        let key_bytes = base32_decode(secret)?;
        let step = timestamp / Self::PERIOD;
        let step_bytes = step.to_be_bytes();

        let mut mac = HmacSha1::new_from_slice(&key_bytes)
            .map_err(|e| IdpError::Internal(format!("HMAC key error: {e}")))?;
        mac.update(&step_bytes);
        let result = mac.finalize().into_bytes();

        // 动态截断 Dynamic Truncation (RFC 4226)
        let offset = (result[19] & 0x0F) as usize;
        let binary = (((result[offset] & 0x7F) as u32) << 24)
            | (((result[offset + 1] & 0xFF) as u32) << 16)
            | (((result[offset + 2] & 0xFF) as u32) << 8)
            | ((result[offset + 3] & 0xFF) as u32);

        let code_num = binary % 10u32.pow(Self::DIGITS);
        Ok(format!("{:06}", code_num))
    }

    /// 校验用户提交的 6 位动态口令（允许 ±1 步长即 ±30 秒的时钟偏移）
    pub fn verify_code(secret: &str, code: &str, current_timestamp: u64) -> Result<bool> {
        let code = code.trim();
        if code.len() != (Self::DIGITS as usize) {
            return Ok(false);
        }

        // 容差窗口：前一步长、当前步长、后一步长
        let steps = [
            current_timestamp.saturating_sub(Self::PERIOD),
            current_timestamp,
            current_timestamp + Self::PERIOD,
        ];

        for t in steps {
            if let Ok(expected) = Self::generate_code(secret, t) {
                if expected == code {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}
