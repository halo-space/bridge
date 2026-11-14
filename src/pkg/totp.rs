use crate::error::{Error, Result};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use url::Url;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

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
                return Err(Error::AuthFailed(
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

/// TOTP 校验参数。默认值对应 RFC 6238 常用配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub window: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            window: 1,
        }
    }
}

impl Config {
    fn valid(self) -> Result<Self> {
        if !(6..=8).contains(&self.digits) || self.period == 0 || self.window > 10 {
            return Err(Error::AuthFailed("Invalid TOTP configuration".into()));
        }
        Ok(self)
    }
}

impl Totp {
    pub const PERIOD: u64 = 30; // 30 秒步长
    pub const DIGITS: u32 = 6; // 6 位数字

    /// 生成 160-bit (20-byte) 随机高强度 Base32 TOTP 秘钥
    pub fn generate_secret() -> String {
        let mut bytes = [0u8; 20];
        OsRng.fill_bytes(&mut bytes);
        base32_encode(&bytes)
    }

    /// 根据调用方主体和专属 Salt 派生 TOTP Secret。
    pub fn derive_secret_with_salt(subject: &str, user_salt: &str) -> String {
        use sha2::{Digest, Sha256};
        let seed = format!("halo:totp:salt_bound:{}:{}", subject, user_salt);
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        let hash = hasher.finalize();
        base32_encode(&hash[..20])
    }

    /// 构造标准绑定跳转 URI（兼容 Google Authenticator, 微软 Authenticator）
    pub fn generate_otpauth_uri(issuer: &str, account: &str, secret: &str) -> Result<String> {
        let label = format!("{issuer}:{account}");
        let mut u = Url::parse(&format!("otpauth://totp/{label}"))
            .map_err(|e| Error::Internal(e.to_string()))?;

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
            .map_err(|e| Error::Internal(format!("二维码生成失败: {e}")))?;

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
        Self::generate_with(secret, timestamp, Config::default())
    }

    /// 按调用方参数生成 TOTP。
    pub fn generate_with(secret: &str, timestamp: u64, config: Config) -> Result<String> {
        let config = config.valid()?;
        let key_bytes = base32_decode(secret)?;
        let step = timestamp / config.period;
        let step_bytes = step.to_be_bytes();

        let result = match config.algorithm {
            Algorithm::Sha1 => {
                let mut mac = HmacSha1::new_from_slice(&key_bytes)
                    .map_err(|e| Error::Internal(format!("HMAC key error: {e}")))?;
                mac.update(&step_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::Sha256 => {
                let mut mac = HmacSha256::new_from_slice(&key_bytes)
                    .map_err(|e| Error::Internal(format!("HMAC key error: {e}")))?;
                mac.update(&step_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::Sha512 => {
                let mut mac = HmacSha512::new_from_slice(&key_bytes)
                    .map_err(|e| Error::Internal(format!("HMAC key error: {e}")))?;
                mac.update(&step_bytes);
                mac.finalize().into_bytes().to_vec()
            }
        };

        // 动态截断 Dynamic Truncation (RFC 4226)
        let offset = (result[result.len() - 1] & 0x0F) as usize;
        let binary = (u32::from(result[offset] & 0x7F) << 24)
            | (u32::from(result[offset + 1]) << 16)
            | (u32::from(result[offset + 2]) << 8)
            | u32::from(result[offset + 3]);

        let code_num = binary % 10u32.pow(config.digits);
        Ok(format!(
            "{:0width$}",
            code_num,
            width = config.digits as usize
        ))
    }

    /// 校验用户提交的 6 位动态口令（允许 ±1 步长即 ±30 秒的时钟偏移）
    pub fn verify_code(secret: &str, code: &str, current_timestamp: u64) -> Result<bool> {
        Self::verify_with(secret, code, current_timestamp, Config::default())
    }

    /// 按调用方参数校验 TOTP。
    pub fn verify_with(
        secret: &str,
        code: &str,
        current_timestamp: u64,
        config: Config,
    ) -> Result<bool> {
        let config = config.valid()?;
        let code = code.trim();
        if code.len() != (config.digits as usize) {
            return Ok(false);
        }

        // 容差窗口：前一步长、当前步长、后一步长
        let step = config.period.saturating_mul(u64::from(config.window));
        let start = current_timestamp.saturating_sub(step);
        let end = current_timestamp.saturating_add(step);
        let mut timestamp = start;
        while timestamp <= end {
            if let Ok(expected) = Self::generate_with(secret, timestamp, config)
                && same(expected.as_bytes(), code.as_bytes())
            {
                return Ok(true);
            }
            if timestamp > u64::MAX - config.period {
                break;
            }
            timestamp += config.period;
        }

        Ok(false)
    }
}

fn same(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for (a, b) in left.iter().zip(right) {
        diff |= usize::from(a ^ b);
    }
    diff == 0
}
