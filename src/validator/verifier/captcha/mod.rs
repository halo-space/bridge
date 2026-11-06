pub mod click;
pub mod image;
pub mod rotate;
pub mod slider;

use serde::{Deserialize, Serialize};

use crate::error::{IdpError, Result};
use crate::store::KvStore;

pub use click::{ClickCaptcha, TargetPoint};
pub use image::ImageCaptcha;
pub use rotate::RotateCaptcha;
pub use slider::SliderCaptcha;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptchaType {
    Image,
    Slider,
    Rotate,
    Click,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaChallenge {
    pub id: String,
    pub captcha_type: CaptchaType,
    pub background: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y_offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaVerifyReq {
    pub id: String,
    pub captcha_type: CaptchaType,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub offset_x: Option<i32>,
    #[serde(default)]
    pub angle: Option<i32>,
    #[serde(default)]
    pub points: Option<Vec<(i32, i32)>>,
}

/// 人机验证码校验。
pub struct CaptchaVerifier {
    ttl_token_seconds: u64,
    max_attempts: u32,
}

impl Default for CaptchaVerifier {
    fn default() -> Self {
        Self::new(300, 5)
    }
}

impl CaptchaVerifier {
    pub fn new(ttl_token_seconds: u64, max_attempts: u32) -> Self {
        Self {
            ttl_token_seconds,
            max_attempts: max_attempts.max(1),
        }
    }

    pub async fn verify<K: KvStore>(&self, kv: &K, req: &CaptchaVerifyReq) -> Result<String> {
        let key = format!("cap:{}", req.id);
        let attempts_key = format!("cap:attempts:{}", req.id);
        let type_key = format!("cap:type:{}", req.id);
        let answer = kv.get(&key).await?.ok_or(IdpError::CaptchaExpired)?;
        let stored_type = kv
            .get(&type_key)
            .await?
            .and_then(|value| serde_json::from_str::<CaptchaType>(&value).ok())
            .ok_or(IdpError::CaptchaExpired)?;
        if stored_type != req.captcha_type {
            return Err(IdpError::CaptchaFailed("Captcha type mismatch".into()));
        }
        let attempts = kv
            .get(&attempts_key)
            .await?
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        if attempts >= self.max_attempts {
            return Err(IdpError::CaptchaFailed("Too many attempts".into()));
        }

        let passed = match req.captcha_type {
            CaptchaType::Image => ImageCaptcha::verify(&answer, req.text.as_deref().unwrap_or("")),
            CaptchaType::Slider => {
                let target: u32 = answer
                    .parse()
                    .map_err(|_| IdpError::Internal("Corrupted slider challenge answer".into()))?;
                SliderCaptcha::verify(target, req.offset_x.unwrap_or(0))
            }
            CaptchaType::Rotate => {
                let target: u32 = answer
                    .parse()
                    .map_err(|_| IdpError::Internal("Corrupted rotate challenge answer".into()))?;
                RotateCaptcha::verify(target, req.angle.unwrap_or(0))
            }
            CaptchaType::Click => {
                let targets: Vec<TargetPoint> = serde_json::from_str(&answer)
                    .map_err(|_| IdpError::Internal("Corrupted click challenge answer".into()))?;
                ClickCaptcha::verify(&targets, req.points.as_deref().unwrap_or(&[]))
            }
        };

        if !passed {
            kv.set(&attempts_key, &(attempts + 1).to_string(), 120)
                .await?;
            return Err(IdpError::CaptchaFailed("Verification failed".into()));
        }

        if !kv.take_if(&key, &answer).await? {
            return Err(IdpError::CaptchaExpired);
        }
        kv.del(&attempts_key).await?;
        kv.del(&type_key).await?;

        let token = format!("cpt_{}", uuid::Uuid::new_v4().simple());
        kv.set(&format!("cpt:{token}"), "1", self.ttl_token_seconds)
            .await?;
        Ok(token)
    }

    pub async fn token<K: KvStore>(&self, kv: &K, token: &str) -> Result<bool> {
        Ok(kv.take(&format!("cpt:{token}")).await?.is_some())
    }
}
