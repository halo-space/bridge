use crate::error::{Error, Result};
use crate::store::Secrets;
use crate::validator::verifier::captcha::{
    CaptchaChallenge, CaptchaType, ClickCaptcha, ImageCaptcha, RotateCaptcha, SliderCaptcha,
};

/// 人机验证码签发。
pub struct CaptchaIssuer {
    ttl_seconds: u64,
}

impl Default for CaptchaIssuer {
    fn default() -> Self {
        Self::new(120)
    }
}

impl CaptchaIssuer {
    pub fn new(ttl_seconds: u64) -> Self {
        Self { ttl_seconds }
    }

    pub async fn issue<K: Secrets>(
        &self,
        kv: &K,
        captcha_type: CaptchaType,
    ) -> Result<CaptchaChallenge> {
        let id = format!("cap_{}", uuid::Uuid::new_v4().simple());
        let key = format!("cap:{id}");
        kv.set(&format!("cap:attempts:{id}"), "0", self.ttl_seconds)
            .await?;
        kv.set(
            &format!("cap:type:{id}"),
            &serde_json::to_string(&captcha_type).map_err(|e| Error::Internal(e.to_string()))?,
            self.ttl_seconds,
        )
        .await?;
        let challenge = match captcha_type {
            CaptchaType::Image => {
                let (answer, background) = ImageCaptcha::generate(4);
                kv.set(&key, &answer, self.ttl_seconds).await?;
                CaptchaChallenge {
                    id,
                    captcha_type,
                    background,
                    slider: None,
                    y_offset: None,
                    prompt: None,
                }
            }
            CaptchaType::Slider => {
                let (target, background, slider, y) = SliderCaptcha::generate();
                kv.set(&key, &target.to_string(), self.ttl_seconds).await?;
                CaptchaChallenge {
                    id,
                    captcha_type,
                    background,
                    slider: Some(slider),
                    y_offset: Some(y),
                    prompt: Some("请拖动滑块完成拼图".into()),
                }
            }
            CaptchaType::Rotate => {
                let (target, background) = RotateCaptcha::generate();
                kv.set(&key, &target.to_string(), self.ttl_seconds).await?;
                CaptchaChallenge {
                    id,
                    captcha_type,
                    background,
                    slider: None,
                    y_offset: None,
                    prompt: Some("请拖动滑块使图片旋转至正向角度".into()),
                }
            }
            CaptchaType::Click => {
                let (points, prompt, background) = ClickCaptcha::generate();
                let answer =
                    serde_json::to_string(&points).map_err(|e| Error::Internal(e.to_string()))?;
                kv.set(&key, &answer, self.ttl_seconds).await?;
                CaptchaChallenge {
                    id,
                    captcha_type,
                    background,
                    slider: None,
                    y_offset: None,
                    prompt: Some(prompt),
                }
            }
        };
        Ok(challenge)
    }
}
