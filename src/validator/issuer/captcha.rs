use crate::error::{Error, Result};
use crate::store::Secrets;
pub mod click;
pub mod image;
pub mod rotate;
pub mod slider;

pub use self::{click::Click, image::Image, rotate::Rotate, slider::Slider};
use crate::validator::verifier::captcha::{CaptchaChallenge, CaptchaType};

/// 人机验证码签发。
pub struct Captcha {
    ttl_seconds: u64,
}

impl Default for Captcha {
    fn default() -> Self {
        Self::new(120)
    }
}

impl Captcha {
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
                let (answer, background) = Image::issue(4);
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
                let (target, background, slider, y) = Slider::issue();
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
                let (target, background) = Rotate::issue();
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
                let (points, prompt, background) = Click::issue();
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

    /// 签发校验成功后的短期通过凭证；校验逻辑由 verifier 独立完成。
    pub async fn token<K: Secrets>(&self, kv: &K, id: &str, ttl: u64) -> Result<String> {
        if kv.take(&format!("cap:passed:{id}")).await?.is_none() {
            return Err(Error::CaptchaFailed("Captcha has not been verified".into()));
        }
        let token = format!("cpt_{}", uuid::Uuid::new_v4().simple());
        kv.set(&format!("cpt:{token}"), "1", ttl.max(1)).await?;
        Ok(token)
    }
}
