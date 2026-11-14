use super::types::{CaptchaType, CaptchaVerifyReq};
use super::{Click, Image, Rotate, Slider, TargetPoint};
use crate::error::{Error, Result};
use crate::store::Secrets;

pub struct Captcha {
    max_attempts: u32,
    passed_ttl_seconds: u64,
}

impl Default for Captcha {
    fn default() -> Self {
        Self::new(5)
    }
}

impl Captcha {
    pub fn new(max_attempts: u32) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            passed_ttl_seconds: 300,
        }
    }

    pub fn ttl(mut self, ttl: u64) -> Self {
        self.passed_ttl_seconds = ttl.max(1);
        self
    }

    /// 校验挑战并记录失败次数。
    ///
    /// `Secrets::incr` 必须由调用方以原子方式实现，bridge 不使用非原子的读写回退。
    pub async fn verify<K: Secrets>(&self, kv: &K, req: &CaptchaVerifyReq) -> Result<()> {
        let key = format!("cap:{}", req.id);
        let attempts_key = format!("cap:attempts:{}", req.id);
        let type_key = format!("cap:type:{}", req.id);
        let answer = kv.get(&key).await?.ok_or(Error::CaptchaExpired)?;
        let stored_type = kv
            .get(&type_key)
            .await?
            .and_then(|value| serde_json::from_str::<CaptchaType>(&value).ok())
            .ok_or(Error::CaptchaExpired)?;
        if stored_type != req.captcha_type {
            return Err(Error::CaptchaFailed("Captcha type mismatch".into()));
        }
        let attempts = kv.incr(&attempts_key, 120).await?;
        if attempts > self.max_attempts {
            return Err(Error::CaptchaFailed("Too many attempts".into()));
        }

        let passed = match req.captcha_type {
            CaptchaType::Image => Image::verify(&answer, req.text.as_deref().unwrap_or("")),
            CaptchaType::Slider => {
                let target: u32 = answer
                    .parse()
                    .map_err(|_| Error::Internal("Corrupted slider challenge answer".into()))?;
                Slider::verify(target, req.offset_x.unwrap_or(0))
            }
            CaptchaType::Rotate => {
                let target: u32 = answer
                    .parse()
                    .map_err(|_| Error::Internal("Corrupted rotate challenge answer".into()))?;
                Rotate::verify(target, req.angle.unwrap_or(0))
            }
            CaptchaType::Click => {
                let targets: Vec<TargetPoint> = serde_json::from_str(&answer)
                    .map_err(|_| Error::Internal("Corrupted click challenge answer".into()))?;
                Click::verify(&targets, req.points.as_deref().unwrap_or(&[]))
            }
        };

        if !passed {
            if attempts >= self.max_attempts {
                return Err(Error::CaptchaFailed("Too many attempts".into()));
            }
            return Err(Error::CaptchaFailed("Verification failed".into()));
        }
        if !kv.take_if(&key, &answer).await? {
            return Err(Error::CaptchaExpired);
        }
        kv.del(&attempts_key).await?;
        kv.del(&type_key).await?;
        kv.set(
            &format!("cap:passed:{}", req.id),
            "1",
            self.passed_ttl_seconds,
        )
        .await?;

        Ok(())
    }

    /// 原子消费由 issuer 签发的短期通过凭证。
    pub async fn take<K: Secrets>(&self, kv: &K, token: &str) -> Result<bool> {
        Ok(kv.take(&format!("cpt:{token}")).await?.is_some())
    }
}
