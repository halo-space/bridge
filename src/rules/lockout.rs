use serde::{Deserialize, Serialize};

/// 登录安全决策结果
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockoutDecision {
    /// 允许直接登录
    Allow,
    /// 失败次数达到阈值，强制要求先完成人机验证码 (Captcha)
    RequireCaptcha,
    /// 账号已锁定，返回剩余锁定秒数
    Locked { remaining_seconds: u64 },
}

/// 登录防暴力破解策略 (对齐 Authing 3.1.2 登录安全)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockoutPolicy {
    /// 最大允许连续失败次数 (超过后锁定账号)
    pub max_failed_attempts: u32,
    /// 锁定持续秒数 (默认 900 秒 = 15 分钟)
    pub lockout_seconds: u64,
    /// 触发人机验证的失败次数阈值 (例如连续输错 3 次即要求验证码)
    pub captcha_threshold: u32,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_seconds: 900,
            captcha_threshold: 3,
        }
    }
}

impl LockoutPolicy {
    /// 根据当前连续失败记录与锁定截止时间评估登录状态
    pub fn evaluate(
        &self,
        failed_attempts: u32,
        locked_until_timestamp: Option<i64>,
    ) -> LockoutDecision {
        let now = chrono::Utc::now().timestamp();

        // 1. 检查是否在锁定窗口期内
        if let Some(locked_until) = locked_until_timestamp {
            if locked_until > now {
                return LockoutDecision::Locked {
                    remaining_seconds: (locked_until - now) as u64,
                };
            }
        }

        // 2. 检查是否超过最大失败上限
        if failed_attempts >= self.max_failed_attempts {
            return LockoutDecision::Locked {
                remaining_seconds: self.lockout_seconds,
            };
        }

        // 3. 检查是否达到验证码触发阈值
        if failed_attempts >= self.captcha_threshold {
            return LockoutDecision::RequireCaptcha;
        }

        LockoutDecision::Allow
    }
}
