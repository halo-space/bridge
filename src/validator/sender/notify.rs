use crate::error::Result;
use crate::validator::sender::mail::SmtpSender;
use crate::validator::sender::sms::SmsSender;
use std::sync::Arc;

/// 通知通道类别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyChannel {
    Email,
    Sms,
}

/// 统一消息通知门面服务 (Notification Facade)
///
/// 将底层 SMTP 邮件和商业短信通道收敛为统一调度接口，业务方无需关心目标通道具体细节。
#[derive(Clone)]
pub struct NotificationService {
    mailer: Arc<SmtpSender>,
    sms: Arc<SmsSender>,
}

impl NotificationService {
    pub fn new(mailer: SmtpSender, sms: SmsSender) -> Self {
        Self {
            mailer: Arc::new(mailer),
            sms: Arc::new(sms),
        }
    }

    /// 根据接收方特征判断通道类型 (包含 '@' 判定为邮件，否则判定为手机短信)
    pub fn detect_channel(target: &str) -> NotifyChannel {
        if target.contains('@') {
            NotifyChannel::Email
        } else {
            NotifyChannel::Sms
        }
    }

    /// 目标通道是否处于激活可用状态
    pub fn is_active_for(&self, target: &str) -> bool {
        match Self::detect_channel(target) {
            NotifyChannel::Email => self.mailer.is_active(),
            NotifyChannel::Sms => self.sms.is_active(),
        }
    }

    /// 统一异步投递验证码
    pub async fn send_verification_code(
        &self,
        target: &str,
        code: &str,
        scene: &str,
        ttl_seconds: u64,
    ) -> Result<()> {
        match Self::detect_channel(target) {
            NotifyChannel::Email => {
                self.mailer
                    .send_verification_code(target, code, scene, ttl_seconds)
                    .await
            }
            NotifyChannel::Sms => {
                self.sms
                    .send_verification_code(target, code, ttl_seconds)
                    .await
            }
        }
    }

    pub fn mailer(&self) -> &SmtpSender {
        &self.mailer
    }

    pub fn sms(&self) -> &SmsSender {
        &self.sms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::sender::mail::SmtpConfig;
    use crate::validator::sender::sms::SmsConfig;

    #[tokio::test]
    async fn test_notification_facade_routing() {
        let mailer = SmtpSender::new(SmtpConfig::default());
        let sms = SmsSender::new(SmsConfig::default());
        let notify = NotificationService::new(mailer, sms);

        assert_eq!(
            NotificationService::detect_channel("user@halo.com"),
            NotifyChannel::Email
        );
        assert_eq!(
            NotificationService::detect_channel("+8613800138000"),
            NotifyChannel::Sms
        );

        // 未配置真实发信网关时平滑降级，返回 Ok(())
        let res_mail = notify
            .send_verification_code("test@halo.com", "123456", "login", 300)
            .await;
        assert!(res_mail.is_ok());

        let res_sms = notify
            .send_verification_code("13800138000", "123456", "login", 300)
            .await;
        assert!(res_sms.is_ok());
    }
}
