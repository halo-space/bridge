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

    pub fn is_active(&self, channel: NotifyChannel) -> bool {
        match channel {
            NotifyChannel::Email => self.mailer.is_active(),
            NotifyChannel::Sms => self.sms.is_active(),
        }
    }

    pub async fn send_code(
        &self,
        channel: NotifyChannel,
        target: &str,
        code: &str,
        scene: &str,
        ttl_seconds: u64,
    ) -> Result<()> {
        match channel {
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

        assert!(notify.is_active(NotifyChannel::Email) == notify.mailer().is_active());
        assert!(notify.is_active(NotifyChannel::Sms) == notify.sms().is_active());

        // 未配置真实发信网关时平滑降级，返回 Ok(())
        let res_mail = notify
            .send_code(
                NotifyChannel::Email,
                "test@halo.com",
                "123456",
                "login",
                300,
            )
            .await;
        assert!(res_mail.is_ok());

        let res_sms = notify
            .send_code(NotifyChannel::Sms, "13800138000", "123456", "login", 300)
            .await;
        assert!(res_sms.is_ok());
    }
}
