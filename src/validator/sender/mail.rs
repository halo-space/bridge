use crate::error::{IdpError, Result};
use lettre::message::MultiPart;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::{Deserialize, Serialize};

fn default_port() -> u16 {
    465
}

fn default_encryption() -> String {
    "tls".to_string()
}

fn default_from_name() -> Option<String> {
    Some("Halo Space 安全团队".to_string())
}

/// SMTP 邮件发送配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    /// 是否启用真实外网邮件发送
    #[serde(default)]
    pub enabled: bool,
    /// 未启用或配置不完整时是否返回错误；开发环境可保持 false 使用 Mock 行为。
    #[serde(default)]
    pub strict: bool,
    /// SMTP 服务器地址 (如 smtp.exmail.qq.com, smtp.aliyun.com)
    #[serde(default)]
    pub host: String,
    /// SMTP 端口 (465 SSL, 587 STARTTLS, 25 明文)
    #[serde(default = "default_port")]
    pub port: u16,
    /// 认证账号 (如 noreply@aiwiki.vip)
    #[serde(default)]
    pub username: String,
    /// 认证密码或授权码
    #[serde(default)]
    pub password: String,
    /// 发件人地址 (通常与 username 相同)
    #[serde(default)]
    pub from_email: String,
    /// 发件人显示名称 (如 "Halo Space 安全团队")
    #[serde(default = "default_from_name")]
    pub from_name: Option<String>,
    /// 加密模式: "tls" (隐式 SSL/TLS, 默认端口 465) | "starttls" (端口 587) | "none" (端口 25)
    #[serde(default = "default_encryption")]
    pub encryption: String,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            strict: false,
            host: String::new(),
            port: 465,
            username: String::new(),
            password: String::new(),
            from_email: String::new(),
            from_name: default_from_name(),
            encryption: default_encryption(),
        }
    }
}

/// 邮件发送服务
#[derive(Clone)]
pub struct SmtpSender {
    config: SmtpConfig,
}

impl SmtpSender {
    pub fn new(config: SmtpConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &SmtpConfig {
        &self.config
    }

    /// 是否已启用且有效配置
    pub fn is_active(&self) -> bool {
        self.config.enabled
            && !self.config.host.trim().is_empty()
            && !self.config.username.trim().is_empty()
            && !self.config.from_email.trim().is_empty()
    }

    /// 发送基础 HTML 邮件
    pub async fn send(
        &self,
        to: &str,
        subject: &str,
        html_body: &str,
        plain_text: Option<&str>,
    ) -> Result<()> {
        if !self.is_active() {
            if self.config.strict {
                return Err(IdpError::EmailFailed(
                    "SMTP channel is disabled or incomplete".into(),
                ));
            }
            tracing::info!(
                target: "idp::mailer",
                "SMTP 未启用或配置不全，跳过公网邮件投递: to={}, subject={}",
                to,
                subject
            );
            return Ok(());
        }

        let from_display = self
            .config
            .from_name
            .as_deref()
            .unwrap_or("Halo Space 安全团队");

        let from_header = format!("\"{}\" <{}>", from_display, self.config.from_email.trim());
        let to_header = to.trim().to_string();

        let email_builder = Message::builder()
            .from(
                from_header
                    .parse()
                    .map_err(|e| IdpError::EmailFailed(format!("Invalid from email: {e}")))?,
            )
            .to(to_header
                .parse()
                .map_err(|e| IdpError::EmailFailed(format!("Invalid to email: {e}")))?)
            .subject(subject);

        let email = if let Some(txt) = plain_text {
            email_builder
                .multipart(MultiPart::alternative_plain_html(
                    txt.to_string(),
                    html_body.to_string(),
                ))
                .map_err(|e| IdpError::EmailFailed(format!("Build multipart email failed: {e}")))?
        } else {
            email_builder
                .header(ContentType::TEXT_HTML)
                .body(html_body.to_string())
                .map_err(|e| IdpError::EmailFailed(format!("Build email failed: {e}")))?
        };

        // 构造异步 SMTP Transport
        let transport = self.build_transport()?;

        transport
            .send(email)
            .await
            .map_err(|e| IdpError::EmailFailed(format!("SMTP send failed to {}: {e}", to)))?;

        tracing::info!(
            target: "idp::mailer",
            "SMTP 邮件投递成功: to={}, subject={}",
            to,
            subject
        );

        Ok(())
    }

    /// 发送 6 位安全身份核验验证码
    pub async fn send_verification_code(
        &self,
        to: &str,
        code: &str,
        scene: &str,
        ttl_secs: u64,
    ) -> Result<()> {
        let (scene_label, scene_desc) = match scene {
            "login" | "login_sms" => ("登录验证", "用于验证您的身份并登录企业控制台"),
            "register" => ("账号注册", "用于激活并完成您的新账号注册"),
            "reset_password" | "reset_pwd" => ("找回密码", "用于重置您的登录安全凭证"),
            "bind_email" => ("邮箱绑定", "用于绑定您的安全工作邮箱"),
            _ => ("安全验证", "用于完成企业安全基线核验"),
        };

        let expire_mins = (ttl_secs / 60).max(1);
        let subject = format!("【Halo Space】{}动态验证码：{}", scene_label, code);

        let html = format!(
            r##"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{subject}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 24px; color: #1e293b; }}
    .container {{ max-width: 560px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }}
    .header {{ background: #0f172a; padding: 28px 32px; color: #ffffff; }}
    .brand {{ font-size: 20px; font-weight: 700; letter-spacing: -0.5px; display: flex; align-items: center; gap: 8px; }}
    .badge {{ font-size: 11px; background: rgba(99, 102, 241, 0.2); color: #818cf8; border: 1px solid rgba(129, 140, 248, 0.3); padding: 2px 8px; border-radius: 9999px; font-weight: 500; }}
    .content {{ padding: 36px 32px 28px; }}
    .greeting {{ font-size: 15px; color: #334155; margin-bottom: 12px; }}
    .desc {{ font-size: 14px; color: #64748b; line-height: 1.6; margin-bottom: 24px; }}
    .code-box {{ background: #f1f5f9; border-radius: 10px; padding: 20px; text-align: center; margin-bottom: 24px; border: 1px dashed #cbd5e1; }}
    .code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #4f46e5; }}
    .tips {{ font-size: 12px; color: #94a3b8; line-height: 1.6; border-top: 1px solid #f1f5f9; padding-top: 20px; }}
    .footer {{ background: #f8fafc; padding: 20px 32px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">
        Halo Space <span class="badge">IAM 身份安全</span>
      </div>
    </div>
    <div class="content">
      <div class="greeting">您好：</div>
      <div class="desc">
        您正在进行 <strong>{scene_label}</strong> 操作（{scene_desc}），请在验证页面输入以下 6 位数字验证码：
      </div>
      <div class="code-box">
        <div class="code">{code}</div>
      </div>
      <div class="tips">
        • 该验证码在 <strong>{expire_mins} 分钟</strong> 内有效，请尽快完成验证。<br>
        • 为保障您的企业账号安全，切勿向包括管理员在内的任何人透露此验证码。<br>
        • 若非您本人发起的请求，请忽略此邮件或联系管理员。
      </div>
    </div>
    <div class="footer">
      本邮件由 Halo Space 企业智能协同平台自动派发，请勿直接回复。
    </div>
  </div>
</body>
</html>"##,
            subject = subject,
            scene_label = scene_label,
            scene_desc = scene_desc,
            code = code,
            expire_mins = expire_mins
        );

        let plain = format!(
            "【Halo Space】您好，您的{}验证码是：{}，{}分钟内有效。如非本人操作请忽略此邮件。",
            scene_label, code, expire_mins
        );

        self.send(to, &subject, &html, Some(&plain)).await
    }

    fn build_transport(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        let host = self.config.host.trim();
        let port = self.config.port;

        let creds = Credentials::new(
            self.config.username.trim().to_string(),
            self.config.password.trim().to_string(),
        );

        let transport_builder = match self.config.encryption.to_lowercase().as_str() {
            "tls" | "ssl" => {
                // 465 隐式 TLS
                let tls_params = TlsParameters::new(host.to_string())
                    .map_err(|e| IdpError::EmailFailed(format!("TLS config error: {e}")))?;
                AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                    .map_err(|e| IdpError::EmailFailed(format!("Invalid SMTP host {}: {e}", host)))?
                    .port(port)
                    .tls(Tls::Wrapper(tls_params))
                    .credentials(creds)
            }
            "starttls" => {
                // 587 STARTTLS
                let tls_params = TlsParameters::new(host.to_string())
                    .map_err(|e| IdpError::EmailFailed(format!("STARTTLS config error: {e}")))?;
                AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                    .map_err(|e| IdpError::EmailFailed(format!("Invalid SMTP host {}: {e}", host)))?
                    .port(port)
                    .tls(Tls::Required(tls_params))
                    .credentials(creds)
            }
            _ => {
                // 明文连接 (仅用于本地内网测试)
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
                    .port(port)
                    .credentials(creds)
            }
        };

        Ok(transport_builder.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_config_defaults() {
        let cfg = SmtpConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.port, 465);
        assert_eq!(cfg.encryption, "tls");
        let sender = SmtpSender::new(cfg);
        assert!(!sender.is_active());
    }

    #[tokio::test]
    async fn test_send_when_inactive_should_graceful_ok() {
        let cfg = SmtpConfig::default();
        let sender = SmtpSender::new(cfg);
        // 未激活状态下不发外网，记录日志并返回 Ok
        let res = sender
            .send_verification_code("test@example.com", "123456", "login", 300)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_smtp_strict_mode_rejects_inactive_channel() {
        let sender = SmtpSender::new(SmtpConfig {
            strict: true,
            ..SmtpConfig::default()
        });
        let res = sender
            .send_verification_code("test@example.com", "123456", "login", 300)
            .await;
        assert!(matches!(res, Err(IdpError::EmailFailed(_))));
    }
}
