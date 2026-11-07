//! # idp
//!
//! Halo Core Identity Provider, Multi-factor Authentication & OIDC Protocol Engine.
//!
//! - `factor`: 登录因子（基础凭证、社交登录、企业身份源和 Passkey）
//! - `pkg`: 可复用安全算法（密码、RSA、TOTP、恢复码）
//! - `validator`: 认证材料能力（issuer、sender、verifier）
//! - `rules`: 认证规则（密码复杂度和登录锁定）
//! - `token`: 令牌生成与校验（JWT Claims 签发、动态扩展 Claims、JWKS 公钥导出）
//! - `factor::oidc`: OIDC / OAuth2 登录因子（发现、授权码、PKCE、state、nonce）
//! - `store`: 存储契约 Trait（零数据库硬依赖，由外部调用方按需实现）
//! - `risk`: 自适应风险风控决策引擎（异地登录、设备指纹、暴力尝试自适应 Step-up MFA 与阻断）
//! - `audit`: 企业级安全审计事件标准（对齐 SOC 2 / 等保 2.0 三级标准）

pub mod audit;
pub mod error;
pub mod factor;
pub mod pipeline;
pub mod pkg;
pub mod risk;
pub mod rules;
pub mod store;
pub mod token;
pub mod types;
pub mod validator;

pub use audit::{AuditEvent, AuditEventType, AuditOutcome};
pub use error::{IdpError, Result};
pub use factor::basic::magic::{MagicLinkConfig, MagicLinkPayload, MagicLinkService};
pub use factor::enterprise::{Device, DeviceProof};
pub use factor::oidc::{Nonce, Pkce, State};
pub use pipeline::{
    Codes, Context, Edge, EdgeConfig, Event, Fallback, Join, Kind, Node, NodeConfig, Op, Output,
    Pipeline, PipelineConfig, Progress, Run, Runner, Services,
};
pub use pkg::password::{Algorithm, Argon2id, Bcrypt, Codec, Password, Pbkdf2, Sm3};
pub use pkg::recovery::RecoveryCode;
pub use pkg::rsa::RsaCrypto;
pub use pkg::totp::Totp;
pub use risk::{RiskAssessment, RiskConfig, RiskDecision, RiskEngine, UserHistory};
pub use rules::{Reauth, Rules};
pub use store::Devices;
pub use store::{Clients, Events, Factors, Limits, Passkeys, Secrets, Users};
pub use types::{
    AuthCode, AuthResult, AuthUser, Identity, Level, Method, OAuthClient, TotpBinding,
};
pub use validator::issuer::{CaptchaIssuer, CodeIssuer, RecoveryIssuer, Scene, TotpIssuer};
pub use validator::sender::sms::{BoxFuture, Sender, SmsConfig, SmsSender};
pub use validator::sender::{NotificationService, NotifyChannel};
pub use validator::sender::{SmtpConfig, SmtpSender};
pub use validator::verifier::Passcode;
pub use validator::verifier::captcha::CaptchaVerifier;
pub use validator::verifier::captcha::{CaptchaChallenge, CaptchaType, CaptchaVerifyReq};
pub use validator::verifier::{
    Recovery as RecoveryVerifier, Start, Totp as TotpVerifier, WebAuthn,
};

/// 对外统一命名空间：`halo::bridge::*`。
pub mod bridge {
    pub use crate::audit;
    pub use crate::error;
    pub use crate::factor;
    pub use crate::pipeline;
    pub use crate::pkg;
    pub use crate::risk;
    pub use crate::rules;
    pub use crate::store;
    pub use crate::token;
    pub use crate::types;
    pub use crate::validator;

    pub use crate::{
        Algorithm, Argon2id, AuditEvent, AuditEventType, AuditOutcome, Bcrypt, BoxFuture,
        CaptchaChallenge, CaptchaIssuer, CaptchaType, CaptchaVerifier, CaptchaVerifyReq, Clients,
        CodeIssuer, Codec, Codes, Context, Device, DeviceProof, Devices, Edge, EdgeConfig, Event,
        Events, Factors, Fallback, Identity, IdpError, Join, Kind, Limits, Method, Node,
        NodeConfig, Nonce, NotificationService, OAuthClient, Op, Output, Passcode, Passkeys,
        Password, Pbkdf2, Pipeline, PipelineConfig, Progress, Reauth, RecoveryCode, RecoveryIssuer,
        RecoveryVerifier, Result, RiskAssessment, RiskConfig, RiskDecision, RiskEngine, Run,
        Runner, Scene, Secrets, Sender, Services, Sm3, SmsConfig, SmsSender, SmtpConfig,
        SmtpSender, Start, State, Totp, TotpIssuer, TotpVerifier, Users, WebAuthn,
    };
    pub use crate::{AuthCode, AuthResult, AuthUser, Level, Rules, TotpBinding};
}
