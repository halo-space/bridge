//! # bridge
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
pub use error::{Error, Result};
pub use factor::basic::magic::{MagicLinkConfig, MagicLinkPayload};
#[cfg(feature = "enterprise")]
pub use factor::enterprise::{Device, DeviceProof};
pub use factor::oidc::{Nonce, Pkce, State};
#[cfg(feature = "full")]
pub use pipeline::Services;
pub use pipeline::{
    Arg, Card, Cards, Claim, Context, Edge, EdgeConfig, Effect, Effects, Event, Fallback, Join,
    Kind, Node, NodeConfig, Op, Output, Pipeline, PipelineConfig, Progress, Resolve, Run, Runner,
    Secret, Sensitive, secret,
};
pub use pkg::password::{Algorithm, Argon2id, Bcrypt, Codec, Codecs, Password, Pbkdf2, Sm3};
pub use pkg::recovery::RecoveryCode;
pub use pkg::rsa::Rsa;
pub use pkg::totp::Totp;
pub use risk::{RiskAssessment, RiskConfig, RiskDecision, RiskEngine, UserHistory};
pub use rules::{Reauth, Rules};
pub use store::Devices;
pub use store::{Clients, Decision, Events, Factors, Limits, Noop, Passkeys, Rule, Secrets, Users};
pub use types::{AuthCode, AuthResult, Identity, Level, Method, OAuthClient, TotpBinding, User};
pub use validator::issuer::Scene;
#[cfg(feature = "passkey")]
pub use validator::issuer::Start;
#[cfg(feature = "sms")]
pub use validator::sender::sms::{BoxFuture, Sender, SmsConfig, SmsSender};
#[cfg(all(feature = "mail", feature = "sms"))]
pub use validator::sender::{Notify, NotifyChannel};
#[cfg(feature = "mail")]
pub use validator::sender::{SmtpConfig, SmtpSender};
#[cfg(feature = "passkey")]
pub use validator::verifier::Auth;
pub use validator::verifier::Passcode;
pub use validator::verifier::captcha::{CaptchaChallenge, CaptchaType, CaptchaVerifyReq};

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

    #[cfg(feature = "full")]
    pub use crate::Services;
    pub use crate::{
        Algorithm, Arg, Argon2id, AuditEvent, AuditEventType, AuditOutcome, Bcrypt,
        CaptchaChallenge, CaptchaType, CaptchaVerifyReq, Card, Cards, Claim, Clients, Codec,
        Codecs, Context, Decision, Devices, Edge, EdgeConfig, Effect, Effects, Error, Event,
        Events, Factors, Fallback, Identity, Join, Kind, Limits, Method, Node, NodeConfig, Nonce,
        Noop, OAuthClient, Op, Output, Passcode, Passkeys, Password, Pbkdf2, Pipeline,
        PipelineConfig, Progress, Reauth, RecoveryCode, Resolve, Result, RiskAssessment,
        RiskConfig, RiskDecision, RiskEngine, Rule, Run, Runner, Scene, Secret, Secrets, Sensitive,
        Sm3, Totp, Users, secret,
    };
    #[cfg(feature = "passkey")]
    pub use crate::{Auth, Start};
    pub use crate::{AuthCode, AuthResult, Level, Rules, TotpBinding, User};
    #[cfg(feature = "sms")]
    pub use crate::{BoxFuture, Sender, SmsConfig, SmsSender};
    #[cfg(feature = "enterprise")]
    pub use crate::{Device, DeviceProof};
    #[cfg(all(feature = "mail", feature = "sms"))]
    pub use crate::{Notify, NotifyChannel};
    #[cfg(feature = "mail")]
    pub use crate::{SmtpConfig, SmtpSender};
}
