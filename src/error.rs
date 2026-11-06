use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdpError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("User not found")]
    UserNotFound,

    #[error("User is disabled or locked")]
    UserDisabled,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Invalid verification code")]
    InvalidVerificationCode,

    #[error("Verification code expired")]
    VerificationCodeExpired,

    #[error("OAuth provider error: {0}")]
    OAuthError(String),

    #[error("LDAP error: {0}")]
    LdapError(String),

    #[error("Invalid client: {0}")]
    InvalidClient(String),

    #[error("Invalid redirect URI: {0}")]
    InvalidRedirectUri(String),

    #[error("Invalid authorization code")]
    InvalidCode,

    #[error("Invalid PKCE code verifier")]
    InvalidPkce,

    #[error("Token error: {0}")]
    TokenError(String),

    #[error("Store error: {0}")]
    StoreError(String),

    #[error("Captcha validation failed: {0}")]
    CaptchaFailed(String),

    #[error("Captcha expired or not found")]
    CaptchaExpired,

    #[error("Email sending failed: {0}")]
    EmailFailed(String),

    #[error("SMS sending failed: {0}")]
    SmsFailed(String),

    #[error("Passkey/WebAuthn error: {0}")]
    WebAuthnError(String),

    #[error("Identity sync error: {0}")]
    SyncError(String),

    #[error("Magic link error: {0}")]
    MagicLinkError(String),

    #[error("Risk engine assessment blocked: {0}")]
    RiskBlocked(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, IdpError>;
