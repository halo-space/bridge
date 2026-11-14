use crate::error::Result;
use crate::factor::passkey::Passkey as StoredPasskey;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey as NativePasskey, PasskeyAuthentication, PasskeyRegistration, Webauthn, WebauthnBuilder,
};

/// Passkey 注册和认证选项签发器。
pub struct Passkey {
    webauthn: Webauthn,
}

impl Passkey {
    pub fn new(rp_id: &str, origin: &str, name: &str) -> Result<Self> {
        let origin =
            Url::parse(origin).map_err(|e| crate::error::Error::WebAuthnError(e.to_string()))?;
        let mut builder = WebauthnBuilder::new(rp_id, &origin)
            .map_err(|e| crate::error::Error::WebAuthnError(e.to_string()))?;
        builder = builder.rp_name(name);
        let webauthn = builder
            .build()
            .map_err(|e| crate::error::Error::WebAuthnError(e.to_string()))?;
        Ok(Self { webauthn })
    }

    /// 为新凭证签发注册选项和结构化状态。
    pub fn issue(&self, subject: &str, name: &str, display_name: &str) -> Result<Start> {
        if subject.trim().is_empty() {
            return Err(crate::error::Error::WebAuthnError(
                "User subject cannot be empty".into(),
            ));
        }
        let user_handle = Uuid::new_v4();
        let (options, state) = self
            .webauthn
            .start_passkey_registration(user_handle, name, display_name, None)
            .map_err(|e| crate::error::Error::WebAuthnError(e.to_string()))?;
        let state = RegisterState {
            state,
            subject: subject.to_string(),
            user_handle: user_handle.to_string(),
            display_name: display_name.to_string(),
        };
        Ok(Start {
            options: serde_json::to_value(options)
                .map_err(|e| crate::error::Error::Internal(e.to_string()))?,
            state: serde_json::to_string(&state)
                .map_err(|e| crate::error::Error::Internal(e.to_string()))?,
        })
    }

    /// 为已登记凭证签发认证请求选项和结构化状态。
    pub fn request(&self, passkeys: &[StoredPasskey]) -> Result<Start> {
        let passkeys: Vec<NativePasskey> = passkeys
            .iter()
            .map(|passkey| {
                let data = passkey.data.as_deref().ok_or_else(|| {
                    crate::error::Error::WebAuthnError("Missing Passkey data".into())
                })?;
                serde_json::from_str(data)
                    .map_err(|e| crate::error::Error::WebAuthnError(e.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| crate::error::Error::WebAuthnError(e.to_string()))?;
        Ok(Start {
            options: serde_json::to_value(options)
                .map_err(|e| crate::error::Error::Internal(e.to_string()))?,
            state: serde_json::to_string(&AuthState { state, passkeys })
                .map_err(|e| crate::error::Error::Internal(e.to_string()))?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegisterState {
    state: PasskeyRegistration,
    subject: String,
    user_handle: String,
    display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthState {
    state: PasskeyAuthentication,
    passkeys: Vec<NativePasskey>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Start {
    pub options: serde_json::Value,
    pub state: String,
}
