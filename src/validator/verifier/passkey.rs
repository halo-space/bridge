use crate::error::Result;
use crate::factor::passkey::Passkey as StoredPasskey;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use url::Url;
use webauthn_rs::prelude::{
    Passkey as NativePasskey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn, WebauthnBuilder,
};

/// Passkey 注册结果和认证结果校验器。
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

    /// 校验注册结果并转换为调用方可保存的凭证模型。
    pub fn register(&self, input: &str, state: &str) -> Result<StoredPasskey> {
        let input: RegisterPublicKeyCredential = serde_json::from_str(input)
            .map_err(|e| crate::error::Error::WebAuthnError(e.to_string()))?;
        let state: RegisterState = serde_json::from_str(state)
            .map_err(|e| crate::error::Error::WebAuthnError(e.to_string()))?;
        let RegisterState {
            state,
            subject,
            user_handle,
            display_name,
        } = state;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&input, &state)
            .map_err(|e| crate::error::Error::WebAuthnError(e.to_string()))?;
        let data = serde_json::to_string(&passkey)
            .map_err(|e| crate::error::Error::Internal(e.to_string()))?;
        let info: NativeInfo = serde_json::from_str(&data)
            .map_err(|e| crate::error::Error::Internal(e.to_string()))?;
        let public_key = serde_json::to_string(passkey.get_public_key())
            .map_err(|e| crate::error::Error::Internal(e.to_string()))?;
        Ok(StoredPasskey {
            subject,
            credential_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(passkey.cred_id()),
            public_key,
            sign_count: 0,
            transports: Vec::new(),
            aaguid: None,
            user_handle: Some(user_handle),
            display_name: Some(display_name),
            created_at: Utc::now().timestamp(),
            last_used_at: None,
            passwordless: false,
            user_verified: info.cred.user_verified,
            backup_eligible: info.cred.backup_eligible,
            backup_state: info.cred.backup_state,
            data: Some(data),
        })
    }

    /// 校验认证结果并返回计数器和最新凭证状态。
    pub fn verify(&self, input: &str, state: &str) -> Result<Auth> {
        let input: PublicKeyCredential = serde_json::from_str(input)
            .map_err(|e| crate::error::Error::WebAuthnError(e.to_string()))?;
        let state: AuthState = serde_json::from_str(state)
            .map_err(|e| crate::error::Error::WebAuthnError(e.to_string()))?;
        let AuthState { state, passkeys } = state;
        let result = self
            .webauthn
            .finish_passkey_authentication(&input, &state)
            .map_err(|e| crate::error::Error::WebAuthnError(e.to_string()))?;
        let data = passkeys
            .into_iter()
            .find(|passkey| passkey.cred_id() == result.cred_id())
            .map(|mut passkey| {
                passkey.update_credential(&result);
                serde_json::to_string(&passkey)
                    .map_err(|e| crate::error::Error::Internal(e.to_string()))
            })
            .transpose()?;
        Ok(Auth {
            credential_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(result.cred_id()),
            counter: result.counter(),
            at: Utc::now().timestamp(),
            user_verified: result.user_verified(),
            backup_eligible: result.backup_eligible(),
            backup_state: result.backup_state(),
            needs_update: result.needs_update(),
            data,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth {
    pub credential_id: String,
    pub counter: u32,
    pub at: i64,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub needs_update: bool,
    pub data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NativeInfo {
    #[serde(default)]
    cred: CredentialInfo,
}

#[derive(Debug, Default, Deserialize)]
struct CredentialInfo {
    #[serde(default)]
    user_verified: bool,
    #[serde(default)]
    backup_eligible: bool,
    #[serde(default)]
    backup_state: bool,
}
