use crate::error::Result;
use crate::factor::passkey::Passkey as StoredPasskey;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey as NativePasskey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn, WebauthnBuilder,
};

/// 标准 WebAuthn 注册和认证。
pub struct WebAuthn {
    webauthn: Webauthn,
}

impl WebAuthn {
    pub fn new(rp_id: &str, origin: &str, name: &str) -> Result<Self> {
        let origin =
            Url::parse(origin).map_err(|e| crate::error::IdpError::WebAuthnError(e.to_string()))?;
        let mut builder = WebauthnBuilder::new(rp_id, &origin)
            .map_err(|e| crate::error::IdpError::WebAuthnError(e.to_string()))?;
        builder = builder.rp_name(name);
        let webauthn = builder
            .build()
            .map_err(|e| crate::error::IdpError::WebAuthnError(e.to_string()))?;
        Ok(Self { webauthn })
    }

    pub fn issue(&self, user_id: &str, name: &str, display_name: &str) -> Result<Start> {
        let user_id = Uuid::parse_str(user_id)
            .map_err(|e| crate::error::IdpError::WebAuthnError(format!("Invalid user id: {e}")))?;
        let (options, state) = self
            .webauthn
            .start_passkey_registration(user_id, name, display_name, None)
            .map_err(|e| crate::error::IdpError::WebAuthnError(e.to_string()))?;
        let state = RegisterState {
            state,
            user_handle: user_id.to_string(),
            display_name: display_name.to_string(),
        };
        Ok(Start {
            options: serde_json::to_value(options)
                .map_err(|e| crate::error::IdpError::Internal(e.to_string()))?,
            state: serde_json::to_string(&state)
                .map_err(|e| crate::error::IdpError::Internal(e.to_string()))?,
        })
    }

    pub fn register(&self, input: &str, state: &str) -> Result<StoredPasskey> {
        let input: RegisterPublicKeyCredential = serde_json::from_str(input)
            .map_err(|e| crate::error::IdpError::WebAuthnError(e.to_string()))?;
        let (state, user_handle, display_name) = match serde_json::from_str::<RegisterState>(state)
        {
            Ok(state) => (
                state.state,
                Some(state.user_handle),
                Some(state.display_name),
            ),
            Err(_) => (
                serde_json::from_str::<PasskeyRegistration>(state)
                    .map_err(|e| crate::error::IdpError::WebAuthnError(e.to_string()))?,
                None,
                None,
            ),
        };
        let passkey = self
            .webauthn
            .finish_passkey_registration(&input, &state)
            .map_err(|e| crate::error::IdpError::WebAuthnError(e.to_string()))?;
        let data = serde_json::to_string(&passkey)
            .map_err(|e| crate::error::IdpError::Internal(e.to_string()))?;
        let info: NativeInfo = serde_json::from_str(&data)
            .map_err(|e| crate::error::IdpError::Internal(e.to_string()))?;
        let public_key = serde_json::to_string(passkey.get_public_key())
            .map_err(|e| crate::error::IdpError::Internal(e.to_string()))?;
        Ok(StoredPasskey {
            credential_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(passkey.cred_id()),
            public_key,
            sign_count: 0,
            transports: Vec::new(),
            aaguid: None,
            user_handle,
            display_name,
            created_at: Utc::now().timestamp(),
            last_used_at: None,
            passwordless: false,
            user_verified: info.cred.user_verified,
            backup_eligible: info.cred.backup_eligible,
            backup_state: info.cred.backup_state,
            data: Some(data),
        })
    }

    pub fn request(&self, passkeys: &[StoredPasskey]) -> Result<Start> {
        let passkeys: Vec<NativePasskey> = passkeys
            .iter()
            .map(|passkey| {
                let data = passkey.data.as_deref().ok_or_else(|| {
                    crate::error::IdpError::WebAuthnError("Missing Passkey data".into())
                })?;
                serde_json::from_str(data)
                    .map_err(|e| crate::error::IdpError::WebAuthnError(e.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| crate::error::IdpError::WebAuthnError(e.to_string()))?;
        Ok(Start {
            options: serde_json::to_value(options)
                .map_err(|e| crate::error::IdpError::Internal(e.to_string()))?,
            state: serde_json::to_string(&state)
                .map_err(|e| crate::error::IdpError::Internal(e.to_string()))?,
        })
    }

    pub fn verify(&self, input: &str, state: &str) -> Result<Auth> {
        let input: PublicKeyCredential = serde_json::from_str(input)
            .map_err(|e| crate::error::IdpError::WebAuthnError(e.to_string()))?;
        let state: PasskeyAuthentication = serde_json::from_str(state)
            .map_err(|e| crate::error::IdpError::WebAuthnError(e.to_string()))?;
        let result = self
            .webauthn
            .finish_passkey_authentication(&input, &state)
            .map_err(|e| crate::error::IdpError::WebAuthnError(e.to_string()))?;
        Ok(Auth {
            credential_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(result.cred_id()),
            counter: result.counter(),
            at: Utc::now().timestamp(),
            user_verified: result.user_verified(),
            backup_eligible: result.backup_eligible(),
            backup_state: result.backup_state(),
            needs_update: result.needs_update(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegisterState {
    state: PasskeyRegistration,
    user_handle: String,
    display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Start {
    pub options: serde_json::Value,
    pub state: String,
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
