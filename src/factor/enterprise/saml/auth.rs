use super::{SamlAssertion, SamlConfig};
use crate::error::{Error, Result};
use crate::types::Identity;
use saml::binding::{Binding, SsoResponseBinding, SsoResponseEndpoint};
use saml::descriptor::IdpDescriptor;
use saml::dsig::algorithms::{DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm};
use saml::nameid::NameIdFormat;
use saml::replay::{ReplayCache, ReplayMode};
use saml::sp::{
    ConsumeResponse, LoginTracker, ServiceProvider, ServiceProviderConfig, SpWantSigned, StartLogin,
};
use std::time::{Duration, SystemTime};

pub struct SamlAuth {
    sp: ServiceProvider,
    idp: IdpDescriptor,
    acs: String,
}

impl SamlAuth {
    pub fn new(config: &SamlConfig) -> Result<Self> {
        let idp = IdpDescriptor::from_metadata_xml(config.metadata.as_bytes())
            .map_err(|e| Error::OAuthError(format!("Invalid SAML metadata: {e}")))?;
        if idp.entity_id != config.idp_entity_id {
            return Err(Error::OAuthError("SAML IdP entity mismatch".into()));
        }
        if !idp
            .sso_endpoints
            .iter()
            .any(|endpoint| endpoint.url == config.idp_sso_url)
        {
            return Err(Error::OAuthError("SAML SSO endpoint mismatch".into()));
        }
        let sp = ServiceProvider::new(ServiceProviderConfig {
            entity_id: config.sp_entity_id.clone(),
            acs: vec![SsoResponseEndpoint::post(
                config.sp_acs_url.clone(),
                0,
                true,
            )],
            slo: Vec::new(),
            name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
            signing_key: None,
            decryption_key: None,
            sign_authn_requests: false,
            want_signed: SpWantSigned {
                response: false,
                assertions: true,
            },
            allow_unsolicited: true,
            default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
            outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
            outbound_digest_algorithm: DigestAlgorithm::Sha256,
        })
        .map_err(|e| Error::OAuthError(format!("Invalid SAML service provider: {e}")))?;
        Ok(Self {
            sp,
            idp,
            acs: config.sp_acs_url.clone(),
        })
    }

    /// 校验 SAML 响应并使用调用方提供的原子重放缓存。
    pub fn check(
        &self,
        response: &[u8],
        now: SystemTime,
        replay_cache: &dyn ReplayCache,
    ) -> Result<SamlAssertion> {
        self.check_inner(response, now, None, Some(replay_cache))
    }

    /// 发起 SP 登录，返回需要由调用方保存的 tracker。
    pub fn start(
        &self,
        relay_state: Option<&str>,
    ) -> Result<(saml::binding::Dispatch, LoginTracker)> {
        let started = self
            .sp
            .start_login(
                &self.idp,
                StartLogin {
                    relay_state,
                    binding: Binding::HttpPost,
                    force_authn: false,
                    is_passive: false,
                    requested_name_id_format: Some(NameIdFormat::EmailAddress),
                    requested_authn_context: None,
                    acs_index: None,
                    acs_url: None,
                    response_binding: Some(SsoResponseBinding::HttpPost),
                },
            )
            .map_err(|e| Error::OAuthError(format!("SAML login start rejected: {e}")))?;
        Ok((started.dispatch, started.tracker))
    }

    /// 校验 SP 发起响应，强制关联 tracker 和 replay cache。
    pub fn check_state(
        &self,
        response: &[u8],
        now: SystemTime,
        tracker: &LoginTracker,
        replay_cache: &dyn ReplayCache,
    ) -> Result<SamlAssertion> {
        self.check_inner(response, now, Some(tracker), Some(replay_cache))
    }

    fn check_inner(
        &self,
        response: &[u8],
        now: SystemTime,
        tracker: Option<&LoginTracker>,
        replay_cache: Option<&dyn ReplayCache>,
    ) -> Result<SamlAssertion> {
        let identity = self
            .sp
            .consume_response(ConsumeResponse {
                idp: &self.idp,
                peer_crypto_policy: None,
                saml_response: response,
                binding: SsoResponseBinding::HttpPost,
                relay_state: None,
                tracker,
                expected_destination: &self.acs,
                now,
                clock_skew: Duration::from_secs(60),
                replay_cache,
                replay_mode: ReplayMode::All,
                holder_of_key_cert: None,
            })
            .map_err(|e| Error::OAuthError(format!("SAML response rejected: {e}")))?;

        let mut email = None;
        let mut display_name = None;
        let mut attributes = serde_json::Map::new();
        for attribute in identity.attributes() {
            let key = attribute
                .friendly_name
                .as_deref()
                .unwrap_or(&attribute.name)
                .to_string();
            attributes.insert(key.clone(), serde_json::json!(attribute.values));
            if email.is_none() && matches!(key.as_str(), "mail" | "email" | "emailAddress") {
                email = attribute.values.first().cloned();
            }
            if display_name.is_none() && matches!(key.as_str(), "displayName" | "name") {
                display_name = attribute.values.first().cloned();
            }
        }
        Ok(SamlAssertion {
            name_id: identity.name_id().value.clone(),
            session_index: identity.session_index().map(str::to_string),
            email,
            display_name,
            attributes: serde_json::Value::Object(attributes),
            assertion_id: Some(identity.assertion_id().to_string()),
            expires_at: identity
                .not_on_or_after()
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_secs() as i64),
        })
    }

    pub fn identity(
        &self,
        response: &[u8],
        now: SystemTime,
        replay_cache: &dyn ReplayCache,
    ) -> Result<Identity> {
        Ok(self.check(response, now, replay_cache)?.identity())
    }
}
