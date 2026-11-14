use super::{SamlAssertion, SamlConfig};
use crate::error::{Error, Result};
use crate::types::Identity;
use base64::Engine as _;
use saml::{
    AcsEndpoint, AssertionSignaturePolicy, BrowserInput, EntityId, FormField, IdpDescriptor,
    MetadataTrustPolicy, PendingAuthnRequest, PendingSnapshot, RelayStateParam, ReplayCache,
    ReplayPolicy, Saml, SamlValidationContext, Sp, SpConfig, SpValidationPolicy, SsoResponse,
    StartSso,
};
use std::time::SystemTime;

/// Browser action returned by [`SamlAuth::start`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dispatch {
    /// HTTP-POST form fields that the caller renders or submits.
    Post {
        action: String,
        fields: Vec<(String, String)>,
    },
    /// HTTP-Redirect URL that the caller sends the browser to.
    Redirect(String),
}

/// Minimal state needed to correlate an SP-initiated SAML response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Tracker {
    request_id: String,
    relay_state: Option<String>,
}

impl Tracker {
    /// SAML AuthnRequest ID.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

/// SAML service provider adapter backed by `saml-rs`.
pub struct SamlAuth {
    sp: Saml<Sp>,
    idp: IdpDescriptor,
    idp_entity_id: String,
    acs: String,
}

impl SamlAuth {
    /// Build an adapter from caller-provided IdP metadata and endpoint policy.
    pub fn new(config: &SamlConfig) -> Result<Self> {
        let idp_entity = EntityId::try_new(config.idp_entity_id.clone())
            .map_err(|e| Error::OAuthError(format!("Invalid SAML IdP entity: {e}")))?;
        let idp = IdpDescriptor::from_metadata_xml_for(
            idp_entity.clone(),
            &config.metadata,
            MetadataTrustPolicy::UnsignedForCompatibility,
        )
        .map_err(|e| Error::OAuthError(format!("Invalid SAML metadata: {e}")))?;
        let sso = idp
            .metadata()
            .get_single_sign_on_service(saml::raw::Binding::Post)
            .ok_or_else(|| {
                Error::OAuthError("SAML metadata has no HTTP-POST SSO endpoint".into())
            })?;
        if sso != config.idp_sso_url {
            return Err(Error::OAuthError("SAML SSO endpoint mismatch".into()));
        }

        let sp_entity = EntityId::try_new(config.sp_entity_id.clone())
            .map_err(|e| Error::OAuthError(format!("Invalid SAML service provider entity: {e}")))?;
        let acs = AcsEndpoint::post(config.sp_acs_url.clone())
            .map_err(|e| Error::OAuthError(format!("Invalid SAML ACS endpoint: {e}")))?;
        let mut validation = SpValidationPolicy::recommended();
        validation.assertions = AssertionSignaturePolicy::RequireSigned;
        let sp_config = SpConfig::builder(sp_entity)
            .acs_endpoint(acs)
            .validation(validation)
            .build()
            .map_err(|e| Error::OAuthError(format!("Invalid SAML service provider: {e}")))?;
        let sp = Saml::sp(sp_config)
            .map_err(|e| Error::OAuthError(format!("Invalid SAML service provider: {e}")))?;

        Ok(Self {
            sp,
            idp,
            idp_entity_id: config.idp_entity_id.clone(),
            acs: config.sp_acs_url.clone(),
        })
    }

    /// Validate an unsolicited IdP response with caller-owned replay storage.
    pub fn check(
        &self,
        response: &[u8],
        now: SystemTime,
        replay: &mut dyn ReplayCache,
    ) -> Result<SamlAssertion> {
        self.finish(
            BrowserInput::<SsoResponse>::post(vec![FormField::new(
                "SAMLResponse",
                base64::engine::general_purpose::STANDARD.encode(response),
            )]),
            None,
            now,
            replay,
        )
    }

    /// Start SP-initiated login and return browser dispatch plus correlation state.
    pub fn start(&self, relay_state: Option<&str>) -> Result<(Dispatch, Tracker)> {
        let relay = RelayStateParam::try_from_option(relay_state.map(str::to_string))
            .map_err(|e| Error::OAuthError(format!("Invalid SAML relay state: {e}")))?;
        let started = self
            .sp
            .start_sso(&self.idp, StartSso::post().relay_state(relay))
            .map_err(|e| Error::OAuthError(format!("SAML login start rejected: {e}")))?;
        let tracker = Tracker {
            request_id: started.pending.request_id().as_str().to_string(),
            relay_state: started.pending.relay_state().as_deref().map(str::to_string),
        };
        let form = started
            .outbound
            .post_form()
            .map_err(|e| Error::OAuthError(format!("SAML POST form unavailable: {e}")))?;
        let fields = form
            .fields()
            .iter()
            .map(|field| (field.name().to_string(), field.value().to_string()))
            .collect();
        Ok((
            Dispatch::Post {
                action: form.action().as_str().to_string(),
                fields,
            },
            tracker,
        ))
    }

    /// Validate a response against an SP-issued tracker and consume replay keys.
    pub fn check_state(
        &self,
        response: &[u8],
        now: SystemTime,
        tracker: &Tracker,
        replay: &mut dyn ReplayCache,
    ) -> Result<SamlAssertion> {
        self.finish(
            BrowserInput::<SsoResponse>::post(vec![FormField::new(
                "SAMLResponse",
                base64::engine::general_purpose::STANDARD.encode(response),
            )]),
            Some(tracker),
            now,
            replay,
        )
    }

    /// Convert a validated assertion to bridge's common identity shape.
    pub fn identity(
        &self,
        response: &[u8],
        now: SystemTime,
        replay: &mut dyn ReplayCache,
    ) -> Result<Identity> {
        Ok(self.check(response, now, replay)?.identity())
    }

    fn finish(
        &self,
        input: BrowserInput<SsoResponse>,
        tracker: Option<&Tracker>,
        now: SystemTime,
        replay: &mut dyn ReplayCache,
    ) -> Result<SamlAssertion> {
        let validation = SamlValidationContext::new(now, ReplayPolicy::RequireCache(replay));
        let session = match tracker {
            Some(tracker) => {
                let relay = RelayStateParam::try_from_option(tracker.relay_state.clone())
                    .map_err(|e| Error::OAuthError(format!("Invalid SAML relay state: {e}")))?;
                let snapshot = PendingSnapshot::<saml::AuthnRequest>::authn_request(
                    tracker.request_id.clone(),
                    relay,
                    self.idp_entity_id.clone(),
                    "post",
                    self.acs.clone(),
                    "post",
                );
                let pending = PendingAuthnRequest::from_snapshot(snapshot)
                    .map_err(|e| Error::OAuthError(format!("Invalid SAML tracker: {e}")))?;
                self.sp
                    .finish_sso(&self.idp, &pending, input, validation)
                    .map_err(|e| Error::OAuthError(format!("SAML response rejected: {e}")))?
            }
            None => self
                .sp
                .accept_unsolicited_sso(&self.idp, input, validation)
                .map_err(|e| Error::OAuthError(format!("SAML response rejected: {e}")))?,
        };
        Ok(assertion(&session))
    }
}

fn assertion(session: &saml::SsoSession) -> SamlAssertion {
    let mut email = None;
    let mut display_name = None;
    let mut attributes = serde_json::Map::new();
    for attribute in session.attributes().as_slice() {
        let values: Vec<String> = attribute
            .values()
            .iter()
            .map(|value| value.as_str().to_string())
            .collect();
        let key = attribute.name().to_string();
        if email.is_none()
            && matches!(
                key.as_str(),
                "mail"
                    | "email"
                    | "emailAddress"
                    | "urn:oid:0.9.2342.19200300.100.1.3"
                    | "0.9.2342.19200300.100.1.3"
            )
        {
            email = values.first().cloned();
        }
        if display_name.is_none()
            && matches!(
                key.as_str(),
                "displayName"
                    | "name"
                    | "urn:oid:2.16.840.1.113730.3.1.241"
                    | "2.16.840.1.113730.3.1.241"
            )
        {
            display_name = values.first().cloned();
        }
        attributes.insert(key, serde_json::json!(values));
    }
    let expires_at = session
        .not_on_or_after()
        .and_then(|instant| chrono::DateTime::parse_from_rfc3339(instant.as_str()).ok())
        .map(|instant| instant.timestamp());
    SamlAssertion {
        name_id: session.name_id().value().to_string(),
        session_index: session
            .authn_session()
            .session_index()
            .map(|value| value.as_str().to_string()),
        email,
        display_name,
        attributes: serde_json::Value::Object(attributes),
        assertion_id: Some(session.assertion_id().as_str().to_string()),
        expires_at,
    }
}
