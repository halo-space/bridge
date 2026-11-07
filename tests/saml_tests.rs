use base64::Engine as _;
use bridge::factor::enterprise::{SamlAuth, SamlConfig};
use saml::attribute::Attribute;
use saml::authn_context::AuthnContextClassRef;
use saml::binding::{Binding, Dispatch, Endpoint, SsoResponseDispatch, SsoResponseEndpoint};
use saml::crypto::cert::X509Certificate;
use saml::crypto::keypair::KeyPair;
use saml::descriptor::SpDescriptor;
use saml::dsig::algorithms::{
    C14nAlgorithm, DigestAlgorithm, PeerCryptoPolicy, SignatureAlgorithm,
};
use saml::idp::{ConsumeAuthnRequest, IdentityProvider, IdentityProviderConfig, IssueResponse};
use saml::nameid::{NameId, NameIdFormat};
use saml::replay::InMemoryReplayCache;
use saml::sp::{ServiceProvider, ServiceProviderConfig, SpWantSigned};
use std::time::Duration;

const IDP_ENTITY: &str = "https://idp.example.com/bridge";
const IDP_SSO: &str = "https://idp.example.com/bridge/sso";
const SP_ENTITY: &str = "https://sp.example.com/bridge";
const SP_ACS: &str = "https://sp.example.com/bridge/acs";

fn key() -> KeyPair {
    let key = KeyPair::from_pkcs8_pem(include_bytes!("fixtures/saml_key.pem")).unwrap();
    let cert = X509Certificate::from_pem(include_bytes!("fixtures/saml_cert.pem")).unwrap();
    key.with_certificate(cert).unwrap()
}

fn idp() -> IdentityProvider {
    IdentityProvider::new(IdentityProviderConfig {
        entity_id: IDP_ENTITY.into(),
        sso: vec![Endpoint::post(IDP_SSO, 0, true)],
        slo: vec![],
        artifact_resolution: vec![],
        supported_name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
        default_name_id_format: NameIdFormat::EmailAddress,
        signing_key: key(),
        decryption_key: None,
        want_authn_requests_signed: false,
        assertion_signing: bridge_assertion_signing(),
        encrypt_assertions_when_possible: false,
        default_session_duration: Duration::from_secs(3600),
        max_authn_request_age: IdentityProviderConfig::DEFAULT_MAX_AUTHN_REQUEST_AGE,
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
        outbound_c14n: C14nAlgorithm::ExclusiveCanonical,
    })
    .unwrap()
}

fn bridge_assertion_signing() -> saml::IdpAssertionSigning {
    saml::IdpAssertionSigning {
        sign_responses: false,
        sign_assertions: true,
    }
}

fn sp() -> ServiceProvider {
    ServiceProvider::new(ServiceProviderConfig {
        entity_id: SP_ENTITY.into(),
        acs: vec![SsoResponseEndpoint::post(SP_ACS, 0, true)],
        slo: vec![],
        name_id_formats: vec![NameIdFormat::Persistent, NameIdFormat::EmailAddress],
        signing_key: None,
        decryption_key: None,
        sign_authn_requests: false,
        want_signed: SpWantSigned {
            response: false,
            assertions: true,
        },
        allow_unsolicited: false,
        default_peer_crypto_policy: PeerCryptoPolicy::strong_defaults(),
        outbound_signature_algorithm: SignatureAlgorithm::RsaSha256,
        outbound_digest_algorithm: DigestAlgorithm::Sha256,
    })
    .unwrap()
}

#[test]
fn saml_sp_state_round_trip() {
    let saml = SamlAuth::new(&SamlConfig {
        idp_entity_id: IDP_ENTITY.into(),
        idp_sso_url: IDP_SSO.into(),
        metadata: include_str!("fixtures/saml_metadata.xml").into(),
        sp_entity_id: SP_ENTITY.into(),
        sp_acs_url: SP_ACS.into(),
    })
    .unwrap();
    let (dispatch, tracker) = saml.start(Some("bridge-state")).unwrap();
    let request = match dispatch {
        Dispatch::Post(form) => base64::engine::general_purpose::STANDARD
            .decode(form.saml_request.unwrap())
            .unwrap(),
        Dispatch::Redirect(_) => panic!("expected POST request"),
    };

    let idp = idp();
    let sp = sp();
    let sp_desc =
        SpDescriptor::from_metadata_xml(sp.metadata_xml(false).unwrap().as_bytes()).unwrap();
    let now = std::time::SystemTime::now();
    let parsed = idp
        .consume_authn_request(ConsumeAuthnRequest {
            sp: &sp_desc,
            peer_crypto_policy: None,
            max_authn_request_age: None,
            saml_request: &request,
            binding: Binding::HttpPost,
            relay_state: Some("bridge-state"),
            detached_signature: None,
            expected_destination: IDP_SSO,
            now,
            clock_skew: Duration::from_secs(60),
        })
        .unwrap();
    let response = idp
        .issue_response(IssueResponse {
            sp: &sp_desc,
            in_response_to: &parsed,
            name_id: NameId::email("alice@example.com"),
            attributes: vec![Attribute::email("alice@example.com")],
            authn_instant: now,
            session_index: "bridge-state-session".into(),
            session_not_on_or_after: Some(now + Duration::from_secs(3600)),
            authn_context_class_ref: AuthnContextClassRef::PasswordProtectedTransport,
            force_encrypt_assertion: None,
            now,
            assertion_lifetime: Duration::from_secs(3600),
            subject_confirmation_lifetime: Duration::from_secs(3600),
            holder_of_key_cert: None,
        })
        .unwrap();
    let response = match response {
        SsoResponseDispatch::Post(form) => base64::engine::general_purpose::STANDARD
            .decode(form.saml_response)
            .unwrap(),
        SsoResponseDispatch::Artifact(_) => panic!("expected POST response"),
    };

    let cache = InMemoryReplayCache::new(16);
    let assertion = saml.check_state(&response, now, &tracker, &cache).unwrap();
    assert_eq!(assertion.email.as_deref(), Some("alice@example.com"));
    assert!(saml.check_state(&response, now, &tracker, &cache).is_err());
}
