use halo::factor::enterprise::{Dispatch, SamlAuth, SamlConfig};
use saml::InMemoryReplayCache;
use std::time::SystemTime;

const IDP_ENTITY: &str = "https://idp.example.com/bridge";
const IDP_SSO: &str = "https://idp.example.com/bridge/sso";
const SP_ENTITY: &str = "https://sp.example.com/bridge";
const SP_ACS: &str = "https://sp.example.com/bridge/acs";

fn auth() -> SamlAuth {
    SamlAuth::new(&SamlConfig {
        idp_entity_id: IDP_ENTITY.into(),
        idp_sso_url: IDP_SSO.into(),
        metadata: include_str!("fixtures/saml_metadata.xml").into(),
        sp_entity_id: SP_ENTITY.into(),
        sp_acs_url: SP_ACS.into(),
    })
    .unwrap()
}

#[test]
fn start_returns_post_dispatch_and_serializable_tracker() {
    let saml = auth();
    let (dispatch, tracker) = saml.start(Some("bridge-state")).unwrap();
    match dispatch {
        Dispatch::Post { action, fields } => {
            assert_eq!(action, IDP_SSO);
            assert!(fields.iter().any(|(name, _)| name == "SAMLRequest"));
        }
        Dispatch::Redirect(_) => panic!("expected POST request"),
    }
    assert!(!tracker.request_id().is_empty());
    let encoded = serde_json::to_string(&tracker).unwrap();
    assert!(encoded.contains("bridge-state"));
}

#[test]
fn invalid_response_is_rejected() {
    let saml = auth();
    let mut cache = InMemoryReplayCache::new();
    assert!(
        saml.check(b"<invalid-saml-response />", SystemTime::now(), &mut cache)
            .is_err()
    );
}
