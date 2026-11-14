use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use halo::factor::basic::magic::MagicLinkConfig;
use halo::factor::oidc;
use halo::factor::passkey::Passkey;
use halo::pkg::password::{Algorithm, Password};
use halo::store::{Clients, Passkeys, Secrets};
use halo::types::{Identity, OAuthClient, User};
use halo::validator::issuer::captcha::{
    Image as IssueImage, Rotate as IssueRotate, Slider as IssueSlider,
};
use halo::validator::issuer::{
    Captcha as IssueCaptcha, Magic as IssueMagic, Passkey as IssuePasskey,
};
use halo::validator::verifier::captcha::{
    Captcha as VerifyCaptcha, CaptchaType, CaptchaVerifyReq, Click as VerifyClick,
    Image as VerifyImage, Rotate as VerifyRotate, Slider as VerifySlider, TargetPoint,
};
use halo::validator::verifier::{Magic as VerifyMagic, Passkey as VerifyPasskey};
use halo::{factor, token};
use jsonwebtoken::{Algorithm as JwtAlgorithm, EncodingKey, Header, encode};
use saml::InMemoryReplayCache;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[test]
fn test_password_hash_and_verify() {
    let raw = "admin123";
    let hash = halo::pkg::password::Password::hash(raw, halo::pkg::password::Algorithm::Argon2id)
        .expect("hash failed");
    assert!(
        halo::pkg::password::Password::verify(
            raw,
            &hash,
            halo::pkg::password::Algorithm::Argon2id,
        )
        .expect("verify failed")
    );
    assert!(
        !halo::pkg::password::Password::verify(
            "WrongSecret",
            &hash,
            halo::pkg::password::Algorithm::Argon2id,
        )
        .expect("verify failed")
    );
}

#[test]
fn test_oidc_discovery_matches_supported_flow() {
    let discovery = oidc::OidcDiscovery::new("https://idp.example");
    assert_eq!(discovery.response_types_supported, vec!["code"]);
    assert_eq!(
        discovery.scopes_supported,
        vec!["openid", "profile", "email"]
    );
    assert_eq!(
        discovery.token_endpoint_auth_methods_supported,
        vec!["client_secret_post", "none"]
    );
    let json = serde_json::to_string(&discovery).unwrap();
    assert!(!json.contains("userinfo_endpoint"));
    assert!(!json.contains("introspection_endpoint"));
}

#[test]
fn test_oidc_values_generate_and_validate() {
    let state = oidc::State::new();
    assert!(state.len() >= 43);
    assert!(oidc::State::check(&state, &state).is_ok());
    assert!(oidc::State::check(&state, "wrong").is_err());

    let nonce = oidc::Nonce::new();
    assert!(nonce.len() >= 43);
    assert!(oidc::Nonce::check(&nonce, &nonce).is_ok());
    assert!(oidc::Nonce::check(&nonce, "wrong").is_err());

    let (verifier, challenge) = oidc::Pkce::new();
    assert!(oidc::Pkce::check(&verifier, &challenge, Some("S256")).is_ok());
    assert!(oidc::Pkce::check("wrong", &challenge, Some("S256")).is_err());
    assert!(oidc::Pkce::check("short", "short", Some("plain")).is_err());
}

#[tokio::test]
async fn test_oidc_state_and_nonce_are_single_use() {
    let kv = MemSecrets::new();
    let state = oidc::State::new();
    kv.set("state-key", &state, 60).await.unwrap();
    oidc::State::take(&kv, "state-key", &state).await.unwrap();
    assert!(oidc::State::take(&kv, "state-key", &state).await.is_err());

    let nonce = oidc::Nonce::new();
    kv.set("nonce-key", &nonce, 60).await.unwrap();
    oidc::Nonce::take(&kv, "nonce-key", &nonce).await.unwrap();
    assert!(oidc::Nonce::take(&kv, "nonce-key", &nonce).await.is_err());
}

#[test]
fn test_saml_fixture_and_replay_cache() {
    let saml = factor::enterprise::SamlAuth::new(&factor::enterprise::SamlConfig {
        idp_entity_id: "https://idp.example.com/bridge".into(),
        idp_sso_url: "https://idp.example.com/bridge/sso".into(),
        metadata: include_str!("fixtures/saml_metadata.xml").into(),
        sp_entity_id: "https://sp.example.com/bridge".into(),
        sp_acs_url: "https://sp.example.com/bridge/acs".into(),
    })
    .unwrap();
    let (dispatch, tracker) = saml.start(Some("bridge-state")).unwrap();
    assert!(matches!(dispatch, saml::binding::Dispatch::Post(_)));
    assert!(!tracker.request_id().is_empty());
    let response = include_bytes!("fixtures/saml_response.xml");
    let now = std::time::SystemTime::now();
    let cache = InMemoryReplayCache::new(16);

    let assertion = saml.check(response, now, &cache).unwrap();
    assert_eq!(assertion.name_id, "alice@example.com");
    assert_eq!(assertion.email.as_deref(), Some("alice@example.com"));
    assert_eq!(assertion.display_name.as_deref(), Some("Alice Example"));
    assert!(assertion.assertion_id.is_some());

    assert!(saml.check(response, now, &cache).is_err());
    assert!(saml.check_state(response, now, &tracker, &cache).is_err());
}

#[test]
fn test_password_algorithms_and_unknown_code() {
    for algorithm in [
        Algorithm::Argon2id,
        Algorithm::Bcrypt,
        Algorithm::Pbkdf2,
        Algorithm::Sm3,
    ] {
        let hash = Password::hash("correct horse battery staple", algorithm).expect("hash failed");
        assert!(
            Password::verify("correct horse battery staple", &hash, algorithm)
                .expect("verify failed")
        );
        assert!(!Password::verify("wrong", &hash, algorithm).expect("verify failed"));
    }
}

#[test]
fn test_rsa_crypto_decrypt() {
    use halo::pkg::rsa::Rsa;
    let crypto = Rsa::new().unwrap();
    let pem = crypto.public_pem();
    assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
}

#[tokio::test]
async fn test_social_and_enterprise_providers() {
    // 1. GitHub 授权跳转链接与用户数据解析
    let gh = factor::social::Github::new(factor::social::GithubConfig {
        client_id: "gh_client_123".into(),
        client_secret: "gh_secret_456".into(),
        scope: None,
    });
    let gh_url = gh
        .authorize_url("state_abc", "https://halo.run/oauth/github/callback")
        .unwrap();
    assert!(gh_url.contains("client_id=gh_client_123"));
    assert!(gh_url.contains("redirect_uri=https%3A%2F%2Fhalo.run%2Foauth%2Fgithub%2Fcallback"));

    let gh_user = serde_json::json!({
        "id": 987654,
        "login": "octocat",
        "name": "The Octocat",
        "email": "octocat@github.com",
        "avatar_url": "https://avatars.githubusercontent.com/u/987654"
    });
    let profile = factor::social::Github::parse(&gh_user).unwrap();
    assert_eq!(profile.provider, "github");
    assert_eq!(profile.openid, "987654");
    assert_eq!(profile.email, Some("octocat@github.com".into()));

    // 2. 微信登录授权链接
    let wx = factor::social::Wechat::new(factor::social::WechatConfig {
        app_id: "wx123456789".into(),
        app_secret: "wxsecret".into(),
        scope: None,
    });
    let wx_url = wx
        .authorize_url("state_xyz", "https://halo.run/oauth/wechat/callback")
        .unwrap();
    assert!(wx_url.contains("appid=wx123456789"));
    assert!(wx_url.contains("#wechat_redirect"));
    let wx_profile = factor::social::Wechat::parse(&serde_json::json!({
        "openid": "wx-openid",
        "unionid": "wx-unionid",
        "nickname": "WeChat User",
        "headimgurl": "https://example.com/avatar.png"
    }))
    .unwrap();
    assert_eq!(wx_profile.openid, "wx-openid");
    assert_eq!(wx_profile.unionid.as_deref(), Some("wx-unionid"));

    let google = factor::social::Google::new(factor::social::GoogleConfig {
        client_id: "google-client".into(),
        client_secret: "google-secret".into(),
        scope: None,
    });
    let google_url = google
        .authorize_url("state_google", "https://halo.run/oauth/google/callback")
        .unwrap();
    assert!(google_url.contains("client_id=google-client"));
    let google_profile = factor::social::Google::parse(&serde_json::json!({
        "sub": "google-sub",
        "name": "Google User",
        "email": "google@example.com",
        "picture": "https://example.com/google.png"
    }))
    .unwrap();
    assert_eq!(google_profile.openid, "google-sub");
    assert_eq!(google_profile.email.as_deref(), Some("google@example.com"));

    // 3. 企业微信与钉钉
    let wecom = factor::enterprise::Wecom::new(factor::enterprise::WecomConfig {
        corp_id: "corp_123".into(),
        agent_id: "1000002".into(),
        corp_secret: "secret".into(),
    });
    let wecom_url = wecom
        .authorize_url("state_wecom", "https://halo.run/oauth/wecom/callback")
        .unwrap();
    assert!(wecom_url.contains("appid=corp_123"));

    let dt = factor::enterprise::Dingtalk::new(factor::enterprise::DingtalkConfig {
        client_id: "dt_app_id".into(),
        client_secret: "dt_secret".into(),
    });
    let dt_url = dt
        .authorize_url("state_dt", "https://halo.run/oauth/dingtalk/callback")
        .unwrap();
    assert!(dt_url.contains("client_id=dt_app_id"));

    let ldap = factor::enterprise::LdapConfig {
        server_url: "ldap://127.0.0.1:389".into(),
        base_dn: "dc=example,dc=com".into(),
        bind_dn: "cn=admin,dc=example,dc=com".into(),
        bind_password: Some("secret".into()),
        user_search_filter: "(&(objectClass=person)(uid={username}))".into(),
        timeout: 8,
    };
    let ldap_identity = factor::enterprise::LdapAuth::identity("alice");
    assert_eq!(ldap_identity.provider, "ldap");
    assert_eq!(ldap_identity.subject, "alice");
    let invalid_filter = factor::enterprise::LdapConfig {
        user_search_filter: "(uid=*)".into(),
        ..ldap
    };
    let ldap_error =
        factor::enterprise::LdapAuth::authenticate(&invalid_filter, "alice", "secret").await;
    assert!(ldap_error.is_err());

    let saml_metadata = r#"
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/saml">
          <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:SingleSignOnService
              Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
              Location="https://idp.example.com/saml/sso" />
          </md:IDPSSODescriptor>
        </md:EntityDescriptor>
    "#;
    let saml = factor::enterprise::SamlAuth::new(&factor::enterprise::SamlConfig {
        idp_entity_id: "https://idp.example.com/saml".into(),
        idp_sso_url: "https://idp.example.com/saml/sso".into(),
        metadata: saml_metadata.into(),
        sp_entity_id: "https://app.example.com/saml".into(),
        sp_acs_url: "https://app.example.com/saml/acs".into(),
    })
    .unwrap();
    let cache = saml::InMemoryReplayCache::new(16);
    assert!(
        saml.check(
            b"<invalid-saml-response />",
            std::time::SystemTime::now(),
            &cache
        )
        .is_err()
    );
}

#[test]
fn test_token_issue_and_verify() {
    let service = token::Token::new(
        "my-super-secret-key-that-is-long-enough-32bytes",
        "halo-idp",
        3600,
        86400,
    );
    let user = User {
        id: 10001,
        username: "admin".into(),
        email: Some("admin@halo.run".into()),
        phone: Some("13800000000".into()),
        password_hash: None,
        password_algorithm: None,
        is_active: true,
    };

    let (access, refresh) = service
        .issue_tokens(&user, None)
        .expect("issue tokens failed");
    let claims = service.verify_token(&access).expect("verify token failed");
    assert_eq!(claims.sub, "10001");
    assert_eq!(claims.username, "admin");

    let refresh_claims = service
        .verify_refresh(&refresh)
        .expect("verify refresh failed");
    assert_eq!(refresh_claims.sub, "10001");

    let id_token = service
        .issue_id_token(&user, "client".into(), Some("nonce-1".into()))
        .expect("issue id token failed");
    assert!(
        service
            .verify_id(&id_token, "client", Some("nonce-1"))
            .is_ok()
    );
    assert!(
        service
            .verify_id(&id_token, "client", Some("wrong"))
            .is_err()
    );
}

#[test]
fn test_token_issue_and_verify_rs256_and_jwks() {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};

    // 1. 生成 RSA 秘钥
    let mut rng = rand_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let priv_pem_str = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let pub_pem_str =
        rsa::pkcs8::EncodePublicKey::to_public_key_pem(&pub_key, LineEnding::LF).unwrap();

    let service = token::Token::with_rsa_pem(
        "https://aiwiki.vip",
        3600,
        86400,
        &priv_pem_str,
        &pub_pem_str,
    );

    let user = User {
        id: 20002,
        username: "rs256_user".into(),
        email: Some("rs256@halo.run".into()),
        phone: None,
        password_hash: None,
        password_algorithm: None,
        is_active: true,
    };

    // 2. 签发并校验 RS256 Token
    let (access, _refresh) = service
        .issue_tokens(&user, Some("halo-client".into()))
        .expect("issue rs256 tokens");
    let claims = service.verify_token(&access).expect("verify rs256 token");
    assert_eq!(claims.sub, "20002");
    assert_eq!(claims.username, "rs256_user");

    let verified_aud = service
        .verify_audience(&access, "halo-client")
        .expect("verify audience");
    assert_eq!(verified_aud.aud, Some("halo-client".to_string()));

    // 3. 验证 JWKS 导出
    let jwks = token::JwksResponse::from_rsa_public_key(&pub_key, "key-2026");
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kty, "RSA");
    assert_eq!(jwks.keys[0].alg, "RS256");
    assert_eq!(jwks.keys[0].use_, "sig");
    assert_eq!(jwks.keys[0].kid, "key-2026");
    assert!(jwks.keys[0].n.is_some());
    assert!(jwks.keys[0].e.is_some());
}

#[test]
fn test_pkce_s256_verify() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

    assert!(oidc::Flow::verify_pkce(verifier, &challenge, Some("S256")).is_ok());
    assert!(oidc::Flow::verify_pkce("wrong_verifier", &challenge, Some("S256")).is_err());
}

#[test]
fn test_captcha_units() {
    // 1. 图形验证码
    let (code, data_uri) = IssueImage::issue(4);
    assert_eq!(code.len(), 4);
    assert!(data_uri.starts_with("data:image/svg+xml;base64,"));
    assert!(VerifyImage::verify(&code, &code.to_lowercase()));
    assert!(!VerifyImage::verify(&code, "0000"));

    // 2. 滑块验证码
    let (target_x, bg_uri, piece_uri, _) = IssueSlider::issue();
    assert!(bg_uri.starts_with("data:image/svg+xml;base64,"));
    assert!(piece_uri.starts_with("data:image/svg+xml;base64,"));
    assert!(VerifySlider::verify(target_x, target_x as i32 + 2)); // 误差2px通过
    assert!(!VerifySlider::verify(target_x, target_x as i32 + 20)); // 误差20px拒绝

    // 3. 旋转验证码
    let (target_deg, rot_uri) = IssueRotate::issue();
    assert!(rot_uri.starts_with("data:image/svg+xml;base64,"));
    assert!(VerifyRotate::verify(target_deg, target_deg as i32 + 3)); // 误差3度通过
    assert!(!VerifyRotate::verify(target_deg, target_deg as i32 + 35)); // 误差35度拒绝

    // 4. 点选验证码
    let targets = vec![
        TargetPoint {
            char: '星',
            x: 50,
            y: 60,
        },
        TargetPoint {
            char: '海',
            x: 150,
            y: 80,
        },
    ];
    let correct_clicks = vec![(52, 61), (149, 78)];
    let wrong_clicks = vec![(10, 10), (149, 78)];
    assert!(VerifyClick::verify(&targets, &correct_clicks));
    assert!(!VerifyClick::verify(&targets, &wrong_clicks));
}

#[test]
fn code_storage_key_does_not_expose_target() {
    let key = halo::validator::issuer::Code::key("login_sms", "+8613800138000");
    assert!(!key.contains("13800138000"));
    assert!(key.starts_with("code:login_sms:"));
}

#[test]
fn external_oidc_authorize_and_id_token_validation() {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};

    let issuer = "https://login.example";
    let provider = oidc::Provider::new(oidc::Config {
        issuer: issuer.into(),
        client_id: "client".into(),
        client_secret: "secret".into(),
        scope: Some("openid email".into()),
        authorization_endpoint: Some("https://login.example/oauth2/authorize".into()),
        token_endpoint: None,
        discovery_endpoint: None,
        jwks_endpoint: None,
    });
    let (_, challenge) = oidc::Pkce::new();
    let url = provider
        .authorize_url(
            "state-1",
            "https://app.example/callback",
            Some("nonce-1"),
            Some(&challenge),
            Some("S256"),
        )
        .unwrap();
    assert!(url.contains("response_type=code"));
    assert!(url.contains("state=state-1"));
    assert!(url.contains("nonce=nonce-1"));

    let mut rng = rand_core::OsRng;
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let private_pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let public = rsa::RsaPublicKey::from(&private);
    let jwks = token::JwksResponse::from_rsa_public_key(&public, "key-1");
    let discovery = oidc::Discovery {
        issuer: issuer.into(),
        authorization_endpoint: "https://login.example/oauth2/authorize".into(),
        token_endpoint: "https://login.example/oauth2/token".into(),
        jwks_uri: "https://login.example/oauth2/jwks".into(),
        jwks,
    };
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": "external-7",
        "aud": "client",
        "exp": now + 60,
        "iat": now,
        "nonce": "nonce-1",
        "email": "alice@example.com",
        "name": "Alice"
    });
    let mut header = Header::new(JwtAlgorithm::RS256);
    header.kid = Some("key-1".into());
    let id_token = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    let profile = provider
        .verify_id(&id_token, &discovery, Some("nonce-1"))
        .unwrap();
    assert_eq!(profile.provider, issuer);
    assert_eq!(profile.subject, "external-7");
    assert_eq!(profile.email.as_deref(), Some("alice@example.com"));
    assert!(
        provider
            .verify_id(&id_token, &discovery, Some("wrong"))
            .is_err()
    );
    let sign = |value: &serde_json::Value| {
        encode(
            &header,
            value,
            &EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap(),
        )
        .unwrap()
    };
    let mut wrong_audience = claims.clone();
    wrong_audience["aud"] = serde_json::json!("other-client");
    assert!(
        provider
            .verify_id(&sign(&wrong_audience), &discovery, Some("nonce-1"))
            .is_err()
    );
    let mut wrong_issuer = claims.clone();
    wrong_issuer["iss"] = serde_json::json!("https://evil.example");
    assert!(
        provider
            .verify_id(&sign(&wrong_issuer), &discovery, Some("nonce-1"))
            .is_err()
    );
    let mut expired = claims;
    expired["exp"] = serde_json::json!(now - 1);
    assert!(
        provider
            .verify_id(&sign(&expired), &discovery, Some("nonce-1"))
            .is_err()
    );
}

// 内存模拟 Secrets
#[derive(Clone)]
struct MemSecrets {
    data: Arc<Mutex<HashMap<String, String>>>,
}

struct MemClients {
    client: OAuthClient,
}

struct MemPasskeys {
    data: Mutex<Vec<(String, Passkey)>>,
}

impl Clients for MemClients {
    async fn find_client(&self, client_id: &str) -> halo::Result<Option<OAuthClient>> {
        Ok((self.client.client_id == client_id).then(|| self.client.clone()))
    }
}

impl MemPasskeys {
    fn new() -> Self {
        Self {
            data: Mutex::new(Vec::new()),
        }
    }
}

impl Passkeys for MemPasskeys {
    async fn save(&self, subject: &str, mut passkey: Passkey) -> halo::Result<()> {
        let mut data = self.data.lock().unwrap();
        if data
            .iter()
            .any(|(_, stored)| stored.credential_id == passkey.credential_id)
        {
            return Err(halo::Error::StoreError(
                "Credential ID already exists".into(),
            ));
        }
        passkey.subject = subject.into();
        data.push((subject.into(), passkey));
        Ok(())
    }

    async fn find(&self, credential_id: &str) -> halo::Result<Option<Passkey>> {
        Ok(self
            .data
            .lock()
            .unwrap()
            .iter()
            .find(|(_, passkey)| passkey.credential_id == credential_id)
            .map(|(_, passkey)| passkey.clone()))
    }

    async fn list(&self, subject: &str) -> halo::Result<Vec<Passkey>> {
        Ok(self
            .data
            .lock()
            .unwrap()
            .iter()
            .filter(|(stored_subject, _)| stored_subject == subject)
            .map(|(_, passkey)| passkey.clone())
            .collect())
    }

    async fn update(
        &self,
        credential_id: &str,
        old_count: u32,
        next: Passkey,
    ) -> halo::Result<bool> {
        let mut data = self.data.lock().unwrap();
        let Some((_, passkey)) = data
            .iter_mut()
            .find(|(_, passkey)| passkey.credential_id == credential_id)
        else {
            return Ok(false);
        };
        if passkey.sign_count != old_count
            || next.credential_id != credential_id
            || !passkey.can_update(next.sign_count)
        {
            return Ok(false);
        }
        *passkey = next;
        passkey.last_used_at = Some(chrono::Utc::now().timestamp());
        Ok(true)
    }
}

impl MemSecrets {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Secrets for MemSecrets {
    async fn set(&self, key: &str, val: &str, _ttl: u64) -> halo::Result<()> {
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), val.to_string());
        Ok(())
    }

    async fn get(&self, key: &str) -> halo::Result<Option<String>> {
        Ok(self.data.lock().unwrap().get(key).cloned())
    }

    async fn take(&self, key: &str) -> halo::Result<Option<String>> {
        Ok(self.data.lock().unwrap().remove(key))
    }

    async fn take_if(&self, key: &str, expected: &str) -> halo::Result<bool> {
        let mut data = self.data.lock().unwrap();
        if data.get(key).map(String::as_str) != Some(expected) {
            return Ok(false);
        }
        data.remove(key);
        Ok(true)
    }

    async fn del(&self, key: &str) -> halo::Result<()> {
        self.data.lock().unwrap().remove(key);
        Ok(())
    }

    async fn claim(&self, key: &str, val: &str, _ttl: u64) -> halo::Result<bool> {
        let mut data = self.data.lock().unwrap();
        if data.contains_key(key) {
            return Ok(false);
        }
        data.insert(key.to_string(), val.to_string());
        Ok(true)
    }

    async fn incr(&self, key: &str, _ttl: u64) -> halo::Result<u32> {
        let mut data = self.data.lock().unwrap();
        let next = data
            .get(key)
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0)
            .saturating_add(1);
        data.insert(key.to_string(), next.to_string());
        Ok(next)
    }
}

fn test_passkey(id: &str, sign_count: u32) -> Passkey {
    Passkey {
        subject: "s1".into(),
        credential_id: id.into(),
        public_key: "key".into(),
        sign_count,
        transports: Vec::new(),
        aaguid: None,
        user_handle: Some("user-handle".into()),
        display_name: Some("Test user".into()),
        created_at: 1,
        last_used_at: None,
        passwordless: true,
        user_verified: false,
        backup_eligible: false,
        backup_state: false,
        data: Some("{}".into()),
    }
}

#[tokio::test]
async fn test_passkey_store_scope_and_unique_id() {
    let store = MemPasskeys::new();
    store.save("s1", test_passkey("key-1", 1)).await.unwrap();
    assert_eq!(store.list("s1").await.unwrap().len(), 1);
    assert!(store.find("key-1").await.unwrap().is_some());
    assert!(store.list("s2").await.unwrap().is_empty());

    let duplicate = store.save("s2", test_passkey("key-1", 1)).await;
    assert!(duplicate.is_err());
}

#[tokio::test]
async fn test_passkey_counter_update_is_compare_and_set() {
    let store = Arc::new(MemPasskeys::new());
    store.save("s1", test_passkey("key-1", 1)).await.unwrap();

    let left = store.clone();
    let right = store.clone();
    let (first, second) = tokio::join!(
        left.update("key-1", 1, test_passkey("key-1", 2)),
        right.update("key-1", 1, test_passkey("key-1", 3)),
    );
    assert_eq!(
        [first.unwrap(), second.unwrap()]
            .into_iter()
            .filter(|ok| *ok)
            .count(),
        1
    );
    assert!(
        !store
            .update("key-1", 1, test_passkey("key-1", 4))
            .await
            .unwrap()
    );
}

#[test]
fn test_passkey_state_and_missing_data() {
    let webauthn = IssuePasskey::new("example.com", "https://example.com", "Halo").unwrap();
    let start = webauthn
        .issue("00000000-0000-0000-0000-000000000001", "user", "Test user")
        .unwrap();
    assert!(start.state.contains("user_handle"));
    assert!(start.state.contains("Test user"));

    let missing = test_passkey("key-1", 0);
    assert!(webauthn.request(&[missing]).is_err());
}

#[tokio::test]
async fn test_captcha_service_flow() {
    let kv = MemSecrets::new();
    let issuer = IssueCaptcha::default();
    let verifier = VerifyCaptcha::default();

    // 1. 生成滑块挑战
    let challenge = issuer
        .issue(&kv, CaptchaType::Slider)
        .await
        .expect("generate failed");
    assert_eq!(challenge.captcha_type, CaptchaType::Slider);
    assert!(challenge.slider.is_some());

    // 获取存入的正确 X 坐标
    let cap_key = format!("cap:{}", challenge.id);
    let answer_x: i32 = kv
        .data
        .lock()
        .unwrap()
        .get(&cap_key)
        .unwrap()
        .parse()
        .unwrap();

    // 2. 错误偏移核验失败 (一次性销毁防爆破)
    let fail_req = CaptchaVerifyReq {
        id: challenge.id.clone(),
        captcha_type: CaptchaType::Slider,
        text: None,
        offset_x: Some(answer_x + 50),
        angle: None,
        points: None,
    };
    assert!(verifier.verify(&kv, &fail_req).await.is_err());

    let type_mismatch = CaptchaVerifyReq {
        id: challenge.id.clone(),
        captcha_type: CaptchaType::Image,
        text: Some("wrong type".into()),
        offset_x: None,
        angle: None,
        points: None,
    };
    assert!(verifier.verify(&kv, &type_mismatch).await.is_err());

    // 同一个挑战并发提交时，Secrets 的原子消费保证最多一个请求成功。
    let concurrent = issuer
        .issue(&kv, CaptchaType::Image)
        .await
        .expect("generate concurrent challenge failed");
    let answer = kv
        .data
        .lock()
        .unwrap()
        .get(&format!("cap:{}", concurrent.id))
        .cloned()
        .unwrap();
    let request = || CaptchaVerifyReq {
        id: concurrent.id.clone(),
        captcha_type: CaptchaType::Image,
        text: Some(answer.clone()),
        offset_x: None,
        angle: None,
        points: None,
    };
    let request_left = request();
    let request_right = request();
    let (left, right) = tokio::join!(
        verifier.verify(&kv, &request_left),
        verifier.verify(&kv, &request_right)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);

    // 3. 重新生成并正确核验
    let challenge2 = issuer
        .issue(&kv, CaptchaType::Slider)
        .await
        .expect("generate failed");
    assert!(issuer.token(&kv, &challenge2.id, 300).await.is_err());
    let cap_key2 = format!("cap:{}", challenge2.id);
    let answer2_x: i32 = kv
        .data
        .lock()
        .unwrap()
        .get(&cap_key2)
        .unwrap()
        .parse()
        .unwrap();

    let success_req = CaptchaVerifyReq {
        id: challenge2.id.clone(),
        captcha_type: CaptchaType::Slider,
        text: None,
        offset_x: Some(answer2_x + 2), // 2px 误差在 ±5 容差范围内
        angle: None,
        points: None,
    };
    verifier
        .verify(&kv, &success_req)
        .await
        .expect("verify failed");
    assert!(
        !kv.data
            .lock()
            .unwrap()
            .keys()
            .any(|key| key.starts_with("cpt:"))
    );
    let token = issuer
        .token(&kv, &challenge2.id, 300)
        .await
        .expect("token failed");
    assert!(token.starts_with("cpt_"));

    // 4. 登录时核验并消费 captcha_token
    assert!(verifier.take(&kv, &token).await.unwrap());
    // 第二次消费即失效
    assert!(!verifier.take(&kv, &token).await.unwrap());
}

#[tokio::test]
async fn test_magic_link_single_use() {
    let kv = MemSecrets::new();
    let config = MagicLinkConfig {
        base_url: "https://auth.halo.local/magic".into(),
        signing_secret: "a-long-test-secret-for-magic-links".into(),
        ttl_seconds: 60,
    };
    let (token, _) = IssueMagic::create(config.clone(), &kv, "User@Example.com", None, "login")
        .await
        .unwrap();
    let first = VerifyMagic::take(config.clone(), &kv, &token)
        .await
        .unwrap();
    assert_eq!(first.email, "user@example.com");
    assert!(VerifyMagic::take(config, &kv, &token).await.is_err());
}

#[tokio::test]
async fn test_oidc_code_keeps_nonce_and_survives_failed_pkce() {
    let kv = MemSecrets::new();
    let (verifier, challenge) = oidc::Pkce::new();
    let clients = MemClients {
        client: OAuthClient {
            client_id: "web".into(),
            client_secret: None,
            client_name: "Web".into(),
            redirect_uris: vec!["https://app.example/callback".into()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            scope: "openid profile".into(),
            is_public: true,
        },
    };
    let authorize = oidc::AuthorizeRequest {
        response_type: "code".into(),
        client_id: "web".into(),
        redirect_uri: "https://app.example/callback".into(),
        scope: Some("openid".into()),
        state: Some("state".into()),
        code_challenge: Some(challenge),
        code_challenge_method: Some("S256".into()),
        nonce: Some("nonce-1".into()),
    };
    let issued_code = oidc::Flow::issue_code_with_nonce(
        &kv,
        "web",
        Identity::new("local", "subject-key"),
        &authorize.redirect_uri,
        "openid",
        authorize.code_challenge.clone(),
        authorize.code_challenge_method.clone(),
        authorize.nonce.clone(),
        60,
    )
    .await
    .unwrap();
    let stored_keys = kv.data.lock().unwrap().keys().cloned().collect::<Vec<_>>();
    assert!(stored_keys.iter().any(|key| key.starts_with("code:")));
    assert!(stored_keys.iter().all(|key| !key.contains(&issued_code)));
    let mut bad_scope = authorize.clone();
    bad_scope.scope = Some("admin".into());
    assert!(
        oidc::Flow::validate_authorize_request(&clients, &bad_scope)
            .await
            .is_err()
    );
    let mut bad_redirect = authorize.clone();
    bad_redirect.redirect_uri = "https://evil.example/callback".into();
    assert!(
        oidc::Flow::validate_authorize_request(&clients, &bad_redirect)
            .await
            .is_err()
    );
    let mut bad_method = authorize.clone();
    bad_method.code_challenge_method = Some("S512".into());
    assert!(
        oidc::Flow::validate_authorize_request(&clients, &bad_method)
            .await
            .is_err()
    );
    oidc::Flow::validate_authorize_request(&clients, &authorize)
        .await
        .unwrap();
    assert!(
        oidc::Flow::validate_authorize_request(&clients, &authorize)
            .await
            .is_ok()
    );
    let code = oidc::Flow::issue_code_with_nonce(
        &kv,
        "web",
        Identity::new("local", "1").name("user"),
        &authorize.redirect_uri,
        "openid",
        authorize.code_challenge.clone(),
        authorize.code_challenge_method.clone(),
        authorize.nonce.clone(),
        60,
    )
    .await
    .unwrap();

    let bad = oidc::TokenRequest {
        grant_type: "authorization_code".into(),
        code: Some(code.clone()),
        redirect_uri: Some(authorize.redirect_uri.clone()),
        client_id: "web".into(),
        client_secret: None,
        code_verifier: Some("wrong".into()),
        refresh_token: None,
    };
    let mut bad_redirect_token = bad.clone();
    bad_redirect_token.redirect_uri = Some("https://evil.example/callback".into());
    assert!(
        oidc::Flow::exchange_code(&clients, &kv, &bad_redirect_token)
            .await
            .is_err()
    );
    let mut bad_client = bad.clone();
    bad_client.client_id = "other".into();
    assert!(
        oidc::Flow::exchange_code(&clients, &kv, &bad_client)
            .await
            .is_err()
    );
    assert!(
        oidc::Flow::exchange_code(&clients, &kv, &bad)
            .await
            .is_err()
    );

    let good = oidc::TokenRequest {
        code_verifier: Some(verifier),
        ..bad
    };
    let exchanged = oidc::Flow::exchange_code(&clients, &kv, &good)
        .await
        .unwrap();
    assert_eq!(exchanged.nonce.as_deref(), Some("nonce-1"));
    assert!(
        oidc::Flow::exchange_code(&clients, &kv, &good)
            .await
            .is_err()
    );

    let (verifier2, challenge2) = oidc::Pkce::new();
    let code2 = oidc::Flow::issue_code_with_nonce(
        &kv,
        "web",
        Identity::new("local", "subject-1").name("Alice"),
        &authorize.redirect_uri,
        "openid",
        Some(challenge2),
        Some("S256".into()),
        Some("nonce-2".into()),
        60,
    )
    .await
    .unwrap();
    let token = token::Token::new("oidc-secret-32-bytes-long-enough", "halo", 60, 600);
    let response = oidc::Flow::exchange(
        &clients,
        &token,
        &kv,
        &oidc::TokenRequest {
            grant_type: "authorization_code".into(),
            code: Some(code2),
            redirect_uri: Some(authorize.redirect_uri.clone()),
            client_id: "web".into(),
            client_secret: None,
            code_verifier: Some(verifier2),
            refresh_token: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, 60);
    assert_eq!(response.scope.as_deref(), Some("openid"));
    assert!(response.id_token.is_some());
}

#[tokio::test]
async fn test_oidc_refresh_rotates_and_revokes_old_token() {
    let kv = MemSecrets::new();
    let clients = MemClients {
        client: OAuthClient {
            client_id: "web".into(),
            client_secret: None,
            client_name: "Web".into(),
            redirect_uris: vec!["https://app.example/callback".into()],
            grant_types: vec!["refresh_token".into()],
            response_types: vec!["code".into()],
            scope: "openid".into(),
            is_public: true,
        },
    };
    let service = token::Token::new("refresh-secret-32-bytes-long-enough", "halo", 60, 600);
    let identity = Identity::new("local", "user-7").name("user");
    let (_, refresh) = service
        .issue_identity(&identity, Some("web".into()), Some("openid".into()))
        .unwrap();
    let request = oidc::TokenRequest {
        grant_type: "refresh_token".into(),
        code: None,
        redirect_uri: None,
        client_id: "web".into(),
        client_secret: None,
        code_verifier: None,
        refresh_token: Some(refresh.clone()),
    };

    let response = oidc::Flow::exchange_refresh_token(&clients, &service, &kv, &request)
        .await
        .unwrap();
    let next_refresh = response.refresh_token.clone().unwrap();
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, 60);
    assert!(response.id_token.is_some());
    assert_ne!(refresh, next_refresh);
    assert!(oidc::Flow::is_token_revoked(&kv, &refresh).await.unwrap());
    let keys = kv.data.lock().unwrap().keys().cloned().collect::<Vec<_>>();
    assert!(keys.iter().all(|key| !key.contains(&refresh)));
    assert!(
        oidc::Flow::exchange_refresh_token(&clients, &service, &kv, &request)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_oidc_refresh_rotation_allows_one_concurrent_consumer() {
    let kv = MemSecrets::new();
    let other = kv.clone();
    let clients = MemClients {
        client: OAuthClient {
            client_id: "web".into(),
            client_secret: None,
            client_name: "Web".into(),
            redirect_uris: vec!["https://app.example/callback".into()],
            grant_types: vec!["refresh_token".into()],
            response_types: vec!["code".into()],
            scope: "openid".into(),
            is_public: true,
        },
    };
    let service = token::Token::new("refresh-race-secret-32-bytes-long", "halo", 60, 600);
    let (_, refresh) = service
        .issue_identity(
            &Identity::new("external", "subject-race"),
            Some("web".into()),
            Some("openid".into()),
        )
        .unwrap();
    let request = oidc::TokenRequest {
        grant_type: "refresh_token".into(),
        code: None,
        redirect_uri: None,
        client_id: "web".into(),
        client_secret: None,
        code_verifier: None,
        refresh_token: Some(refresh),
    };
    let (left, right) = tokio::join!(
        oidc::Flow::exchange_refresh_token(&clients, &service, &kv, &request),
        oidc::Flow::exchange_refresh_token(&clients, &service, &other, &request),
    );
    assert_eq!(left.is_ok() as u8 + right.is_ok() as u8, 1);
}

#[test]
fn test_password_policy_and_strength() {
    let policy = halo::rules::password::Policy::default();

    // 强密码验证通过
    assert!(
        policy
            .validate("Secure@2026!Halo", Some("zhangsan"))
            .is_ok()
    );

    // 太短报错
    assert!(policy.validate("S@1a", None).is_err());

    // 弱密码黑名单报错
    assert!(policy.validate("admin123", None).is_err());

    // 包含用户名报错
    assert!(policy.validate("Zhangsan@2026!", Some("zhangsan")).is_err());

    // 强度评估
    assert_eq!(
        policy.assess_strength("123"),
        halo::rules::password::Strength::Weak
    );
    assert_eq!(
        policy.assess_strength("Secure@2026!Halo"),
        halo::rules::password::Strength::Strong
    );
}

#[test]
fn test_lockout_policy() {
    let policy = halo::rules::lockout::Policy::default();

    // 0 次失败允许登录
    assert_eq!(
        policy.evaluate(0, None),
        halo::rules::lockout::Decision::Allow
    );

    // 3 次失败触发验证码
    assert_eq!(
        policy.evaluate(3, None),
        halo::rules::lockout::Decision::RequireCaptcha
    );

    // 5 次失败锁定账号
    match policy.evaluate(5, None) {
        halo::rules::lockout::Decision::Locked { remaining_seconds } => {
            assert_eq!(remaining_seconds, 900);
        }
        _ => panic!("Expected locked decision"),
    }
}

#[test]
fn test_totp_and_recovery_codes() {
    // 1. 生成秘钥与绑定链接
    let secret = halo::pkg::totp::Totp::generate_secret();
    assert!(!secret.is_empty());
    let uri =
        halo::pkg::totp::Totp::generate_otpauth_uri("HaloIAM", "user@halo.run", &secret).unwrap();
    assert!(uri.starts_with("otpauth://totp/HaloIAM:user@halo.run"));

    // 2. 生成动态口令与核验
    let now = chrono::Utc::now().timestamp() as u64;
    let code = halo::pkg::totp::Totp::generate_code(&secret, now).unwrap();
    assert_eq!(code.len(), 6);
    assert!(halo::pkg::totp::Totp::verify_code(&secret, &code, now).unwrap());
    assert!(!halo::pkg::totp::Totp::verify_code(&secret, "000000", now).unwrap());
    let config = halo::pkg::totp::Config {
        algorithm: halo::pkg::totp::Algorithm::Sha256,
        digits: 8,
        period: 60,
        window: 0,
    };
    let code = halo::pkg::totp::Totp::generate_with(&secret, now, config).unwrap();
    assert_eq!(code.len(), 8);
    assert!(halo::pkg::totp::Totp::verify_with(&secret, &code, now, config).unwrap());

    // 3. 应急恢复码
    let batch = halo::pkg::recovery::RecoveryCode::generate_batch(5);
    assert_eq!(batch.len(), 5);
    let hashes: Vec<String> = batch
        .iter()
        .map(|c| halo::pkg::recovery::RecoveryCode::hash_code(c))
        .collect();

    // 正确消费一个恢复码
    let consumed_hash = halo::pkg::recovery::RecoveryCode::verify(&batch[0], &hashes).unwrap();
    assert_eq!(consumed_hash, hashes[0]);

    // 错误恢复码拦截
    assert!(halo::pkg::recovery::RecoveryCode::verify("INVALID-CODE", &hashes).is_err());

    // 4. 用户专属 Salt 强绑定派生测试
    let subject = "user-3000000000000001";
    let salt1 = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let salt2 = "ffffffffffffffffffffffffffffffff";

    let secret_u1_s1 = halo::pkg::totp::Totp::derive_secret_with_salt(subject, salt1);
    let secret_u1_s1_repeat = halo::pkg::totp::Totp::derive_secret_with_salt(subject, salt1);
    let secret_u1_s2 = halo::pkg::totp::Totp::derive_secret_with_salt(subject, salt2);
    let secret_u2_s1 =
        halo::pkg::totp::Totp::derive_secret_with_salt("user-3000000000000002", salt1);

    // 确定性：相同用户 + 相同盐派生出的秘钥严格一致
    assert_eq!(secret_u1_s1, secret_u1_s1_repeat);
    // 隔离性：不同盐派生出的秘钥完全不同
    assert_ne!(secret_u1_s1, secret_u1_s2);
    // 隔离性：不同用户哪怕相同盐派生出的秘钥也完全不同
    assert_ne!(secret_u1_s1, secret_u2_s1);

    // 强绑定秘钥正常参与 TOTP 生成与核验
    let code_salt = halo::pkg::totp::Totp::generate_code(&secret_u1_s1, now).unwrap();
    assert!(halo::pkg::totp::Totp::verify_code(&secret_u1_s1, &code_salt, now).unwrap());
    // 拿另一个盐派生的秘钥核验必然失败
    assert!(!halo::pkg::totp::Totp::verify_code(&secret_u1_s2, &code_salt, now).unwrap());
}

#[test]
fn test_custom_claims_token_injection() {
    let service =
        halo::token::Token::new("my-32-byte-secret-key-1234567890", "halo-idp", 3600, 86400);
    let user = User {
        id: 20001,
        username: "developer".into(),
        email: Some("dev@halo.run".into()),
        phone: None,
        password_hash: None,
        password_algorithm: None,
        is_active: true,
    };

    let mut custom = serde_json::Map::new();
    custom.insert(
        "department".into(),
        serde_json::json!("Core Infrastructure"),
    );
    custom.insert("employee_id".into(), serde_json::json!("HALO-999"));

    let (access, _) = service
        .issue_tokens_with_claims(&user, Some("client-web".into()), Some(custom))
        .unwrap();

    let claims = service.verify_token(&access).unwrap();
    assert_eq!(claims.sub, "20001");
    assert_eq!(
        claims.custom.get("department").unwrap(),
        "Core Infrastructure"
    );
    assert_eq!(claims.custom.get("employee_id").unwrap(), "HALO-999");
}

#[test]
fn test_custom_claims_cannot_override_reserved_claims() {
    let service = token::Token::new(
        "custom-claims-secret-that-is-at-least-32-bytes",
        "halo-idp",
        300,
        600,
    );
    let identity = Identity::new("local", "subject");
    let mut claims = serde_json::Map::new();
    claims.insert("sub".into(), serde_json::json!("attacker"));
    assert!(
        service
            .issue_identity_with_claims(&identity, None, None, Some(claims))
            .is_err()
    );
}

#[tokio::test]
async fn test_passkey_fixture_register_request_verify() {
    let issuer = IssuePasskey::new(
        "etools-dev.example.com",
        "https://etools-dev.example.com:8080",
        "Halo",
    )
    .unwrap();
    let verifier = VerifyPasskey::new(
        "etools-dev.example.com",
        "https://etools-dev.example.com:8080",
        "Halo",
    )
    .unwrap();
    let start = issuer.issue("employee:42", "user", "User").unwrap();
    let mut state: serde_json::Value = serde_json::from_str(&start.state).unwrap();
    state["state"]["rs"]["challenge"] =
        serde_json::Value::String("FQky0FqnmV5KYqFU96E9aApSIRtjXiKcVFUf8Am8iDQ".into());

    let registered = verifier
        .register(
            include_str!("fixtures/passkey_register.json"),
            &state.to_string(),
        )
        .unwrap();
    assert_eq!(
        registered.credential_id,
        "KwlEDOBCBc9P1YU3NWihYLCeY-I9KGMhPap9vwHbVoI"
    );
    assert_eq!(registered.sign_count, 0);
    assert!(registered.user_verified);
    assert!(!registered.backup_eligible);
    assert!(!registered.backup_state);
    assert!(registered.data.is_some());

    let store = MemPasskeys::new();
    store.save("s1", registered).await.unwrap();
    let stored = store
        .find("KwlEDOBCBc9P1YU3NWihYLCeY-I9KGMhPap9vwHbVoI")
        .await
        .unwrap()
        .unwrap();

    let auth = issuer.request(&[stored]).unwrap();
    let mut auth_state: serde_json::Value = serde_json::from_str(&auth.state).unwrap();
    auth_state["state"]["ast"]["challenge"] =
        serde_json::Value::String("vXR-a0od0rVjsq3WptR82x2pCToaG3j2V62p0vGZlr0".into());
    let auth_state = auth_state.to_string();
    let state_store = MemSecrets::new();
    state_store
        .set("passkey:state", &auth_state, 60)
        .await
        .unwrap();

    let result = verifier
        .verify_once(
            &state_store,
            "passkey:state",
            include_str!("fixtures/passkey_auth.json"),
            &auth_state,
        )
        .await
        .unwrap();
    assert_eq!(
        result.credential_id,
        "KwlEDOBCBc9P1YU3NWihYLCeY-I9KGMhPap9vwHbVoI"
    );
    assert_eq!(result.counter, 1);
    assert!(result.user_verified);
    assert!(!result.backup_eligible);
    assert!(!result.backup_state);
    assert!(result.needs_update);
    assert!(result.data.is_some());

    assert!(
        verifier
            .verify_once(
                &state_store,
                "passkey:state",
                include_str!("fixtures/passkey_auth.json"),
                &auth_state,
            )
            .await
            .is_err()
    );

    let mut next = store
        .find("KwlEDOBCBc9P1YU3NWihYLCeY-I9KGMhPap9vwHbVoI")
        .await
        .unwrap()
        .unwrap();
    next.sign_count = result.counter;
    next.user_verified = result.user_verified;
    next.backup_eligible = result.backup_eligible;
    next.backup_state = result.backup_state;
    next.data = result.data.clone();
    assert!(
        store
            .update("KwlEDOBCBc9P1YU3NWihYLCeY-I9KGMhPap9vwHbVoI", 0, next,)
            .await
            .unwrap()
    );
    let updated = store
        .find("KwlEDOBCBc9P1YU3NWihYLCeY-I9KGMhPap9vwHbVoI")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.sign_count, 1);
    assert!(updated.last_used_at.is_some());
    assert_eq!(updated.data, result.data);
}
