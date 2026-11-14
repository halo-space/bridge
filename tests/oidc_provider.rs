use halo::factor::oidc::{Config, Provider};
use halo::token::JwksResponse;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn exchange_code_reads_discovery_and_validates_id_token() {
    let mut rng = rand_core::OsRng;
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let private_pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let public = rsa::RsaPublicKey::from(&private);
    let jwks = JwksResponse::from_rsa_public_key(&public, "key-1");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let issuer = base.as_str();
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
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("key-1".into());
    let id_token = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap(),
    )
    .unwrap();

    let discovery = serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks")
    })
    .to_string();

    let bodies = vec![
        discovery,
        serde_json::to_string(&jwks).unwrap(),
        serde_json::json!({"access_token":"access","id_token":id_token}).to_string(),
    ];
    tokio::spawn(async move {
        for body in bodies {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    let provider = Provider::new(Config {
        issuer: base.clone(),
        client_id: "client".into(),
        client_secret: "secret".into(),
        scope: Some("openid profile email".into()),
        authorization_endpoint: None,
        token_endpoint: None,
        discovery_endpoint: Some(format!("{base}/discovery")),
        jwks_endpoint: None,
    });

    let profile = provider
        .exchange_code_for_profile(
            "code",
            "https://app/callback",
            Some("verifier"),
            Some("nonce-1"),
        )
        .await;
    assert_eq!(profile.unwrap().subject, "external-7");
}
