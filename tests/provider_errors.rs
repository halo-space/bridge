use halo::Error;
use halo::factor::enterprise::{DingtalkConfig, DingtalkProvider, WecomConfig, WecomProvider};
use halo::factor::social::{
    FeishuConfig, FeishuProvider, GithubConfig, GithubProvider, GoogleConfig, GoogleProvider,
    WechatConfig, WechatProvider,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const DEAD: &str = "http://127.0.0.1:1";

#[tokio::test]
async fn providers_surface_network_failures() {
    let github = GithubProvider::new(GithubConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
        scope: None,
    })
    .endpoint(DEAD);
    assert!(
        github
            .exchange_code_for_profile("code", "https://app/callback")
            .await
            .is_err()
    );

    let google = GoogleProvider::new(GoogleConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
        scope: None,
    })
    .endpoint(DEAD);
    assert!(
        google
            .exchange_code_for_profile("code", "https://app/callback")
            .await
            .is_err()
    );

    let wechat = WechatProvider::new(WechatConfig {
        app_id: "id".into(),
        app_secret: "secret".into(),
        scope: None,
    })
    .endpoint(DEAD);
    assert!(wechat.exchange_code_for_profile("code").await.is_err());

    let feishu = FeishuProvider::new(FeishuConfig {
        app_id: "id".into(),
        app_secret: "secret".into(),
    })
    .endpoint(DEAD);
    assert!(
        feishu
            .exchange_code_for_profile("code", "https://app/callback")
            .await
            .is_err()
    );

    let wecom = WecomProvider::new(WecomConfig {
        corp_id: "id".into(),
        agent_id: "agent".into(),
        corp_secret: "secret".into(),
    })
    .endpoint(DEAD);
    assert!(wecom.exchange_code_for_user("code").await.is_err());

    let dingtalk = DingtalkProvider::new(DingtalkConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
    })
    .endpoint(DEAD);
    assert!(dingtalk.exchange_code_for_user("code").await.is_err());
}

async fn endpoint(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    format!("http://{address}")
}

fn oauth_error<T>(result: halo::Result<T>, text: &str) {
    match result {
        Err(Error::OAuthError(message)) => assert!(message.contains(text), "{message}"),
        Err(error) => panic!("unexpected error: {error:?}"),
        Ok(_) => panic!("expected provider error"),
    }
}

#[tokio::test]
async fn providers_surface_business_errors() {
    let github = GithubProvider::new(GithubConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
        scope: None,
    })
    .endpoint(endpoint(r#"{"error":"bad_code","error_description":"invalid code"}"#).await);
    oauth_error(
        github
            .exchange_code_for_profile("code", "https://app/callback")
            .await,
        "invalid code",
    );

    let google = GoogleProvider::new(GoogleConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
        scope: None,
    })
    .endpoint(endpoint(r#"{"error":"invalid_grant","error_description":"expired code"}"#).await);
    oauth_error(
        google
            .exchange_code_for_profile("code", "https://app/callback")
            .await,
        "expired code",
    );

    let wechat = WechatProvider::new(WechatConfig {
        app_id: "id".into(),
        app_secret: "secret".into(),
        scope: None,
    })
    .endpoint(endpoint(r#"{"errcode":40029,"errmsg":"invalid code"}"#).await);
    oauth_error(
        wechat.exchange_code_for_profile("code").await,
        "invalid code",
    );

    let feishu = FeishuProvider::new(FeishuConfig {
        app_id: "id".into(),
        app_secret: "secret".into(),
    })
    .endpoint(endpoint(r#"{"code":999,"msg":"invalid app"}"#).await);
    oauth_error(
        feishu
            .exchange_code_for_profile("code", "https://app/callback")
            .await,
        "invalid app",
    );

    let wecom = WecomProvider::new(WecomConfig {
        corp_id: "id".into(),
        agent_id: "agent".into(),
        corp_secret: "secret".into(),
    })
    .endpoint(endpoint(r#"{"errcode":40014,"errmsg":"invalid corp"}"#).await);
    oauth_error(wecom.exchange_code_for_user("code").await, "invalid corp");

    let dingtalk = DingtalkProvider::new(DingtalkConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
    })
    .endpoint(endpoint(r#"{"code":"invalid","message":"invalid app"}"#).await);
    oauth_error(dingtalk.exchange_code_for_user("code").await, "invalid app");
}
