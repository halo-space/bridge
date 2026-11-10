use halo::Error;
use halo::factor::enterprise::{Dingtalk, DingtalkConfig, Wecom, WecomConfig};
use halo::factor::social::{
    Feishu, FeishuConfig, Github, GithubConfig, Google, GoogleConfig, Wechat, WechatConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const DEAD: &str = "http://127.0.0.1:1";

#[tokio::test]
async fn providers_surface_network_failures() {
    let github = Github::new(GithubConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
        scope: None,
    })
    .auth(DEAD);
    assert!(
        github
            .exchange_code_for_profile("code", "https://app/callback")
            .await
            .is_err()
    );

    let google = Google::new(GoogleConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
        scope: None,
    })
    .auth(DEAD);
    assert!(
        google
            .exchange_code_for_profile("code", "https://app/callback")
            .await
            .is_err()
    );

    let wechat = Wechat::new(WechatConfig {
        app_id: "id".into(),
        app_secret: "secret".into(),
        scope: None,
    })
    .api(DEAD);
    assert!(wechat.exchange_code_for_profile("code").await.is_err());

    let feishu = Feishu::new(FeishuConfig {
        app_id: "id".into(),
        app_secret: "secret".into(),
    })
    .api(DEAD);
    assert!(
        feishu
            .exchange_code_for_profile("code", "https://app/callback")
            .await
            .is_err()
    );

    let wecom = Wecom::new(WecomConfig {
        corp_id: "id".into(),
        agent_id: "agent".into(),
        corp_secret: "secret".into(),
    })
    .api(DEAD);
    assert!(wecom.exchange_code_for_user("code").await.is_err());

    let dingtalk = Dingtalk::new(DingtalkConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
    })
    .api(DEAD);
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

async fn sequence(bodies: Vec<&'static str>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for body in bodies {
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
    let github = Github::new(GithubConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
        scope: None,
    })
    .auth(endpoint(r#"{"error":"bad_code","error_description":"invalid code"}"#).await);
    oauth_error(
        github
            .exchange_code_for_profile("code", "https://app/callback")
            .await,
        "invalid code",
    );

    let google = Google::new(GoogleConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
        scope: None,
    })
    .auth(endpoint(r#"{"error":"invalid_grant","error_description":"expired code"}"#).await);
    oauth_error(
        google
            .exchange_code_for_profile("code", "https://app/callback")
            .await,
        "expired code",
    );

    let wechat = Wechat::new(WechatConfig {
        app_id: "id".into(),
        app_secret: "secret".into(),
        scope: None,
    })
    .api(endpoint(r#"{"errcode":40029,"errmsg":"invalid code"}"#).await);
    oauth_error(
        wechat.exchange_code_for_profile("code").await,
        "invalid code",
    );

    let feishu = Feishu::new(FeishuConfig {
        app_id: "id".into(),
        app_secret: "secret".into(),
    })
    .api(endpoint(r#"{"code":999,"msg":"invalid app"}"#).await);
    oauth_error(
        feishu
            .exchange_code_for_profile("code", "https://app/callback")
            .await,
        "invalid app",
    );

    let wecom = Wecom::new(WecomConfig {
        corp_id: "id".into(),
        agent_id: "agent".into(),
        corp_secret: "secret".into(),
    })
    .api(endpoint(r#"{"errcode":40014,"errmsg":"invalid corp"}"#).await);
    oauth_error(wecom.exchange_code_for_user("code").await, "invalid corp");

    let dingtalk = Dingtalk::new(DingtalkConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
    })
    .api(endpoint(r#"{"code":"invalid","message":"invalid app"}"#).await);
    oauth_error(dingtalk.exchange_code_for_user("code").await, "invalid app");
}

#[tokio::test]
async fn providers_complete_success_flows() {
    let github_endpoint = sequence(vec![
        r#"{"access_token":"gh-token"}"#,
        r#"{"id":7,"login":"alice","name":"Alice","email":"alice@example.com"}"#,
    ])
    .await;
    let github = Github::new(GithubConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
        scope: None,
    })
    .auth(&github_endpoint)
    .api(&github_endpoint);
    let profile = github
        .exchange_code_for_profile("code", "https://app/callback")
        .await
        .unwrap();
    assert_eq!(profile.provider, "github");
    assert_eq!(profile.openid, "7");
    assert_eq!(profile.email.as_deref(), Some("alice@example.com"));

    let google_endpoint = sequence(vec![
        r#"{"access_token":"google-token"}"#,
        r#"{"sub":"google-1","email":"alice@example.com","name":"Alice"}"#,
    ])
    .await;
    let google = Google::new(GoogleConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
        scope: None,
    })
    .auth(&google_endpoint)
    .userinfo(&google_endpoint);
    let profile = google
        .exchange_code_for_profile("code", "https://app/callback")
        .await
        .unwrap();
    assert_eq!(profile.provider, "google");
    assert_eq!(profile.openid, "google-1");

    let wechat_endpoint = sequence(vec![
        r#"{"access_token":"wechat-token","openid":"wx-1"}"#,
        r#"{"openid":"wx-1","unionid":"union-1","nickname":"Alice"}"#,
    ])
    .await;
    let wechat = Wechat::new(WechatConfig {
        app_id: "id".into(),
        app_secret: "secret".into(),
        scope: None,
    })
    .api(&wechat_endpoint);
    let profile = wechat.exchange_code_for_profile("code").await.unwrap();
    assert_eq!(profile.provider, "wechat");
    assert_eq!(profile.openid, "wx-1");
    assert_eq!(profile.unionid.as_deref(), Some("union-1"));

    let feishu_endpoint = sequence(vec![
        r#"{"app_access_token":"app-token"}"#,
        r#"{"data":{"access_token":"user-token"}}"#,
        r#"{"data":{"open_id":"fs-1","union_id":"union-1","name":"Alice"}}"#,
    ])
    .await;
    let feishu = Feishu::new(FeishuConfig {
        app_id: "id".into(),
        app_secret: "secret".into(),
    })
    .api(&feishu_endpoint);
    let profile = feishu
        .exchange_code_for_profile("code", "https://app/callback")
        .await
        .unwrap();
    assert_eq!(profile.provider, "feishu");
    assert_eq!(profile.openid, "fs-1");

    let wecom_endpoint = sequence(vec![
        r#"{"access_token":"wecom-token"}"#,
        r#"{"UserId":"wecom-1","name":"Alice"}"#,
    ])
    .await;
    let wecom = Wecom::new(WecomConfig {
        corp_id: "id".into(),
        agent_id: "agent".into(),
        corp_secret: "secret".into(),
    })
    .api(&wecom_endpoint);
    let value = wecom.exchange_code_for_user("code").await.unwrap();
    assert_eq!(Wecom::identity(&value).unwrap().subject, "wecom-1");

    let dingtalk_endpoint = sequence(vec![
        r#"{"accessToken":"ding-token"}"#,
        r#"{"unionId":"ding-1","nick":"Alice"}"#,
    ])
    .await;
    let dingtalk = Dingtalk::new(DingtalkConfig {
        client_id: "id".into(),
        client_secret: "secret".into(),
    })
    .api(&dingtalk_endpoint);
    let value = dingtalk.exchange_code_for_user("code").await.unwrap();
    assert_eq!(Dingtalk::identity(&value).unwrap().subject, "ding-1");
}
