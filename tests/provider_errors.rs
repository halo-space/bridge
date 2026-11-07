use halo::factor::enterprise::{DingtalkConfig, DingtalkProvider, WecomConfig, WecomProvider};
use halo::factor::social::{
    FeishuConfig, FeishuProvider, GithubConfig, GithubProvider, GoogleConfig, GoogleProvider,
    WechatConfig, WechatProvider,
};

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
