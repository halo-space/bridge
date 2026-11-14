use halo::bridge::{Context, Event, Identity, Node, Output, Pipeline, Progress, Runner};
use halo::factor::oidc::State;
use halo::factor::social::Github;
use serde_json::Value;

/// Provider 只负责协议和资料转换。
/// Runner 负责把调用方保存的 state、Provider 资料和 Pipeline 连接起来。
struct GithubLogin {
    state: String,
}

impl Runner for GithubLogin {
    async fn run(&self, node: &Node, context: &Context) -> halo::Result<Output> {
        let data = context
            .data
            .get(&node.id)
            .and_then(Value::as_object)
            .ok_or(halo::Error::AuthFailed("Missing GitHub input".into()))?;
        let state = data
            .get("state")
            .and_then(Value::as_str)
            .ok_or(halo::Error::AuthFailed("Missing state".into()))?;
        State::check(&self.state, state)?;

        let profile = Github::parse(
            data.get("profile")
                .ok_or(halo::Error::AuthFailed("Missing GitHub profile".into()))?,
        )?;
        let identity: Identity = profile.clone().into();

        Ok(Output::Pass {
            routes: Vec::new(),
            // 后续节点只需要统一身份资料，不把第三方 access token 放进流程输出。
            data: serde_json::json!({
                "provider": profile.provider,
                "subject": profile.openid,
                "email": profile.email,
            }),
            identity: Some(identity),
            at: 1,
        })
    }
}

#[tokio::main]
async fn main() -> halo::Result<()> {
    let pipeline = Pipeline::new(
        "input",
        vec![
            Node::input(
                "input",
                vec!["code".into(), "state".into(), "profile".into()],
            )
            .edge(None::<String>, "github"),
            Node::verify("github", "github"),
        ],
    );
    let state = State::new();
    let runner = GithubLogin {
        state: state.clone(),
    };
    let (mut run, _) = pipeline.start(Context::default())?;
    pipeline.resume(
        &mut run,
        Event::Input {
            node: "input".into(),
            data: serde_json::json!({
                "code": "github-code",
                "state": state,
                "profile": {
                    "id": 7,
                    "login": "alice",
                    "name": "Alice",
                    "email": "alice@example.com"
                }
            }),
            at: 1,
        },
    )?;
    let progress = pipeline.run(&mut run, &runner).await?;
    assert_eq!(progress, Progress::Done);
    println!("provider identity: {:?}", run.context.identity);
    Ok(())
}
