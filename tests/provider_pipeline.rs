use halo::bridge::{Context, Event, Identity, Node, Output, Pipeline, Progress, Runner};
use halo::factor::oidc::State;
use halo::factor::social::Github;
use serde_json::Value;

struct Login {
    state: String,
    mismatch: bool,
}

impl Runner for Login {
    async fn run(&self, node: &Node, context: &Context) -> halo::Result<Output> {
        let data = context
            .data
            .get(&node.id)
            .and_then(Value::as_object)
            .ok_or(halo::Error::AuthFailed("Missing provider input".into()))?;

        match &node.kind {
            halo::bridge::Kind::Verify(kind) if kind == "github" => {
                let state = data
                    .get("state")
                    .and_then(Value::as_str)
                    .ok_or(halo::Error::AuthFailed("Missing state".into()))?;
                State::check(&self.state, state)?;
                let profile = Github::parse(
                    data.get("profile")
                        .ok_or(halo::Error::AuthFailed("Missing provider profile".into()))?,
                )?;
                let identity: Identity = profile.clone().into();
                Ok(Output::Pass {
                    routes: Vec::new(),
                    data: serde_json::json!({
                        "provider": profile.provider,
                        "subject": profile.openid,
                        "email": profile.email,
                    }),
                    identity: Some(identity),
                    at: 1,
                })
            }
            halo::bridge::Kind::Verify(kind) if kind == "totp" => {
                if data.get("code").and_then(Value::as_str) != Some("123456") {
                    return Err(halo::Error::InvalidCredentials);
                }
                let identity = context
                    .identity
                    .clone()
                    .ok_or(halo::Error::InvalidCredentials)?;
                let identity = if self.mismatch {
                    Identity::new("github", "other")
                } else {
                    identity
                };
                Ok(Output::Pass {
                    routes: Vec::new(),
                    data: serde_json::json!({ "verified": "totp" }),
                    identity: Some(identity),
                    at: 2,
                })
            }
            _ => Err(halo::Error::Unsupported(node.id.clone())),
        }
    }
}

fn pipeline() -> Pipeline {
    Pipeline::new(
        "input",
        vec![
            Node::input(
                "input",
                vec!["code".into(), "state".into(), "profile".into()],
            )
            .edge(None::<String>, "github"),
            Node::verify("github", "github").edge(None::<String>, "totp_input"),
            Node::input("totp_input", vec!["code".into()]).edge(None::<String>, "totp"),
            Node::verify("totp", "totp"),
        ],
    )
}

#[tokio::test]
async fn provider_identity_continues_into_pipeline() {
    let pipeline = pipeline();
    let state = State::new();
    let runner = Login {
        state: state.clone(),
        mismatch: false,
    };
    let (mut run, _) = pipeline.start(Context::default()).unwrap();
    pipeline
        .resume(
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
                        "email": "alice@example.com",
                        "access_token": "must-not-enter-the-run"
                    }
                }),
                at: 1,
            },
        )
        .unwrap();
    assert!(matches!(
        pipeline.run(&mut run, &runner).await.unwrap(),
        Progress::Need { ref node, .. } if node == "totp_input"
    ));
    pipeline
        .resume(
            &mut run,
            Event::Input {
                node: "totp_input".into(),
                data: serde_json::json!({ "code": "123456" }),
                at: 2,
            },
        )
        .unwrap();
    assert_eq!(
        pipeline.run(&mut run, &runner).await.unwrap(),
        Progress::Done
    );
    assert_eq!(
        run.context
            .identity
            .as_ref()
            .map(|identity| identity.subject.as_str()),
        Some("7")
    );
    let serialized = serde_json::to_string(&run).unwrap();
    assert!(!serialized.contains("must-not-enter-the-run"));
}

#[tokio::test]
async fn provider_identity_mismatch_denies_following_factor() {
    let pipeline = pipeline();
    let state = State::new();
    let runner = Login {
        state: state.clone(),
        mismatch: true,
    };
    let (mut run, _) = pipeline.start(Context::default()).unwrap();
    pipeline
        .resume(
            &mut run,
            Event::Input {
                node: "input".into(),
                data: serde_json::json!({
                    "code": "github-code",
                    "state": state,
                    "profile": {"id": 7}
                }),
                at: 1,
            },
        )
        .unwrap();
    assert!(matches!(
        pipeline.run(&mut run, &runner).await.unwrap(),
        Progress::Need { ref node, .. } if node == "totp_input"
    ));
    pipeline
        .resume(
            &mut run,
            Event::Input {
                node: "totp_input".into(),
                data: serde_json::json!({ "code": "123456" }),
                at: 2,
            },
        )
        .unwrap();
    assert!(matches!(
        pipeline.run(&mut run, &runner).await.unwrap(),
        Progress::Deny { ref reason, .. } if reason == "Identity mismatch"
    ));
}
