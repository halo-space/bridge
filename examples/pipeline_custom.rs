use halo::bridge::{Context, Event, Extend, Identity, Node, Output, Pipeline, Progress, Runner};
use serde_json::Value;

struct Defaults;

impl Runner for Defaults {
    async fn run(&self, node: &Node, _context: &Context) -> halo::Result<Output> {
        Err(halo::IdpError::Internal(format!(
            "Unsupported pipeline node: {}",
            node.id
        )))
    }
}

struct CompanyPassword;

impl Runner for CompanyPassword {
    async fn run(&self, node: &Node, context: &Context) -> halo::Result<Output> {
        if node.kind != halo::bridge::Kind::Verify("password".into()) {
            return Err(halo::IdpError::Internal(format!(
                "Unsupported pipeline node: {}",
                node.id
            )));
        }
        let input = context
            .data
            .get(&node.id)
            .and_then(Value::as_object)
            .ok_or_else(|| halo::IdpError::InvalidCredentials)?;
        if input.get("username").and_then(Value::as_str) != Some("alice")
            || input.get("password").and_then(Value::as_str) != Some("company-secret")
        {
            return Err(halo::IdpError::InvalidCredentials);
        }
        Ok(Output::Pass {
            routes: Vec::new(),
            data: serde_json::json!({ "source": "company-password" }),
            identity: Some(Identity::new("company", "alice")),
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
                vec!["username".into(), "password".into(), "tenant".into()],
            )
            .edge(None::<String>, "password"),
            Node::verify("password", "password"),
        ],
    );
    let runner = Extend::new(Defaults, CompanyPassword);
    let (mut run, _) = pipeline.start(Context::default())?;
    pipeline.resume(
        &mut run,
        Event::Input {
            node: "input".into(),
            data: serde_json::json!({
                "username": "alice",
                "password": "company-secret",
                "tenant": "acme"
            }),
            at: 1,
        },
    )?;
    let progress = pipeline.run(&mut run, &runner).await?;
    assert_eq!(progress, Progress::Done);
    println!("custom password: {progress:?}");
    Ok(())
}
