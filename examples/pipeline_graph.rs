use halo::bridge::{Context, Event, Join, Kind, Node, Output, Pipeline, Progress, Runner};
use serde_json::{Value, json};

struct Demo;

impl Runner for Demo {
    async fn run(&self, node: &Node, context: &Context) -> halo::bridge::Result<Output> {
        let data = context.data.get(&node.id).cloned().unwrap_or(Value::Null);
        let routes = if node.id == "start" {
            data.get("routes")
                .and_then(Value::as_array)
                .map(|routes| {
                    routes
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        } else if matches!(node.kind, Kind::Verify(ref code) if code == "password")
            && data.get("risk").and_then(Value::as_bool) == Some(true)
        {
            vec!["risk".into()]
        } else {
            Vec::new()
        };
        Ok(Output::Pass {
            routes,
            data: json!({ "simulated": true }),
            identity: None,
            at: 1,
        })
    }
}

async fn input(
    pipeline: &Pipeline,
    run: &mut halo::bridge::Run,
    node: &str,
    data: Value,
) -> halo::bridge::Result<Progress> {
    pipeline.resume(
        run,
        Event::Input {
            node: node.into(),
            data,
            at: 1,
        },
    )
}

fn risk_branch() -> Pipeline {
    Pipeline::new(
        "password",
        vec![
            Node::verify("password", "password")
                .edge(Some("normal"), "audit")
                .edge(Some("risk"), "totp"),
            Node::verify("totp", "totp").edge(None::<String>, "audit"),
            Node::effect("audit", "audit").join(Join::Any),
        ],
    )
}

fn all_factors() -> Pipeline {
    Pipeline::new(
        "start",
        vec![
            Node::verify("start", "start")
                .edge(Some("password"), "password")
                .edge(Some("passkey"), "passkey"),
            Node::verify("password", "password").edge(None::<String>, "join"),
            Node::verify("passkey", "passkey").edge(None::<String>, "join"),
            Node::effect("join", "audit").join(Join::All),
        ],
    )
}

fn any_factor() -> Pipeline {
    Pipeline::new(
        "start",
        vec![
            Node::verify("start", "start")
                .edge(Some("password"), "password")
                .edge(Some("passkey"), "passkey"),
            Node::verify("password", "password").edge(None::<String>, "join"),
            Node::verify("passkey", "passkey").edge(None::<String>, "join"),
            Node::effect("join", "audit").join(Join::Any),
        ],
    )
}

async fn run_risk(runner: &Demo, risk: bool) -> halo::bridge::Result<Progress> {
    let pipeline = risk_branch();
    let (mut run, _) = pipeline.start(Context::default())?;
    input(&pipeline, &mut run, "password", json!({ "risk": risk })).await?;
    let progress = pipeline.run(&mut run, runner).await?;
    if risk {
        input(&pipeline, &mut run, "totp", json!({ "code": "123456" })).await?;
        pipeline.run(&mut run, runner).await
    } else {
        Ok(progress)
    }
}

async fn run_join(
    pipeline: Pipeline,
    runner: &Demo,
    start: &[&str],
    branches: &[&str],
) -> halo::bridge::Result<Progress> {
    let (mut run, _) = pipeline.start(Context::default())?;
    let routes = start
        .iter()
        .map(|route| (*route).to_string())
        .collect::<Vec<_>>();
    input(&pipeline, &mut run, "start", json!({ "routes": routes })).await?;
    let mut progress = pipeline.run(&mut run, runner).await?;
    for branch in branches {
        if !matches!(progress, Progress::Need { ref node, .. } if node == branch) {
            break;
        }
        input(&pipeline, &mut run, branch, json!({ "ok": true })).await?;
        progress = pipeline.run(&mut run, runner).await?;
    }
    Ok(progress)
}

#[tokio::main]
async fn main() -> halo::bridge::Result<()> {
    let runner = Demo;
    println!("normal branch: {:?}", run_risk(&runner, false).await?);
    println!("risk branch: {:?}", run_risk(&runner, true).await?);
    println!(
        "all join: {:?}",
        run_join(
            all_factors(),
            &runner,
            &["password", "passkey"],
            &["password", "passkey"],
        )
        .await?
    );
    println!(
        "any join: {:?}",
        run_join(
            any_factor(),
            &runner,
            &["password", "passkey"],
            &["password"]
        )
        .await?
    );
    Ok(())
}
