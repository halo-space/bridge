use halo::bridge::{Context, Event, Join, Node, Pipeline, Progress};
use serde_json::Value;

fn pass(node: &str, routes: &[&str]) -> Event {
    Event::Pass {
        node: node.into(),
        routes: routes.iter().map(|route| (*route).into()).collect(),
        data: Value::Null,
        identity: None,
        at: 1,
    }
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

fn run(pipeline: &Pipeline, events: Vec<Event>) -> halo::bridge::Result<Progress> {
    let (mut run, mut progress) = pipeline.start(Context::default())?;
    for event in events {
        progress = pipeline.resume(&mut run, event)?;
    }
    Ok(progress)
}

fn main() -> halo::bridge::Result<()> {
    let normal = run(
        &risk_branch(),
        vec![pass("password", &["normal"]), pass("audit", &[])],
    )?;
    let risk = run(
        &risk_branch(),
        vec![
            pass("password", &["risk"]),
            pass("totp", &[]),
            pass("audit", &[]),
        ],
    )?;
    let all = run(
        &all_factors(),
        vec![
            pass("start", &["password", "passkey"]),
            pass("password", &[]),
            pass("passkey", &[]),
            pass("join", &[]),
        ],
    )?;
    let any = run(
        &any_factor(),
        vec![
            pass("start", &["password", "passkey"]),
            pass("password", &[]),
            pass("join", &[]),
        ],
    )?;

    println!("normal branch: {normal:?}");
    println!("risk branch: {risk:?}");
    println!("all join: {all:?}");
    println!("any join: {any:?}");
    Ok(())
}
