use halo::bridge::{Context, Event, Node, Output, Pipeline, Progress, Runner};
use serde_json::{Value, json};

struct Demo;

impl Runner for Demo {
    async fn run(&self, node: &Node, context: &Context) -> halo::bridge::Result<Output> {
        let data = context.data.get(&node.id).cloned().unwrap_or(Value::Null);
        let routes =
            if node.id == "password" && data.get("risk").and_then(Value::as_bool) == Some(true) {
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

fn phone_code() -> Pipeline {
    Pipeline::new(
        "phone",
        vec![
            Node::input("phone", vec!["phone".into()]).edge(None::<String>, "captcha"),
            Node::input("captcha", vec!["answer".into()]).edge(None::<String>, "sms_issue"),
            Node::issue("sms_issue", "sms").edge(None::<String>, "code"),
            Node::input("code", vec!["code".into()]).edge(None::<String>, "sms"),
            Node::verify("sms", "sms"),
        ],
    )
}

fn password_totp() -> Pipeline {
    Pipeline::new(
        "password",
        vec![
            Node::input("password", vec!["account".into(), "password".into()])
                .edge(None::<String>, "totp"),
            Node::input("totp", vec!["code".into()]).edge(None::<String>, "done"),
            Node::effect("done", "audit"),
        ],
    )
}

#[tokio::main]
async fn main() -> halo::bridge::Result<()> {
    let runner = Demo;
    let phone = phone_code();
    let (mut run, _) = phone.start(Context::default())?;
    input(&phone, &mut run, "phone", json!({ "phone": "13800138000" })).await?;
    input(&phone, &mut run, "captcha", json!({ "answer": "ok" })).await?;
    let progress = phone.run(&mut run, &runner).await?;
    println!("phone issue: {progress:?}");
    input(&phone, &mut run, "code", json!({ "code": "123456" })).await?;
    let progress = phone.run(&mut run, &runner).await?;
    println!("phone code: {progress:?}");

    let password = password_totp();
    let (mut run, _) = password.start(Context::default())?;
    input(
        &password,
        &mut run,
        "password",
        json!({ "account": "alice", "password": "***" }),
    )
    .await?;
    let progress = password.run(&mut run, &runner).await?;
    println!("password + totp: {progress:?}");
    input(&password, &mut run, "totp", json!({ "code": "123456" })).await?;
    let progress = password.run(&mut run, &runner).await?;
    println!("completed: {progress:?}");
    Ok(())
}
