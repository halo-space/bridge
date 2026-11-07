use halo::bridge::{Context, Node, Output, Pipeline, Progress, Runner};
use serde_json::Value;

struct Demo;

impl Runner for Demo {
    async fn run(&self, node: &Node, _context: &Context) -> halo::bridge::Result<Output> {
        let data = match node.id.as_str() {
            "phone" => serde_json::json!({"phone": "13800138000"}),
            "captcha" => serde_json::json!({"passed": true}),
            "sms_issue" => serde_json::json!({"id": "sms-1"}),
            "code" => serde_json::json!({"code": "123456"}),
            "sms" => serde_json::json!({"verified": true}),
            _ => Value::Null,
        };
        Ok(Output::Pass {
            routes: Vec::new(),
            data,
            identity: None,
            at: 1,
        })
    }
}

#[tokio::main]
async fn main() -> halo::bridge::Result<()> {
    let pipeline = Pipeline::new(
        "phone",
        vec![
            Node::input("phone", vec!["phone".into()]).edge(None::<String>, "captcha"),
            Node::verify("captcha", "slider").edge(None::<String>, "sms_issue"),
            Node::issue("sms_issue", "sms").edge(None::<String>, "code"),
            Node::input("code", vec!["code".into()]).edge(None::<String>, "sms"),
            Node::verify("sms", "sms"),
        ],
    );
    let runner = Demo;
    let (mut run, mut progress) = pipeline.start(Context::default())?;
    loop {
        match progress {
            Progress::Need { .. } => progress = pipeline.execute(&mut run, &runner).await?,
            Progress::Done => break,
            Progress::Retry { .. } | Progress::Deny { .. } => break,
        }
    }
    println!("runner result: {progress:?}");
    Ok(())
}
