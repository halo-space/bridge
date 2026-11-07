use bridge::{Context, Event, Node, Pipeline, Progress};
use serde_json::json;

fn pass(node: &str, data: serde_json::Value) -> Event {
    Event::Pass {
        node: node.into(),
        routes: Vec::new(),
        data,
        identity: None,
        at: 1,
    }
}

fn run(pipeline: &Pipeline, events: Vec<Event>) -> bridge::Result<Progress> {
    let (mut run, mut progress) = pipeline.start(Context::default())?;
    for event in events {
        progress = pipeline.resume(&mut run, event)?;
    }
    Ok(progress)
}

fn phone_code() -> Pipeline {
    Pipeline::new(
        "phone",
        vec![
            Node::input("phone", vec!["phone".into()]).edge(None::<String>, "captcha"),
            Node::verify("captcha", "slider").edge(None::<String>, "sms_issue"),
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
            Node::verify("password", "password").edge(None::<String>, "totp"),
            Node::verify("totp", "totp"),
        ],
    )
}

fn password_passkey() -> Pipeline {
    Pipeline::new(
        "password",
        vec![
            Node::verify("password", "password").edge(None::<String>, "passkey"),
            Node::issue("passkey", "webauthn").edge(None::<String>, "credential"),
            Node::input("credential", vec!["credential".into()]).edge(None::<String>, "check"),
            Node::verify("check", "passkey"),
        ],
    )
}

fn main() -> bridge::Result<()> {
    let phone = phone_code();
    let phone_result = run(
        &phone,
        vec![
            pass("phone", json!({"phone": "13800138000"})),
            pass("captcha", json!({"passed": true})),
            pass("sms_issue", json!({"id": "sms-1"})),
            pass("code", json!({"code": "123456"})),
            pass("sms", json!({"passed": true})),
        ],
    )?;

    let password_totp_result = run(
        &password_totp(),
        vec![
            pass("password", json!({"account": "alice", "password": "***"})),
            pass("totp", json!({"code": "123456"})),
        ],
    )?;

    let passkey_result = run(
        &password_passkey(),
        vec![
            pass("password", json!({"account": "alice", "password": "***"})),
            pass("passkey", json!({"challenge": "..."})),
            pass("credential", json!({"credential": "..."})),
            pass("check", json!({"verified": true})),
        ],
    )?;

    println!("phone code: {phone_result:?}");
    println!("password + totp: {password_totp_result:?}");
    println!("password + passkey: {passkey_result:?}");
    Ok(())
}
