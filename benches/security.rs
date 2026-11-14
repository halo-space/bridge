use halo::bridge::{Context, Identity, Node, Pipeline, Progress};
use halo::factor::social::Github;
use halo::pkg::password::{Algorithm, Password};
use halo::pkg::totp::Totp;
use halo::token::Token;
use halo::validator::sender::sms::{SmsConfig, SmsSender};
use serde_json::json;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let rounds = 5;
    let started = Instant::now();
    for _ in 0..rounds {
        let hash = Password::hash(black_box("benchmark-password"), Algorithm::Argon2id).unwrap();
        black_box(Password::verify("benchmark-password", &hash, Algorithm::Argon2id).unwrap());
    }
    println!("password rounds={rounds} elapsed={:?}", started.elapsed());

    let secret = Totp::generate_secret();
    let started = Instant::now();
    for _ in 0..rounds * 10 {
        let code = Totp::generate_code(&secret, 1_700_000_000).unwrap();
        black_box(Totp::verify_code(&secret, &code, 1_700_000_000).unwrap());
    }
    println!(
        "totp rounds={} elapsed={:?}",
        rounds * 10,
        started.elapsed()
    );

    let token = Token::new("benchmark-secret-long-enough-32-bytes", "bridge", 300, 3600);
    let identity = Identity::new("local", "benchmark");
    let started = Instant::now();
    for _ in 0..rounds * 10 {
        let (access, _) = token.issue_identity(&identity, None, None).unwrap();
        black_box(token.verify_token(&access).unwrap());
    }
    println!(
        "token rounds={} elapsed={:?}",
        rounds * 10,
        started.elapsed()
    );

    let pipeline = Pipeline::new("input", vec![Node::input("input", vec![])]);
    let started = Instant::now();
    for _ in 0..rounds * 100 {
        let (_, progress) = pipeline.start(Context::default()).unwrap();
        assert!(matches!(progress, Progress::Need { .. } | Progress::Done));
    }
    println!(
        "pipeline rounds={} elapsed={:?}",
        rounds * 100,
        started.elapsed()
    );

    let profile = json!({"id": 1, "login": "bench", "name": "Bench", "email": "bench@example.com"});
    let started = Instant::now();
    for _ in 0..rounds * 100 {
        black_box(Github::parse(&profile).unwrap());
    }
    println!(
        "provider rounds={} elapsed={:?}",
        rounds * 100,
        started.elapsed()
    );

    let sender = SmsSender::new(SmsConfig::default());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let started = Instant::now();
    runtime.block_on(async {
        for _ in 0..rounds * 100 {
            sender
                .send_code("13800138000", "123456", 300)
                .await
                .unwrap();
        }
    });
    println!(
        "sender rounds={} elapsed={:?}",
        rounds * 100,
        started.elapsed()
    );
}
