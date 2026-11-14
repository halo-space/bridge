use halo::bridge::{Context, Event, Node, Output, Pipeline, Progress, Runner};
use serde_json::json;
use std::time::Instant;

struct Pass;

impl Runner for Pass {
    async fn run(&self, _node: &Node, _context: &Context) -> halo::bridge::Result<Output> {
        Ok(Output::Pass {
            routes: Vec::new(),
            data: json!({ "passed": true }),
            identity: None,
            at: 1,
        })
    }
}

#[tokio::main]
async fn main() {
    let pipeline = Pipeline::new(
        "a",
        vec![
            Node::input("a", vec![]).edge(None::<String>, "b"),
            Node::verify("b", "code").edge(None::<String>, "c"),
            Node::effect("c", "audit"),
        ],
    );
    let rounds = 10_000;
    let started = Instant::now();
    for _ in 0..rounds {
        let (mut run, progress) = pipeline.start(Context::default()).unwrap();
        assert!(matches!(progress, Progress::Need { .. }));
        pipeline
            .resume(
                &mut run,
                Event::Input {
                    node: "a".into(),
                    data: serde_json::json!({ "value": 1 }),
                    at: 1,
                },
            )
            .unwrap();
        pipeline
            .resume(
                &mut run,
                Event::Input {
                    node: "b".into(),
                    data: json!({ "code": "123456" }),
                    at: 1,
                },
            )
            .unwrap();
        assert_eq!(pipeline.run(&mut run, &Pass).await.unwrap(), Progress::Done);
    }
    let elapsed = started.elapsed();
    println!(
        "pipeline rounds={rounds} elapsed={elapsed:?} per_round={:?}",
        elapsed / rounds
    );
}
