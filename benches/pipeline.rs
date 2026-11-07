use halo::bridge::{Context, Event, Node, Pipeline, Progress};
use serde_json::Value;
use std::time::Instant;

fn pass(node: &str) -> Event {
    Event::Pass {
        node: node.into(),
        routes: Vec::new(),
        data: Value::Null,
        identity: None,
        at: 1,
    }
}

fn main() {
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
        pipeline.resume(&mut run, pass("b")).unwrap();
        assert_eq!(
            pipeline.resume(&mut run, pass("c")).unwrap(),
            Progress::Done
        );
    }
    let elapsed = started.elapsed();
    println!(
        "pipeline rounds={rounds} elapsed={elapsed:?} per_round={:?}",
        elapsed / rounds
    );
}
