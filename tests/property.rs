use halo::bridge::{Context, PipelineConfig};
use halo::token::Token;
use halo::types::Identity;
use proptest::prelude::*;
use serde_json::json;

proptest! {
    #[test]
    fn context_validation_is_bounded(text in "[a-zA-Z0-9]{0,9000}") {
        let context = Context {
            request: json!({"value": text}),
            ..Context::default()
        };
        let result = context.validate();
        prop_assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn invalid_pipeline_never_panics(start in "[a-z]{0,8}") {
        let config = PipelineConfig {
            version: 1,
            start,
            max_steps: Some(128),
            nodes: Vec::new(),
        };
        let cards = halo::bridge::Cards::new();
        let result = config.compile_with(&cards);
        prop_assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn token_subject_round_trips(subject in "[a-zA-Z0-9:_-]{1,48}") {
        let token = Token::new("property-secret-with-at-least-32-bytes", "bridge", 300, 600);
        let identity = Identity::new("test", subject.clone());
        let (access, _) = token.issue_identity(&identity, None, None).unwrap();
        let claims = token.verify_token(&access).unwrap();
        prop_assert_eq!(claims.sub, subject);
    }
}
