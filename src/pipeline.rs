use crate::error::{IdpError, Result};
use crate::types::Identity;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Pipeline 中的一个节点。`kind` 由调用方映射到具体 issuer、sender 或 verifier。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Node {
    Input { id: String, fields: Vec<String> },
    Check { id: String, kind: String },
    Issue { id: String, kind: String },
    Verify { id: String, kind: String },
    Effect { id: String, kind: String },
}

impl Node {
    pub fn input(id: impl Into<String>, fields: Vec<String>) -> Self {
        Self::Input {
            id: id.into(),
            fields,
        }
    }

    pub fn check(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self::Check {
            id: id.into(),
            kind: kind.into(),
        }
    }

    pub fn issue(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self::Issue {
            id: id.into(),
            kind: kind.into(),
        }
    }

    pub fn verify(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self::Verify {
            id: id.into(),
            kind: kind.into(),
        }
    }

    pub fn effect(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self::Effect {
            id: id.into(),
            kind: kind.into(),
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::Input { id, .. }
            | Self::Check { id, .. }
            | Self::Issue { id, .. }
            | Self::Verify { id, .. }
            | Self::Effect { id, .. } => id,
        }
    }

    fn kind(&self) -> &str {
        match self {
            Self::Input { .. } => "input",
            Self::Check { kind, .. } => kind,
            Self::Issue { kind, .. } => kind,
            Self::Verify { kind, .. } => kind,
            Self::Effect { kind, .. } => kind,
        }
    }

    fn fields(&self) -> Vec<String> {
        match self {
            Self::Input { fields, .. } => fields.clone(),
            _ => Vec::new(),
        }
    }
}

/// 节点之间传递的认证上下文。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    pub tenant_id: i64,
    pub identity: Option<Identity>,
    pub data: Map<String, Value>,
    pub evidence: Vec<Evidence>,
}

/// 已完成节点产生的证据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub node: String,
    pub at: i64,
    pub data: Value,
}

/// 调用方执行当前节点后回传的结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    Pass {
        node: String,
        data: Value,
        identity: Option<Identity>,
        at: i64,
    },
    Fail {
        node: String,
        reason: String,
        retry: bool,
    },
}

/// Pipeline 暂停状态。调用方可以序列化并以单次凭证保存。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub index: usize,
    pub context: Context,
}

/// Pipeline 当前执行结果。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Progress {
    Need {
        index: usize,
        node: String,
        kind: String,
        fields: Vec<String>,
    },
    Retry {
        index: usize,
        node: String,
        reason: String,
    },
    Deny {
        node: String,
        reason: String,
    },
    Done,
}

/// 登录前、认证中和登录后的统一流程编排器。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pipeline {
    nodes: Vec<Node>,
}

impl Pipeline {
    pub fn new(nodes: Vec<Node>) -> Self {
        Self { nodes }
    }

    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    pub fn validate(&self) -> Result<()> {
        let mut ids = std::collections::HashSet::new();
        for node in &self.nodes {
            if node.id().trim().is_empty() {
                return Err(IdpError::Internal("Pipeline node id is empty".into()));
            }
            if !ids.insert(node.id()) {
                return Err(IdpError::Internal(format!(
                    "Pipeline node id is duplicated: {}",
                    node.id()
                )));
            }
        }
        Ok(())
    }

    pub fn start(&self, context: Context) -> Result<(Run, Progress)> {
        self.validate()?;
        let mut state = Run { index: 0, context };
        let progress = self.advance(&mut state);
        Ok((state, progress))
    }

    pub fn resume(&self, state: &mut Run, event: Event) -> Result<Progress> {
        let Some(node) = self.nodes.get(state.index) else {
            return Ok(Progress::Done);
        };
        let current = node.id().to_string();
        match event {
            Event::Pass {
                node,
                data,
                identity,
                at,
            } => {
                self.check_node(&current, &node)?;
                if let Some(identity) = identity {
                    if let Some(existing) = &state.context.identity {
                        if existing.provider != identity.provider
                            || existing.subject != identity.subject
                        {
                            return Ok(Progress::Deny {
                                node: current,
                                reason: "Identity mismatch".into(),
                            });
                        }
                    } else {
                        state.context.identity = Some(identity);
                    }
                }
                state.context.data.insert(current.clone(), data.clone());
                state.context.evidence.push(Evidence {
                    node: current,
                    at,
                    data,
                });
                state.index += 1;
                Ok(self.advance(state))
            }
            Event::Fail {
                node,
                reason,
                retry,
            } => {
                self.check_node(&current, &node)?;
                if retry {
                    Ok(Progress::Retry {
                        index: state.index,
                        node: current,
                        reason,
                    })
                } else {
                    Ok(Progress::Deny {
                        node: current,
                        reason,
                    })
                }
            }
        }
    }

    fn advance(&self, state: &mut Run) -> Progress {
        match self.nodes.get(state.index) {
            Some(node) => Progress::Need {
                index: state.index,
                node: node.id().to_string(),
                kind: node.kind().to_string(),
                fields: node.fields(),
            },
            None => Progress::Done,
        }
    }

    fn check_node(&self, expected: &str, actual: &str) -> Result<()> {
        if expected == actual {
            Ok(())
        } else {
            Err(IdpError::AuthFailed(format!(
                "Pipeline node mismatch: expected {expected}, got {actual}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pipeline() -> Pipeline {
        Pipeline::new(vec![
            Node::input("phone", vec!["phone".into()]),
            Node::verify("captcha", "slider"),
            Node::issue("sms", "sms"),
            Node::input("sms_code", vec!["code".into()]),
            Node::verify("sms_check", "sms"),
            Node::verify("totp", "totp"),
            Node::effect("audit", "audit"),
        ])
    }

    #[test]
    fn advances_phone_captcha_sms_totp_chain() {
        let pipeline = pipeline();
        let (mut state, progress) = pipeline.start(Context::default()).unwrap();
        assert_eq!(
            progress,
            Progress::Need {
                index: 0,
                node: "phone".into(),
                kind: "input".into(),
                fields: vec!["phone".into()],
            }
        );

        for (node, data) in [
            ("phone", serde_json::json!({"phone": "13800138000"})),
            ("captcha", serde_json::json!({"passed": true})),
            ("sms", serde_json::json!({"id": "sms-1"})),
            ("sms_code", serde_json::json!({"code": "123456"})),
            ("sms_check", serde_json::json!({"passed": true})),
            ("totp", serde_json::json!({"passed": true})),
            ("audit", serde_json::json!({"written": true})),
        ] {
            let progress = pipeline
                .resume(
                    &mut state,
                    Event::Pass {
                        node: node.into(),
                        data,
                        identity: None,
                        at: 1,
                    },
                )
                .unwrap();
            if node == "audit" {
                assert_eq!(progress, Progress::Done);
            }
        }
    }

    #[test]
    fn supports_retry_and_deny() {
        let pipeline = Pipeline::new(vec![Node::verify("captcha", "slider")]);
        let (mut state, _) = pipeline.start(Context::default()).unwrap();
        assert!(matches!(
            pipeline
                .resume(
                    &mut state,
                    Event::Fail {
                        node: "captcha".into(),
                        reason: "wrong".into(),
                        retry: true,
                    },
                )
                .unwrap(),
            Progress::Retry { .. }
        ));
        assert!(matches!(
            pipeline
                .resume(
                    &mut state,
                    Event::Fail {
                        node: "captcha".into(),
                        reason: "blocked".into(),
                        retry: false,
                    },
                )
                .unwrap(),
            Progress::Deny { .. }
        ));
    }

    #[test]
    fn rejects_identity_mixing_and_duplicate_node_ids() {
        let duplicate = Pipeline::new(vec![
            Node::input("same", vec![]),
            Node::verify("same", "password"),
        ]);
        assert!(duplicate.start(Context::default()).is_err());

        let pipeline = Pipeline::new(vec![Node::verify("password", "password")]);
        let (mut state, _) = pipeline
            .start(Context {
                identity: Some(Identity::new("local", "1")),
                ..Context::default()
            })
            .unwrap();
        let progress = pipeline
            .resume(
                &mut state,
                Event::Pass {
                    node: "password".into(),
                    data: Value::Null,
                    identity: Some(Identity::new("local", "2")),
                    at: 1,
                },
            )
            .unwrap();
        assert!(matches!(progress, Progress::Deny { .. }));
    }
}
