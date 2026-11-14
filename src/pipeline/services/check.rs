use super::*;
use crate::risk::{RiskContext, RiskDecision, UserHistory};

impl<S, U, F, P, E, D, L> Services<S, U, F, P, E, D, L>
where
    S: Secrets,
    U: Users,
    F: Factors,
    P: Passkeys,
    E: Events,
    D: Devices,
    L: Limits,
{
    pub(super) async fn check(&self, node: &Node, context: &Context, kind: &str) -> Result<Output> {
        if kind == "risk" || kind == "risk.score" {
            let engine = self
                .risk
                .as_ref()
                .ok_or_else(|| Error::Unsupported("Risk engine is not configured".into()))?;
            let data = node_data(context, node)?;
            let input: RiskInput = serde_json::from_value(data.clone())
                .map_err(|error| Error::AuthFailed(format!("Invalid risk input: {error}")))?;
            let assessment = engine.evaluate(&input.context, &input.history);
            let routes = match assessment.decision {
                RiskDecision::Allow => vec!["allow".into()],
                RiskDecision::RequireMfa => vec!["mfa".into()],
                RiskDecision::Block => vec!["block".into()],
            };
            return Ok(Output::Pass {
                routes,
                data: serde_json::to_value(assessment)
                    .map_err(|error| Error::Internal(error.to_string()))?,
                identity: context.identity.clone(),
                at: chrono::Utc::now().timestamp(),
            });
        }
        if kind == "identity" && context.identity.is_some() {
            return Ok(pass(Value::Null));
        }
        if kind == "present" {
            let data = context.data.get(&node.id);
            for field in &node.fields {
                let present = data
                    .and_then(|value| value.get(field))
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty());
                if !present {
                    return Ok(Output::Fail {
                        reason: format!("Missing field: {field}"),
                        retry: false,
                    });
                }
            }
            return Ok(pass(Value::Null));
        }
        Err(Error::Unsupported(format!(
            "Unsupported pipeline check: {kind}"
        )))
    }
}

#[derive(Debug, serde::Deserialize)]
struct RiskInput {
    context: RiskContext,
    history: UserHistory,
}
