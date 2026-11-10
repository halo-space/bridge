use super::*;

impl<S, U, F, P, E, D> Services<S, U, F, P, E, D>
where
    S: Secrets,
    U: Users,
    F: Factors,
    P: Passkeys,
    E: Events,
    D: Devices,
{
    pub(super) async fn check(&self, node: &Node, context: &Context, kind: &str) -> Result<Output> {
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
