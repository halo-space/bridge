use super::*;

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
    pub(super) async fn issue_passkey(&self, node: &Node, context: &Context) -> Result<Output> {
        let passkey = self
            .passkey_issue
            .as_ref()
            .ok_or_else(|| Error::WebAuthnError("Pipeline Passkey issuer is missing".into()))?;
        let data = node_data(context, node)?;
        if data.get("name").is_some() && data.get("display_name").is_some() {
            let subject = data
                .get("subject")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::AuthFailed("Missing field: subject".into()))?;
            let start = passkey.issue(
                subject,
                string(data, "name")?.as_str(),
                string(data, "display_name")?.as_str(),
            )?;
            return Ok(pass(json!({
                "mode": "register",
                "options": start.options,
                "state": start.state,
            })));
        }
        let subject = context
            .identity
            .as_ref()
            .ok_or(Error::UserNotFound)?
            .subject
            .clone();
        let passkeys = self.passkeys.list(&subject).await?;
        let start = passkey.request(&passkeys)?;
        Ok(pass(json!({
            "mode": "request",
            "options": start.options,
            "state": start.state,
        })))
    }
}
