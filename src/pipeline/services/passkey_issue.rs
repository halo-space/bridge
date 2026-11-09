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
    pub(super) async fn issue_passkey(&self, context: &Context) -> Result<Output> {
        let webauthn = self
            .webauthn
            .as_ref()
            .ok_or_else(|| Error::WebAuthnError("Pipeline WebAuthn service is missing".into()))?;
        if let Some(data) = context.data.values().rev().find(|value| {
            value.get("user_id").is_some()
                && value.get("name").is_some()
                && value.get("display_name").is_some()
        }) {
            let start = webauthn.issue(
                string(data, "user_id")?.as_str(),
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
        let start = webauthn.request(&passkeys)?;
        Ok(pass(json!({
            "mode": "request",
            "options": start.options,
            "state": start.state,
        })))
    }
}
