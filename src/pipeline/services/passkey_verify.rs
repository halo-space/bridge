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
    pub(super) async fn verify_passkey(&self, context: &Context, data: &Value) -> Result<Output> {
        let passkey = self
            .passkey_verify
            .as_ref()
            .ok_or_else(|| Error::WebAuthnError("Pipeline Passkey verifier is missing".into()))?;
        let input = string(data, "input").or_else(|_| string(data, "credential"))?;
        let state = string(data, "state")?;
        let auth = passkey.verify(&input, &state)?;
        let stored = self
            .passkeys
            .find(&auth.credential_id)
            .await?
            .ok_or_else(|| Error::WebAuthnError("Passkey is not registered".into()))?;
        if stored.subject.trim().is_empty() {
            return Err(Error::WebAuthnError("Passkey subject is missing".into()));
        }
        if let Some(identity) = &context.identity
            && identity.subject != stored.subject
        {
            return Err(Error::WebAuthnError("Passkey identity mismatch".into()));
        }
        if !stored.can_update(auth.counter) {
            return Err(Error::WebAuthnError(
                "Passkey counter did not advance".into(),
            ));
        }
        let mut updated = stored.clone();
        updated.sign_count = auth.counter;
        updated.last_used_at = Some(auth.at);
        updated.user_verified = auth.user_verified;
        updated.backup_eligible = auth.backup_eligible;
        updated.backup_state = auth.backup_state;
        if let Some(data) = auth.data {
            updated.data = Some(data);
        }
        if !self
            .passkeys
            .update(&auth.credential_id, stored.sign_count, updated)
            .await?
        {
            return Err(Error::WebAuthnError(
                "Passkey counter update lost race".into(),
            ));
        }
        let identity = context
            .identity
            .clone()
            .or_else(|| Some(crate::types::Identity::new("passkey", stored.subject)));
        Ok(Output::Pass {
            routes: Vec::new(),
            data: json!({
            "verified": true,
            "credential_id": auth.credential_id,
            "counter": auth.counter,
            "user_verified": auth.user_verified,
            }),
            identity,
            at: chrono::Utc::now().timestamp(),
        })
    }
}
