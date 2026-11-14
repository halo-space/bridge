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
    pub(super) async fn audit(&self, context: &Context, kind: &str) -> Result<Output> {
        let event_type = match kind {
            "audit" | "auth.success" => AuditEventType::AuthSuccess,
            "auth.failed" => AuditEventType::AuthFailed,
            "mfa.challenge" => AuditEventType::MfaChallenged,
            "mfa.passed" => AuditEventType::MfaPassed,
            "mfa.failed" => AuditEventType::MfaFailed,
            "passkey.success" => AuditEventType::PasskeyAuthSuccess,
            "passkey.failed" => AuditEventType::PasskeyAuthFailed,
            _ => {
                return Err(Error::Unsupported(format!(
                    "Unsupported pipeline audit: {kind}"
                )));
            }
        };
        let mut event = AuditEvent::new(
            event_type,
            event_string(context, "client_ip").unwrap_or_default(),
            AuditOutcome::Success,
        )
        .with_metadata(json!({ "pipeline": true }));
        if let Some(identity) = context.identity.clone() {
            event = event.with_identity(identity);
        }
        self.events.record_event(&event).await?;
        Ok(pass(json!({ "recorded": true, "event_id": event.id })))
    }
}
