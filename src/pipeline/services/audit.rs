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
    pub(super) async fn audit(&self, context: &Context, kind: &str) -> Result<Output> {
        let event_type = match kind {
            "audit" | "auth.success" | "auth_success" => AuditEventType::AuthSuccess,
            "auth.failed" | "auth_failed" => AuditEventType::AuthFailed,
            "mfa.challenge" | "mfa_challenged" => AuditEventType::MfaChallenged,
            "mfa.passed" | "mfa_passed" => AuditEventType::MfaPassed,
            "mfa.failed" | "mfa_failed" => AuditEventType::MfaFailed,
            "passkey.success" | "passkey_auth_success" => AuditEventType::PasskeyAuthSuccess,
            "passkey.failed" | "passkey_auth_failed" => AuditEventType::PasskeyAuthFailed,
            _ => {
                return Err(Error::Unsupported(format!(
                    "Unsupported pipeline audit: {kind}"
                )));
            }
        };
        let event = AuditEvent::new(
            event_type,
            find_string(context, "client_ip").unwrap_or_default(),
            AuditOutcome::Success,
        )
        .with_metadata(json!({ "pipeline": true }));
        self.events.record_event(&event).await?;
        Ok(pass(json!({ "recorded": true, "event_id": event.id })))
    }
}
