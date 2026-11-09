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
    pub(super) async fn send(&self, node: &Node, context: &Context, kind: &str) -> Result<Output> {
        let data = node_data(context, node)?;
        let channel = if kind.contains("email") {
            NotifyChannel::Email
        } else if kind.contains("sms") {
            NotifyChannel::Sms
        } else {
            match data.get("channel").and_then(Value::as_str) {
                Some("email") => NotifyChannel::Email,
                Some("sms") => NotifyChannel::Sms,
                _ => return Err(Error::Internal("Missing notification channel".into())),
            }
        };
        let target = data
            .get("target")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Internal("Missing code target".into()))?;
        let key = data
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Internal("Missing code key".into()))?;
        let code = self
            .secrets
            .get(key)
            .await?
            .ok_or(Error::VerificationCodeExpired)?;
        let scene = data.get("scene").and_then(Value::as_str).unwrap_or("login");
        self.notify
            .send_code(channel, target, &code, scene, self.code_ttl)
            .await?;
        Ok(pass(json!({
            "sent": true,
            "channel": match channel {
                NotifyChannel::Email => "email",
                NotifyChannel::Sms => "sms",
            },
            "target": target,
        })))
    }
}
