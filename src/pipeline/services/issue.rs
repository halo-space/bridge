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
    pub(super) async fn issue(&self, node: &Node, context: &Context, kind: &str) -> Result<Output> {
        let input = node_data(context, node).unwrap_or(&Value::Null);
        if kind == "device" {
            let data = input;
            let device_id = string(data, "device_id")?;
            let device = self
                .devices
                .find(&device_id)
                .await?
                .ok_or_else(|| Error::AuthFailed("Device not found".into()))?;
            let nonce = device.issue_nonce(&self.secrets, self.code_ttl).await?;
            return Ok(pass(json!({
                "device_id": device_id,
                "nonce": nonce,
                "expires_in": self.code_ttl,
            })));
        }
        if kind == "captcha" || kind.starts_with("captcha.") {
            self.allow(node, context, input).await?;
            let captcha_type = captcha_type(kind)?;
            let challenge = self
                .captcha_issue
                .issue(&self.secrets, captcha_type)
                .await?;
            return Ok(pass(json!({ "challenge": challenge })));
        }
        if matches!(kind, "passkey" | "webauthn") {
            return self.issue_passkey(node, context).await;
        }

        let channel = channel(kind)?;
        let target = target(context, node, channel)?;
        self.allow(node, context, input).await?;
        let scene = node
            .args
            .get("scene")
            .and_then(Value::as_str)
            .filter(|scene| !scene.trim().is_empty())
            .unwrap_or(if channel == "email" {
                "login_email"
            } else {
                "login_sms"
            });
        let key = Code::key(scene, &target);
        Code::issue(&self.secrets, &key, self.code_ttl, self.code_digits).await?;
        Ok(pass(json!({
            "channel": channel,
            "target": target,
            "code_key": key,
            "scene": scene,
            "ttl": self.code_ttl,
        })))
    }
}
