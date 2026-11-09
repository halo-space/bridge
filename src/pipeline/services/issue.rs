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
    pub(super) async fn issue(&self, node: &Node, context: &Context, kind: &str) -> Result<Output> {
        if kind == "device" {
            let data = node_data(context, node)?;
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
            let captcha_type = captcha_type(kind)?;
            let challenge = self
                .captcha_issuer
                .issue(&self.secrets, captcha_type)
                .await?;
            return Ok(pass(json!({ "challenge": challenge })));
        }
        if matches!(kind, "passkey" | "webauthn") {
            return self.issue_passkey(context).await;
        }

        let channel = channel(kind)?;
        let target = target(context, node, channel)?;
        let scene = if channel == "email" {
            "login_email"
        } else {
            "login_sms"
        };
        let key = CodeIssuer::key(scene, &target);
        CodeIssuer::issue(&self.secrets, &key, self.code_ttl, self.code_digits).await?;
        Ok(pass(json!({
            "channel": channel,
            "target": target,
            "key": key,
            "scene": scene,
            "ttl": self.code_ttl,
        })))
    }
}
