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
    pub(super) async fn verify(
        &self,
        node: &Node,
        context: &Context,
        kind: &str,
    ) -> Result<Output> {
        let data = node_data(context, node)?;
        let guard = self.allow(node, context, data).await?;
        if kind == "captcha" || kind.starts_with("captcha.") {
            return self
                .finish(guard, async {
                    let req: CaptchaVerifyReq = serde_json::from_value(data.clone())
                        .map_err(|e| Error::CaptchaFailed(e.to_string()))?;
                    self.captcha_verify.verify(&self.secrets, &req).await?;
                    let token = self
                        .captcha_issue
                        .token(&self.secrets, &req.id, self.code_ttl)
                        .await?;
                    Ok(pass(json!({ "token": token })))
                })
                .await;
        }
        if kind == "sms" || kind == "code.sms" {
            let phone = string(data, "phone")?;
            let code = string(data, "code")?;
            let scene = data
                .get("scene")
                .and_then(Value::as_str)
                .unwrap_or(SmsCode::SCENE);
            return self
                .finish(guard, async {
                    let user = SmsCode::authenticate_scene(
                        &self.users,
                        &self.secrets,
                        &phone,
                        &code,
                        scene,
                    )
                    .await?;
                    Ok(identity_pass(user))
                })
                .await;
        }
        if kind == "email" || kind == "code.email" {
            let email = string(data, "email")?;
            let code = string(data, "code")?;
            let scene = data
                .get("scene")
                .and_then(Value::as_str)
                .unwrap_or(EmailCode::SCENE);
            return self
                .finish(guard, async {
                    let user = EmailCode::authenticate_scene(
                        &self.users,
                        &self.secrets,
                        &email,
                        &code,
                        scene,
                    )
                    .await?;
                    Ok(identity_pass(user))
                })
                .await;
        }
        if kind == "totp" {
            let account = string(data, "account")?;
            let code = string(data, "code")?;
            let timestamp = data
                .get("timestamp")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| chrono::Utc::now().timestamp() as u64);
            return self
                .finish(guard, async {
                    let user = TotpCode::authenticate(
                        &self.users,
                        &self.factors,
                        &account,
                        &code,
                        timestamp,
                    )
                    .await?;
                    Ok(identity_pass(user))
                })
                .await;
        }
        if kind == "password"
            || kind == "account.password"
            || kind == "email.password"
            || kind == "phone.password"
        {
            let password = string(data, "password")?;
            return self
                .finish(guard, async {
                    let user = if kind == "email.password" {
                        EmailPassword::authenticate(&self.users, &string(data, "email")?, &password)
                            .await?
                    } else if kind == "phone.password" {
                        PhonePassword::authenticate(&self.users, &string(data, "phone")?, &password)
                            .await?
                    } else {
                        Account::authenticate(&self.users, &string(data, "account")?, &password)
                            .await?
                    };
                    Ok(identity_pass(user))
                })
                .await;
        }
        if kind == "passkey" || kind == "webauthn" {
            return self.finish(guard, self.verify_passkey(context, data)).await;
        }
        if kind == "device" {
            return self.finish(guard, self.verify_device(context, data)).await;
        }
        Err(Error::Unsupported(format!(
            "Unsupported pipeline verifier: {kind}"
        )))
    }
}
