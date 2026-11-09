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
    pub(super) async fn verify_device(&self, context: &Context, data: &Value) -> Result<Output> {
        let device_id = string(data, "device_id")?;
        let proof = DeviceProof {
            device_id: device_id.clone(),
            nonce: string(data, "nonce")?,
            at: data
                .get("at")
                .and_then(Value::as_i64)
                .ok_or_else(|| Error::AuthFailed("Missing field: at".into()))?,
            signature: string(data, "signature")?,
        };
        let now = data
            .get("now")
            .and_then(Value::as_i64)
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        let window = data.get("window").and_then(Value::as_i64).unwrap_or(120);
        let device = self
            .devices
            .find(&device_id)
            .await?
            .ok_or_else(|| Error::AuthFailed("Device not found".into()))?;
        if let Some(identity) = &context.identity
            && identity.subject != device.subject
        {
            return Err(Error::AuthFailed("Device identity mismatch".into()));
        }
        device.verify(&proof, now, window)?;
        if self
            .secrets
            .take(&device.nonce_key(&proof.nonce))
            .await?
            .is_none()
        {
            return Err(Error::AuthFailed(
                "Device proof is expired or already used".into(),
            ));
        }
        let subject = device.subject.clone();
        let mut used = device;
        used.last_used_at = Some(proof.at);
        if !self.devices.update(used).await? {
            return Err(Error::StoreError("Device update failed".into()));
        }
        let identity = context
            .identity
            .clone()
            .or_else(|| Some(crate::types::Identity::new("device", subject)));
        Ok(Output::Pass {
            routes: Vec::new(),
            data: json!({ "verified": true, "device_id": device_id }),
            identity,
            at: chrono::Utc::now().timestamp(),
        })
    }
}
