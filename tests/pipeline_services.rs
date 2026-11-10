use halo::bridge::{
    CaptchaType, CaptchaVerifyReq, Context, Device, Devices, Event, Factors, Node, Notify,
    Passkeys, Pipeline, Progress, Secrets, Services, Users,
};
use halo::bridge::{Error, Events, TotpBinding, User};
use halo::bridge::{SmsConfig, SmsSender, SmtpConfig, SmtpSender};
use halo::factor::passkey::Passkey;
use halo::pkg::totp::Totp;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Mem {
    values: Arc<Mutex<HashMap<String, String>>>,
}

impl Mem {
    fn get_sync(&self, key: &str) -> Option<String> {
        self.values.lock().unwrap().get(key).cloned()
    }
}

impl Secrets for Mem {
    async fn set(&self, key: &str, value: &str, _ttl: u64) -> halo::Result<()> {
        self.values
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn get(&self, key: &str) -> halo::Result<Option<String>> {
        Ok(self.get_sync(key))
    }

    async fn take(&self, key: &str) -> halo::Result<Option<String>> {
        Ok(self.values.lock().unwrap().remove(key))
    }

    async fn take_if(&self, key: &str, expected: &str) -> halo::Result<bool> {
        let mut values = self.values.lock().unwrap();
        if values.get(key).map(String::as_str) != Some(expected) {
            return Ok(false);
        }
        values.remove(key);
        Ok(true)
    }

    async fn del(&self, key: &str) -> halo::Result<()> {
        self.values.lock().unwrap().remove(key);
        Ok(())
    }
}

#[derive(Clone)]
struct UserMem {
    user: User,
}

impl Users for UserMem {
    async fn find_by_username(&self, username: &str) -> halo::Result<Option<User>> {
        Ok((self.user.username == username).then(|| self.user.clone()))
    }

    async fn find_by_phone(&self, phone: &str) -> halo::Result<Option<User>> {
        Ok((self.user.phone.as_deref() == Some(phone)).then(|| self.user.clone()))
    }

    async fn find_by_email(&self, email: &str) -> halo::Result<Option<User>> {
        Ok((self.user.email.as_deref() == Some(email)).then(|| self.user.clone()))
    }

    async fn find_by_id(&self, id: i64) -> halo::Result<Option<User>> {
        Ok((self.user.id == id).then(|| self.user.clone()))
    }
}

#[derive(Clone)]
struct FactorMem {
    binding: TotpBinding,
}

impl Factors for FactorMem {
    async fn find_totp(&self, _user_id: i64) -> halo::Result<Option<TotpBinding>> {
        Ok(Some(self.binding.clone()))
    }
}

#[derive(Clone, Default)]
struct PasskeyMem;

impl Passkeys for PasskeyMem {
    async fn save(&self, _subject: &str, _passkey: Passkey) -> halo::Result<()> {
        Err(Error::Internal("unused in this test".into()))
    }

    async fn find(&self, _credential_id: &str) -> halo::Result<Option<Passkey>> {
        Err(Error::Internal("unused in this test".into()))
    }

    async fn list(&self, _subject: &str) -> halo::Result<Vec<Passkey>> {
        Err(Error::Internal("unused in this test".into()))
    }

    async fn update(
        &self,
        _credential_id: &str,
        _old_count: u32,
        _passkey: Passkey,
    ) -> halo::Result<bool> {
        Err(Error::Internal("unused in this test".into()))
    }
}

#[derive(Clone, Default)]
struct EventMem {
    count: Arc<Mutex<u32>>,
}

impl Events for EventMem {
    async fn record_event(&self, _event: &halo::bridge::AuditEvent) -> halo::Result<()> {
        *self.count.lock().unwrap() += 1;
        Ok(())
    }
}

#[derive(Clone, Default)]
struct DeviceMem {
    device: Arc<Mutex<Option<Device>>>,
}

impl Devices for DeviceMem {
    async fn save(&self, device: Device) -> halo::Result<()> {
        *self.device.lock().unwrap() = Some(device);
        Ok(())
    }

    async fn find(&self, device_id: &str) -> halo::Result<Option<Device>> {
        Ok(self
            .device
            .lock()
            .unwrap()
            .clone()
            .filter(|device| device.id == device_id))
    }

    async fn update(&self, device: Device) -> halo::Result<bool> {
        *self.device.lock().unwrap() = Some(device);
        Ok(true)
    }

    async fn revoke(&self, device_id: &str) -> halo::Result<bool> {
        let mut stored = self.device.lock().unwrap();
        if let Some(device) = stored.as_mut()
            && device.id == device_id
        {
            device.revoke();
            return Ok(true);
        }
        Ok(false)
    }
}

fn services(
    secrets: Mem,
    user: User,
    factors: FactorMem,
    events: EventMem,
) -> Services<Mem, UserMem, FactorMem, PasskeyMem, EventMem, DeviceMem> {
    let notify = Notify::new(
        SmtpSender::new(SmtpConfig::default()),
        SmsSender::new(SmsConfig::default()),
    );
    Services::new(
        secrets,
        UserMem { user },
        factors,
        PasskeyMem,
        events,
        DeviceMem::default(),
        notify,
    )
}

fn user() -> User {
    User {
        id: 7,
        username: "alice".into(),
        email: Some("alice@example.com".into()),
        phone: Some("13800138000".into()),
        password_hash: None,
        password_algorithm: None,
        is_active: true,
    }
}

#[tokio::test]
async fn pipeline_runs_captcha_sms_and_audit_without_node_dispatch_in_app() {
    let secrets = Mem::default();
    let events = EventMem::default();
    let events_counter = events.count.clone();
    let services = services(
        secrets.clone(),
        user(),
        FactorMem {
            binding: TotpBinding {
                secret: Totp::generate_secret(),
                enabled: true,
            },
        },
        events,
    );
    let pipeline = Pipeline::new(
        "phone",
        vec![
            Node::input("phone", vec!["phone".into()]).edge(None::<String>, "captcha_issue"),
            Node::issue("captcha_issue", "captcha.slider").edge(None::<String>, "captcha"),
            Node::input("captcha", vec!["captcha".into()]).edge(None::<String>, "captcha_verify"),
            Node::verify("captcha_verify", "captcha.slider")
                .edge(None::<String>, "issue")
                .limit(3),
            Node::issue("issue", "sms")
                .args(serde_json::json!({ "scene": "signin" }))
                .edge(None::<String>, "send"),
            Node::effect("send", "sms.send").edge(None::<String>, "code"),
            Node::input("code", vec!["code".into()]).edge(None::<String>, "verify"),
            Node::verify("verify", "sms").edge(None::<String>, "audit"),
            Node::effect("audit", "audit"),
        ],
    );

    let (mut run, progress) = pipeline
        .start(Context {
            ..Context::default()
        })
        .unwrap();
    assert!(matches!(progress, Progress::Need { ref node, .. } if node == "phone"));

    let progress = pipeline
        .resume(
            &mut run,
            Event::Input {
                node: "phone".into(),
                data: serde_json::json!({ "phone": "13800138000" }),
                at: 1,
            },
        )
        .unwrap();
    assert!(matches!(progress, Progress::Need { ref node, .. } if node == "captcha_issue"));
    let progress = pipeline.run(&mut run, &services).await.unwrap();
    assert!(matches!(progress, Progress::Need { ref node, .. } if node == "captcha"));

    let challenge = run.context.data["captcha_issue"]["challenge"].clone();
    let captcha_id = challenge["id"].as_str().unwrap().to_string();
    let target = secrets
        .get_sync(&format!("cap:{captcha_id}"))
        .unwrap()
        .parse::<i32>()
        .unwrap();

    let progress = pipeline
        .resume(
            &mut run,
            Event::Input {
                node: "captcha".into(),
                data: serde_json::to_value(CaptchaVerifyReq {
                    id: captcha_id,
                    captcha_type: CaptchaType::Slider,
                    text: None,
                    offset_x: Some(target),
                    angle: None,
                    points: None,
                })
                .unwrap(),
                at: 2,
            },
        )
        .unwrap();
    assert!(matches!(progress, Progress::Need { ref node, .. } if node == "captcha_verify"));
    let progress = pipeline.run(&mut run, &services).await.unwrap();
    assert!(matches!(progress, Progress::Need { ref node, .. } if node == "code"));

    let code = secrets
        .get_sync("code:signin:13800138000")
        .expect("pipeline issued a code");
    let progress = pipeline
        .resume(
            &mut run,
            Event::Input {
                node: "code".into(),
                data: serde_json::json!({ "phone": "13800138000", "code": code }),
                at: 3,
            },
        )
        .unwrap();
    assert!(matches!(progress, Progress::Need { ref node, .. } if node == "verify"));
    let progress = pipeline.run(&mut run, &services).await.unwrap();
    assert_eq!(progress, Progress::Done);
    assert_eq!(*events_counter.lock().unwrap(), 1);
    let identity = run.context.identity.expect("identity");
    assert_eq!(identity.provider, "local");
    assert_eq!(identity.subject, "7");
    assert_eq!(identity.name.as_deref(), Some("alice"));
    assert_eq!(identity.email.as_deref(), Some("alice@example.com"));
    assert_eq!(identity.phone.as_deref(), Some("13800138000"));
}

#[tokio::test]
async fn pipeline_runs_totp_and_password_verifiers() {
    let secret = Totp::generate_secret();
    let user = user();
    let factors = FactorMem {
        binding: TotpBinding {
            secret: secret.clone(),
            enabled: true,
        },
    };
    let services = services(Mem::default(), user, factors, EventMem::default());
    let now = chrono::Utc::now().timestamp() as u64;
    let code = Totp::generate_code(&secret, now).unwrap();
    let pipeline = Pipeline::new("totp", vec![Node::verify("totp", "totp")]);
    let (mut run, _) = pipeline
        .start(Context {
            ..Context::default()
        })
        .unwrap();
    pipeline
        .resume(
            &mut run,
            Event::Input {
                node: "totp".into(),
                data: serde_json::json!({ "account": "alice", "code": code, "timestamp": now }),
                at: 1,
            },
        )
        .unwrap();
    assert_eq!(
        pipeline.run(&mut run, &services).await.unwrap(),
        Progress::Done
    );
}
