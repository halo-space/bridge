use halo::bridge::{BoxFuture, Sender, SmsConfig, SmsSender};

struct CompanySms;

impl Sender for CompanySms {
    fn send<'a>(&'a self, phone: &'a str, code: &'a str, ttl_secs: u64) -> BoxFuture<'a> {
        Box::pin(async move {
            println!("company sms: phone={phone}, code={code}, ttl={ttl_secs}s");
            Ok(())
        })
    }
}

#[tokio::main]
async fn main() -> halo::Result<()> {
    let sender = SmsSender::with(
        SmsConfig {
            enabled: true,
            access_key_id: "company".into(),
            access_key_secret: "company".into(),
            ..SmsConfig::default()
        },
        CompanySms,
    );
    sender
        .send_verification_code("13800138000", "123456", 300)
        .await
}
