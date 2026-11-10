#[cfg(feature = "mail")]
pub mod mail;
#[cfg(all(feature = "mail", feature = "sms"))]
pub mod notify;
#[cfg(feature = "sms")]
pub mod sms;

#[cfg(feature = "mail")]
pub use mail::{SmtpConfig, SmtpSender};
#[cfg(all(feature = "mail", feature = "sms"))]
pub use notify::{Notify, NotifyChannel};
#[cfg(feature = "sms")]
pub use sms::{SmsConfig, SmsSender};
