pub mod captcha;
pub mod magic;
pub mod passcode;
#[cfg(feature = "passkey")]
pub mod passkey;
pub mod recovery;
pub mod totp;

pub use captcha::{CaptchaChallenge, CaptchaType, CaptchaVerifier, CaptchaVerifyReq};
pub use magic::Magic;
pub use passcode::Passcode;
#[cfg(feature = "passkey")]
pub use passkey::{Start, WebAuthn};
pub use recovery::Recovery;
pub use totp::Totp;

pub(crate) fn same(left: &str, right: &str) -> bool {
    let mut diff = left.len() ^ right.len();
    for (a, b) in left.bytes().zip(right.bytes()) {
        diff |= usize::from(a ^ b);
    }
    diff == 0
}
