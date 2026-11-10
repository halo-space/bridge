use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand_core::{OsRng, RngCore};

/// 旋转验证码签发。
pub struct Rotate;

impl Rotate {
    pub const SIZE: u32 = 180;

    pub fn issue() -> (u32, String) {
        let target = 45 + (OsRng.next_u32() % 270);
        let svg = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 {s} {s}"><defs><linearGradient id="rotGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#4F46E5"/><stop offset="100%" stop-color="#EC4899"/></linearGradient></defs><g transform="rotate({deg} {half} {half})"><circle cx="{half}" cy="{half}" r="80" fill="url(#rotGrad)"/><polygon points="{half},25 {p1},125 {p2},125" fill="#FFFFFF" opacity="0.9"/><circle cx="{half}" cy="{half}" r="22" fill="#1E1B4B"/></g></svg>"##,
            s = Self::SIZE,
            half = Self::SIZE / 2,
            deg = target,
            p1 = (Self::SIZE / 2) - 35,
            p2 = (Self::SIZE / 2) + 35
        );
        (
            target,
            format!("data:image/svg+xml;base64,{}", STANDARD.encode(svg)),
        )
    }
}
