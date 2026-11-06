use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand_core::{OsRng, RngCore};

pub struct RotateCaptcha;

impl RotateCaptcha {
    pub const SIZE: u32 = 180;
    pub const TOLERANCE: i32 = 8; // 允许误差 ±8 度

    /// 生成随机角度旋转验证码 (返回: 目标还原角度, 旋转后的图片Base64)
    pub fn generate() -> (u32, String) {
        // 随机旋转 45 ~ 315 度
        let target_deg = 45 + (OsRng.next_u32() % 270);

        let svg = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{s}" height="{s}" viewBox="0 0 {s} {s}">
                <defs>
                    <linearGradient id="rotGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="#4F46E5"/>
                        <stop offset="100%" stop-color="#EC4899"/>
                    </linearGradient>
                </defs>
                <g transform="rotate({deg} {half} {half})">
                    <circle cx="{half}" cy="{half}" r="80" fill="url(#rotGrad)"/>
                    <polygon points="{half},25 {p1},125 {p2},125" fill="#FFFFFF" opacity="0.9"/>
                    <circle cx="{half}" cy="{half}" r="22" fill="#1E1B4B"/>
                </g>
            </svg>"##,
            s = Self::SIZE,
            half = Self::SIZE / 2,
            deg = target_deg,
            p1 = (Self::SIZE / 2) - 35,
            p2 = (Self::SIZE / 2) + 35
        );

        let data_uri = format!(
            "data:image/svg+xml;base64,{}",
            STANDARD.encode(svg.as_bytes())
        );
        (target_deg, data_uri)
    }

    /// 校验旋转角度是否对齐归零
    pub fn verify(target_deg: u32, submitted_deg: i32) -> bool {
        let diff = ((target_deg as i32 - submitted_deg).abs()) % 360;
        let min_diff = diff.min(360 - diff);
        min_diff <= Self::TOLERANCE
    }
}
