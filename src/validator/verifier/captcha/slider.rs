use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand_core::{OsRng, RngCore};

pub struct SliderCaptcha;

impl SliderCaptcha {
    pub const BG_WIDTH: u32 = 320;
    pub const BG_HEIGHT: u32 = 160;
    pub const PIECE_SIZE: u32 = 44;
    pub const TOLERANCE: i32 = 5; // 允许误差 ±5 像素

    /// 生成滑块拼图（返回: 目标X坐标, 背景图Base64, 滑块图Base64, Y轴固定偏移）
    pub fn generate() -> (u32, String, String, u32) {
        // 目标 X 在 [70, 260], Y 在 [25, 95]
        let target_x = 70 + (OsRng.next_u32() % (Self::BG_WIDTH - 70 - Self::PIECE_SIZE));
        let target_y = 25 + (OsRng.next_u32() % (Self::BG_HEIGHT - 25 - Self::PIECE_SIZE));

        // 渐变主题底色
        let bg_svg = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
                <defs>
                    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="#3B82F6"/>
                        <stop offset="100%" stop-color="#1E1B4B"/>
                    </linearGradient>
                    <filter id="shadow"><feDropShadow dx="2" dy="2" stdDeviation="3" flood-opacity="0.5"/></filter>
                </defs>
                <rect width="100%" height="100%" fill="url(#bgGrad)" rx="8"/>
                <circle cx="80" cy="40" r="28" fill="#60A5FA" opacity="0.3"/>
                <circle cx="240" cy="110" r="38" fill="#818CF8" opacity="0.25"/>
                <!-- 缺口阴影槽位 -->
                <rect x="{tx}" y="{ty}" width="{ps}" height="{ps}" rx="6" fill="#0F172A" opacity="0.75" stroke="#FFFFFF" stroke-dasharray="3,3" stroke-width="1.5"/>
            </svg>"##,
            w = Self::BG_WIDTH,
            h = Self::BG_HEIGHT,
            tx = target_x,
            ty = target_y,
            ps = Self::PIECE_SIZE
        );

        // 移动拼图切块
        let piece_svg = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{ps}" height="{ps}" viewBox="0 0 {ps} {ps}">
                <defs>
                    <linearGradient id="pieceGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="#60A5FA"/>
                        <stop offset="100%" stop-color="#2563EB"/>
                    </linearGradient>
                </defs>
                <rect width="{ps}" height="{ps}" rx="6" fill="url(#pieceGrad)" stroke="#FFFFFF" stroke-width="2"/>
            </svg>"##,
            ps = Self::PIECE_SIZE
        );

        let bg_data_uri = format!(
            "data:image/svg+xml;base64,{}",
            STANDARD.encode(bg_svg.as_bytes())
        );
        let piece_data_uri = format!(
            "data:image/svg+xml;base64,{}",
            STANDARD.encode(piece_svg.as_bytes())
        );

        (target_x, bg_data_uri, piece_data_uri, target_y)
    }

    /// 校验滑块拖动偏移量
    pub fn verify(target_x: u32, submitted_x: i32) -> bool {
        let diff = (target_x as i32 - submitted_x).abs();
        diff <= Self::TOLERANCE
    }
}
