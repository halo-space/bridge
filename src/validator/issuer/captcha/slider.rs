use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand_core::{OsRng, RngCore};

/// 滑块验证码签发。
pub struct Slider;

impl Slider {
    pub const BG_WIDTH: u32 = 320;
    pub const BG_HEIGHT: u32 = 160;
    pub const PIECE_SIZE: u32 = 44;

    pub fn issue() -> (u32, String, String, u32) {
        let target_x = 70 + (OsRng.next_u32() % (Self::BG_WIDTH - 70 - Self::PIECE_SIZE));
        let target_y = 25 + (OsRng.next_u32() % (Self::BG_HEIGHT - 25 - Self::PIECE_SIZE));
        let bg = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}"><defs><linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#3B82F6"/><stop offset="100%" stop-color="#1E1B4B"/></linearGradient></defs><rect width="100%" height="100%" fill="url(#bgGrad)" rx="8"/><circle cx="80" cy="40" r="28" fill="#60A5FA" opacity="0.3"/><circle cx="240" cy="110" r="38" fill="#818CF8" opacity="0.25"/><rect x="{tx}" y="{ty}" width="{ps}" height="{ps}" rx="6" fill="#0F172A" opacity="0.75" stroke="#FFFFFF" stroke-dasharray="3,3" stroke-width="1.5"/></svg>"##,
            w = Self::BG_WIDTH,
            h = Self::BG_HEIGHT,
            tx = target_x,
            ty = target_y,
            ps = Self::PIECE_SIZE
        );
        let piece = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{ps}" height="{ps}" viewBox="0 0 {ps} {ps}"><defs><linearGradient id="pieceGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#60A5FA"/><stop offset="100%" stop-color="#2563EB"/></linearGradient></defs><rect width="{ps}" height="{ps}" rx="6" fill="url(#pieceGrad)" stroke="#FFFFFF" stroke-width="2"/></svg>"##,
            ps = Self::PIECE_SIZE
        );
        (
            target_x,
            format!("data:image/svg+xml;base64,{}", STANDARD.encode(bg)),
            format!("data:image/svg+xml;base64,{}", STANDARD.encode(piece)),
            target_y,
        )
    }
}
