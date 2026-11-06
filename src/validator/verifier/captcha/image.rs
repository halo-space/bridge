use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand_core::{OsRng, RngCore};

pub struct ImageCaptcha;

impl ImageCaptcha {
    const WIDTH: u32 = 120;
    const HEIGHT: u32 = 40;
    const CHARS: &'static [u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

    /// 生成随机字符及高辨识度干扰 SVG 图形验证码
    pub fn generate(len: usize) -> (String, String) {
        let mut answer = String::with_capacity(len);
        let mut char_elements = Vec::with_capacity(len);

        let colors = [
            "#4F46E5", "#0891B2", "#059669", "#D97706", "#DC2626", "#7C3AED",
        ];

        for i in 0..len {
            let idx = (OsRng.next_u32() as usize) % Self::CHARS.len();
            let ch = Self::CHARS[idx] as char;
            answer.push(ch);

            let x = 16 + (i as u32) * 22;
            let y = 26 + (OsRng.next_u32() % 6);
            let rot = ((OsRng.next_u32() % 30) as i32) - 15;
            let color = colors[(OsRng.next_u32() as usize) % colors.len()];

            char_elements.push(format!(
                r##"<text x="{x}" y="{y}" font-family="Arial, sans-serif" font-weight="bold" font-size="22" fill="{color}" transform="rotate({rot} {x} {y})">{ch}</text>"##
            ));
        }

        // 随机干扰线
        let mut noise_lines = Vec::new();
        for _ in 0..3 {
            let x1 = OsRng.next_u32() % Self::WIDTH;
            let y1 = OsRng.next_u32() % Self::HEIGHT;
            let x2 = OsRng.next_u32() % Self::WIDTH;
            let y2 = OsRng.next_u32() % Self::HEIGHT;
            let stroke = colors[(OsRng.next_u32() as usize) % colors.len()];
            noise_lines.push(format!(
                r##"<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}" stroke-width="1.2" opacity="0.45" />"##
            ));
        }

        let svg = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}"><rect width="100%" height="100%" fill="#F1F5F9" rx="6"/>{lines}{chars}</svg>"##,
            w = Self::WIDTH,
            h = Self::HEIGHT,
            lines = noise_lines.join(""),
            chars = char_elements.join("")
        );

        let data_uri = format!(
            "data:image/svg+xml;base64,{}",
            STANDARD.encode(svg.as_bytes())
        );
        (answer, data_uri)
    }

    /// 校验字符（忽略大小写）
    pub fn verify(expected: &str, input: &str) -> bool {
        expected.trim().eq_ignore_ascii_case(input.trim())
    }
}
