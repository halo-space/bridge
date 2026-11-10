use crate::validator::verifier::captcha::TargetPoint;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand_core::{OsRng, RngCore};

/// 点选验证码签发。
pub struct Click;

impl Click {
    const WIDTH: u32 = 320;
    const HEIGHT: u32 = 160;
    const WORDS: &'static [char] = &[
        '星', '海', '蓝', '天', '云', '山', '风', '月', '光', '火', '晨', '曦',
    ];

    pub fn issue() -> (Vec<TargetPoint>, String, String) {
        let mut indexes = Vec::new();
        while indexes.len() < 3 {
            let index = (OsRng.next_u32() as usize) % Self::WORDS.len();
            if !indexes.contains(&index) {
                indexes.push(index);
            }
        }
        let targets: Vec<char> = indexes.iter().map(|&index| Self::WORDS[index]).collect();
        let prompt = format!(
            "请依次点击：{}",
            targets
                .iter()
                .map(|c| format!("「{c}」"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let colors = ["#1E293B", "#334155", "#0F172A", "#475569"];
        let mut points = Vec::new();
        let mut chars = Vec::new();
        for (i, &ch) in targets.iter().enumerate() {
            let x = 40 + (i as u32) * 85 + (OsRng.next_u32() % 25);
            let y = 50 + (OsRng.next_u32() % 65);
            let rot = ((OsRng.next_u32() % 40) as i32) - 20;
            let color = colors[(OsRng.next_u32() as usize) % colors.len()];
            points.push(TargetPoint { char: ch, x, y });
            chars.push(format!(r##"<text x="{x}" y="{y}" font-family="PingFang SC, Microsoft YaHei, sans-serif" font-weight="bold" font-size="28" fill="{color}" transform="rotate({rot} {x} {y})">{ch}</text>"##));
        }
        let svg = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}"><rect width="100%" height="100%" fill="#F8FAFC" rx="8" stroke="#E2E8F0" stroke-width="1"/><circle cx="50" cy="50" r="30" fill="#E2E8F0" opacity="0.6"/><circle cx="280" cy="120" r="45" fill="#E2E8F0" opacity="0.4"/>{chars}</svg>"##,
            w = Self::WIDTH,
            h = Self::HEIGHT,
            chars = chars.join("")
        );
        (
            points,
            prompt,
            format!("data:image/svg+xml;base64,{}", STANDARD.encode(svg)),
        )
    }
}
