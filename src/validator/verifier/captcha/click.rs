use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetPoint {
    pub char: char,
    pub x: u32,
    pub y: u32,
}

pub struct ClickCaptcha;

impl ClickCaptcha {
    pub const WIDTH: u32 = 320;
    pub const HEIGHT: u32 = 160;
    pub const HIT_RADIUS: f64 = 26.0; // 点击允许命中半径 (像素)

    const WORDS: &'static [char] = &[
        '星', '海', '蓝', '天', '云', '山', '风', '月', '光', '火', '晨', '曦',
    ];

    /// 生成文字点选验证码 (返回: 目标序列字符及坐标JSON, 提示文字, 背景图Base64)
    pub fn generate() -> (Vec<TargetPoint>, String, String) {
        let mut selected_indices = Vec::new();
        while selected_indices.len() < 3 {
            let idx = (OsRng.next_u32() as usize) % Self::WORDS.len();
            if !selected_indices.contains(&idx) {
                selected_indices.push(idx);
            }
        }

        let targets: Vec<char> = selected_indices.iter().map(|&i| Self::WORDS[i]).collect();
        let prompt = format!(
            "请依次点击：{}",
            targets
                .iter()
                .map(|c| format!("「{c}」"))
                .collect::<Vec<_>>()
                .join(" ")
        );

        // 分配分散坐标
        let mut points = Vec::new();
        let mut char_svgs = Vec::new();

        let colors = ["#1E293B", "#334155", "#0F172A", "#475569"];

        for (i, &ch) in targets.iter().enumerate() {
            let x = 40 + (i as u32) * 85 + (OsRng.next_u32() % 25);
            let y = 50 + (OsRng.next_u32() % 65);
            let rot = ((OsRng.next_u32() % 40) as i32) - 20;
            let color = colors[(OsRng.next_u32() as usize) % colors.len()];

            points.push(TargetPoint { char: ch, x, y });
            char_svgs.push(format!(
                r##"<text x="{x}" y="{y}" font-family="PingFang SC, Microsoft YaHei, sans-serif" font-weight="bold" font-size="28" fill="{color}" transform="rotate({rot} {x} {y})">{ch}</text>"##
            ));
        }

        let svg = format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
                <rect width="100%" height="100%" fill="#F8FAFC" rx="8" stroke="#E2E8F0" stroke-width="1"/>
                <!-- 干扰纹理 -->
                <circle cx="50" cy="50" r="30" fill="#E2E8F0" opacity="0.6"/>
                <circle cx="280" cy="120" r="45" fill="#E2E8F0" opacity="0.4"/>
                {chars}
            </svg>"##,
            w = Self::WIDTH,
            h = Self::HEIGHT,
            chars = char_svgs.join("")
        );

        let data_uri = format!(
            "data:image/svg+xml;base64,{}",
            STANDARD.encode(svg.as_bytes())
        );
        (points, prompt, data_uri)
    }

    /// 校验用户依次点击的点序列是否命中
    pub fn verify(targets: &[TargetPoint], clicks: &[(i32, i32)]) -> bool {
        if targets.len() != clicks.len() {
            return false;
        }

        for (target, click) in targets.iter().zip(clicks.iter()) {
            let dx = (target.x as f64) - (click.0 as f64);
            let dy = (target.y as f64) - (click.1 as f64);
            let dist = (dx * dx + dy * dy).sqrt();
            if dist > Self::HIT_RADIUS {
                return false;
            }
        }

        true
    }
}
