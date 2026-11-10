use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptchaType {
    Image,
    Slider,
    Rotate,
    Click,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetPoint {
    pub char: char,
    pub x: u32,
    pub y: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaChallenge {
    pub id: String,
    pub captcha_type: CaptchaType,
    pub background: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y_offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaVerifyReq {
    pub id: String,
    pub captcha_type: CaptchaType,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub offset_x: Option<i32>,
    #[serde(default)]
    pub angle: Option<i32>,
    #[serde(default)]
    pub points: Option<Vec<(i32, i32)>>,
}
