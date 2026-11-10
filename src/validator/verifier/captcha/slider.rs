/// 滑块验证码答案校验。
pub struct Slider;

impl Slider {
    pub const TOLERANCE: i32 = 5;

    /// 校验滑块拖动偏移量。
    pub fn verify(target_x: u32, submitted_x: i32) -> bool {
        let diff = (target_x as i32 - submitted_x).abs();
        diff <= Self::TOLERANCE
    }
}
