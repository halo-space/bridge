/// 旋转验证码答案校验。
pub struct Rotate;

impl Rotate {
    pub const TOLERANCE: i32 = 8;

    /// 校验旋转角度是否对齐。
    pub fn verify(target_deg: u32, submitted_deg: i32) -> bool {
        let diff = ((target_deg as i32 - submitted_deg).abs()) % 360;
        let min_diff = diff.min(360 - diff);
        min_diff <= Self::TOLERANCE
    }
}
