use super::types::TargetPoint;

/// 点选验证码答案校验。
pub struct Click;

impl Click {
    pub const HIT_RADIUS: f64 = 26.0;

    /// 校验用户依次点击的点序列是否命中。
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
