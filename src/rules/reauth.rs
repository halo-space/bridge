use chrono::Utc;

/// 重新认证有效期规则。
pub struct Reauth;

impl Reauth {
    pub fn valid(at: i64, ttl: i64) -> bool {
        if at <= 0 || ttl <= 0 {
            return false;
        }
        Utc::now().timestamp().saturating_sub(at) <= ttl
    }
}
