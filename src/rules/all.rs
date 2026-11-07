use super::{Reauth, lockout, password};

/// 认证规则集合。
#[derive(Debug, Clone)]
pub struct Rules {
    pub password: password::Policy,
    pub lockout: lockout::Policy,
    pub reauth_secs: i64,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            password: password::Policy::default(),
            lockout: lockout::Policy::default(),
            reauth_secs: 900,
        }
    }
}

impl Rules {
    pub fn reauth(&self, at: i64) -> bool {
        Reauth::valid(at, self.reauth_secs)
    }
}
