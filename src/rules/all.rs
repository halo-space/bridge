use super::{LockoutPolicy, PasswordPolicy, Reauth};

/// 认证规则集合。
#[derive(Debug, Clone)]
pub struct Rules {
    pub password: PasswordPolicy,
    pub lockout: LockoutPolicy,
    pub reauth_secs: i64,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            password: PasswordPolicy::default(),
            lockout: LockoutPolicy::default(),
            reauth_secs: 900,
        }
    }
}

impl Rules {
    pub fn reauth(&self, at: i64) -> bool {
        Reauth::valid(at, self.reauth_secs)
    }
}
