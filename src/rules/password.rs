use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Strength {
    Weak,
    Medium,
    Strong,
}

/// 密码安全策略配置 (对齐 Authing 3.1.1 密码策略)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub min_length: usize,
    pub max_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special_char: bool,
    pub disallow_username: bool,
    pub special_chars: String,
    pub weak_passwords: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_length: 8,
            max_length: 64,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special_char: true,
            disallow_username: true,
            special_chars: "!@#$%^&*()_+-=[]{}|;:,.<>?".to_string(),
            weak_passwords: vec![
                "123456".into(),
                "12345678".into(),
                "123456789".into(),
                "password".into(),
                "admin123".into(),
                "root1234".into(),
                "qwertyuiop".into(),
                "halo1234".into(),
            ],
        }
    }
}

impl Policy {
    /// 校验密码是否符合策略规范
    pub fn validate(&self, password: &str, username: Option<&str>) -> Result<()> {
        let len = password.chars().count();
        if len < self.min_length {
            return Err(Error::AuthFailed(format!(
                "Password must be at least {} characters long",
                self.min_length
            )));
        }
        if len > self.max_length {
            return Err(Error::AuthFailed(format!(
                "Password cannot exceed {} characters",
                self.max_length
            )));
        }

        // 弱密码黑名单拦截
        if self
            .weak_passwords
            .iter()
            .any(|w| w.eq_ignore_ascii_case(password))
        {
            return Err(Error::AuthFailed(
                "Password is too common and unsafe".into(),
            ));
        }

        // 禁止包含账号名
        if self.disallow_username
            && let Some(uname) = username
            && !uname.is_empty()
            && password.to_lowercase().contains(&uname.to_lowercase())
        {
            return Err(Error::AuthFailed(
                "Password cannot contain your username".into(),
            ));
        }

        let mut has_upper = false;
        let mut has_lower = false;
        let mut has_digit = false;
        let mut has_special = false;

        for ch in password.chars() {
            if ch.is_ascii_uppercase() {
                has_upper = true;
            } else if ch.is_ascii_lowercase() {
                has_lower = true;
            } else if ch.is_ascii_digit() {
                has_digit = true;
            } else if self.special_chars.contains(ch) {
                has_special = true;
            }
        }

        if self.require_uppercase && !has_upper {
            return Err(Error::AuthFailed(
                "Password must contain at least one uppercase letter".into(),
            ));
        }
        if self.require_lowercase && !has_lower {
            return Err(Error::AuthFailed(
                "Password must contain at least one lowercase letter".into(),
            ));
        }
        if self.require_digit && !has_digit {
            return Err(Error::AuthFailed(
                "Password must contain at least one number".into(),
            ));
        }
        if self.require_special_char && !has_special {
            return Err(Error::AuthFailed(
                "Password must contain at least one special character".into(),
            ));
        }

        Ok(())
    }

    /// 评估密码强度（弱 / 中 / 强）
    pub fn assess_strength(&self, password: &str) -> Strength {
        let len = password.chars().count();
        if len < 6 {
            return Strength::Weak;
        }

        let mut score = 0;
        if len >= 8 {
            score += 1;
        }
        if len >= 12 {
            score += 1;
        }
        if password.chars().any(|c| c.is_ascii_uppercase()) {
            score += 1;
        }
        if password.chars().any(|c| c.is_ascii_lowercase()) {
            score += 1;
        }
        if password.chars().any(|c| c.is_ascii_digit()) {
            score += 1;
        }
        if password.chars().any(|c| self.special_chars.contains(c)) {
            score += 1;
        }

        if score <= 2 {
            Strength::Weak
        } else if score <= 4 {
            Strength::Medium
        } else {
            Strength::Strong
        }
    }
}
