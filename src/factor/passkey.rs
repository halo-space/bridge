use serde::{Deserialize, Serialize};

/// 持久化的 Passkey。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey {
    pub credential_id: String,
    pub public_key: String,
    pub sign_count: u32,
    pub transports: Vec<String>,
    pub aaguid: Option<String>,
    #[serde(default)]
    pub user_handle: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    pub created_at: i64,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    #[serde(default)]
    pub passwordless: bool,
    /// `webauthn-rs` 标准 Passkey 序列化数据。
    #[serde(default)]
    pub data: Option<String>,
}

impl Passkey {
    /// 判断认证结果是否可以推进签名计数器。
    pub fn can_update(&self, count: u32) -> bool {
        self.sign_count == 0 || count > self.sign_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passkey(sign_count: u32) -> Passkey {
        Passkey {
            credential_id: "id".into(),
            public_key: "key".into(),
            sign_count,
            transports: Vec::new(),
            aaguid: None,
            user_handle: None,
            display_name: None,
            created_at: 1,
            last_used_at: None,
            passwordless: false,
            data: None,
        }
    }

    #[test]
    fn counter_can_advance_or_start_at_zero() {
        assert!(passkey(0).can_update(0));
        assert!(passkey(0).can_update(1));
        assert!(passkey(2).can_update(3));
        assert!(!passkey(2).can_update(2));
        assert!(!passkey(2).can_update(1));
    }
}
