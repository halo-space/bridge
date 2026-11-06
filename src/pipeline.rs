use crate::types::{AuthResult, Method};

/// 认证方式组合规则。
#[derive(Debug, Clone)]
pub struct Pipeline {
    methods: Vec<Method>,
}

impl Pipeline {
    pub fn new(methods: Vec<Method>) -> Self {
        Self { methods }
    }

    pub fn methods(&self) -> &[Method] {
        &self.methods
    }

    pub fn accept(&self, results: &[AuthResult]) -> bool {
        self.methods
            .iter()
            .all(|required| results.iter().any(|result| result.method == *required))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Level;

    #[test]
    fn accepts_required_methods() {
        let identity = crate::types::Identity::new("local", "1");
        let results = vec![
            AuthResult::new(identity.clone(), Method::Password, Level::First),
            AuthResult::new(identity, Method::Totp, Level::Second),
        ];
        assert!(Pipeline::new(vec![Method::Password, Method::Totp]).accept(&results));
        assert!(!Pipeline::new(vec![Method::Password, Method::Passkey]).accept(&results));
    }
}
