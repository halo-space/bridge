use crate::types::{AuthResult, Level, Method};

/// 一步认证要求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub method: Method,
    pub level: Level,
    pub max_age: Option<i64>,
}

impl Step {
    pub fn new(method: Method, level: Level) -> Self {
        Self {
            method,
            level,
            max_age: None,
        }
    }

    pub fn age(mut self, seconds: i64) -> Self {
        self.max_age = Some(seconds);
        self
    }
}

/// Pipeline 当前还需要的步骤，或已经完成。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    Next { index: usize, method: Method },
    Done,
}

/// 认证步骤编排规则。
#[derive(Debug, Clone)]
pub struct Pipeline {
    steps: Vec<Step>,
}

impl Pipeline {
    /// 使用默认强度创建步骤：第一步为 First，后续步骤为 Second。
    pub fn new(methods: Vec<Method>) -> Self {
        Self::steps(
            methods
                .into_iter()
                .enumerate()
                .map(|(index, method)| {
                    Step::new(
                        method,
                        if index == 0 {
                            Level::First
                        } else {
                            Level::Second
                        },
                    )
                })
                .collect(),
        )
    }

    pub fn steps(steps: Vec<Step>) -> Self {
        Self { steps }
    }

    pub fn push(&mut self, step: Step) {
        self.steps.push(step);
    }

    pub fn methods(&self) -> Vec<Method> {
        self.steps.iter().map(|step| step.method).collect()
    }

    pub fn run(&self, results: &[AuthResult], now: i64) -> Progress {
        let mut after = i64::MIN;
        for (index, step) in self.steps.iter().enumerate() {
            let result = results
                .iter()
                .filter(|result| {
                    result.method == step.method
                        && result.level >= step.level
                        && result.at >= after
                        && result.at <= now
                        && step
                            .max_age
                            .map(|max_age| now.saturating_sub(result.at) <= max_age)
                            .unwrap_or(true)
                })
                .min_by_key(|result| result.at);
            let Some(result) = result else {
                return Progress::Next {
                    index,
                    method: step.method,
                };
            };
            after = result.at;
        }
        Progress::Done
    }

    pub fn accept(&self, results: &[AuthResult]) -> bool {
        self.run(results, chrono::Utc::now().timestamp()) == Progress::Done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Identity;

    fn result(identity: &Identity, method: Method, level: Level, at: i64) -> AuthResult {
        AuthResult {
            identity: identity.clone(),
            method,
            level,
            at,
        }
    }

    #[test]
    fn runs_steps_in_order_and_reports_next() {
        let identity = Identity::new("local", "1");
        let results = vec![
            result(&identity, Method::Totp, Level::Second, 20),
            result(&identity, Method::Password, Level::First, 10),
        ];
        let pipeline = Pipeline::new(vec![Method::Password, Method::Totp]);
        assert_eq!(pipeline.run(&results, 20), Progress::Done);

        let reversed = vec![
            result(&identity, Method::Password, Level::First, 20),
            result(&identity, Method::Totp, Level::Second, 10),
        ];
        assert_eq!(
            pipeline.run(&reversed, 20),
            Progress::Next {
                index: 1,
                method: Method::Totp,
            }
        );
    }

    #[test]
    fn enforces_level_and_age() {
        let identity = Identity::new("local", "1");
        let pipeline = Pipeline::steps(vec![
            Step::new(Method::Password, Level::First),
            Step::new(Method::Totp, Level::Second).age(30),
        ]);
        let results = vec![
            result(&identity, Method::Password, Level::First, 90),
            result(&identity, Method::Totp, Level::First, 95),
        ];
        assert_eq!(
            pipeline.run(&results, 100),
            Progress::Next {
                index: 1,
                method: Method::Totp,
            }
        );
        assert!(!pipeline.accept(&results));
    }

    #[test]
    fn supports_append_factor() {
        let mut pipeline = Pipeline::new(vec![Method::Password]);
        pipeline.push(Step::new(Method::Passkey, Level::Second));
        assert_eq!(pipeline.methods(), vec![Method::Password, Method::Passkey]);
    }
}
