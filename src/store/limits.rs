use crate::error::Result;

/// 一次节点执行的频控和锁定参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub limit: u32,
    pub window: u64,
    pub lock: u64,
}

impl Rule {
    pub const fn new(limit: u32, window: u64) -> Self {
        Self {
            limit,
            window,
            lock: 0,
        }
    }

    pub const fn lock(mut self, lock: u64) -> Self {
        self.lock = lock;
        self
    }
}

/// 频控或锁定检查的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { retry_after: u64 },
}

#[allow(async_fn_in_trait)]
pub trait Limits: Send + Sync {
    async fn allow(&self, key: &str, limit: u32, window_secs: u64) -> Result<bool>;

    /// 记录一次认证失败。调用方可以在这里递增失败次数并设置锁定截止时间。
    async fn fail(&self, _key: &str, _rule: Rule) -> Result<Decision> {
        Ok(Decision::Allow)
    }

    /// 认证成功后清理连续失败状态。
    async fn clear(&self, _key: &str) -> Result<()> {
        Ok(())
    }
}

/// 默认不限制的实现，便于只使用内置 Services 的调用方直接启动。
#[derive(Debug, Clone, Copy, Default)]
pub struct Noop;

impl Limits for Noop {
    async fn allow(&self, _key: &str, _limit: u32, _window_secs: u64) -> Result<bool> {
        Ok(true)
    }
}
