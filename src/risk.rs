use serde::{Deserialize, Serialize};

/// 风险决策结果
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskDecision {
    /// 低风险：无阻碍通行允许登录
    Allow,
    /// 中风险：强制多因素 (MFA / 验证码) 二次核验 (Step-up Authentication)
    RequireMfa,
    /// 高风险：阻断本次登录请求并触发告警 / 临时冻结
    Block,
}

/// 登录请求上下文环境
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContext {
    /// 客户端 IP
    pub client_ip: String,
    /// 浏览器 / 客户端 User-Agent
    pub user_agent: String,
    /// 国家 / 地区编码 (如 "CN", "US", "JP")
    pub geo_country: Option<String>,
    /// 城市名称 (如 "Beijing", "Shenzhen")
    pub geo_city: Option<String>,
    /// 请求时间戳 (UNIX 秒)
    pub timestamp: i64,
    /// 近期连续失败尝试次数
    pub consecutive_failed_attempts: u32,
}

/// 用户历史登录安全档案
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserHistory {
    /// 历史上成功登录过的常用 IP 列表
    pub known_ips: Vec<String>,
    /// 历史上常用客户端 User-Agent 特征
    pub known_user_agents: Vec<String>,
    /// 上次登录的国家代码
    pub last_country: Option<String>,
    /// 上次登录时间戳 (UNIX 秒)
    pub last_login_at: Option<i64>,
    /// 上次登录 IP
    pub last_ip: Option<String>,
}

/// 风险评估策略配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskConfig {
    /// 是否开启自适应风险风控
    pub enabled: bool,
    /// 未知新 IP 加权分 (默认 25)
    pub weight_unknown_ip: u8,
    /// 未知新设备/浏览器加权分 (默认 25)
    pub weight_unknown_device: u8,
    /// 不可能位移/跨国快速切换加权分 (默认 50)
    pub weight_impossible_travel: u8,
    /// 单次失败尝试加权分 (默认 15)
    pub weight_per_failure: u8,
    /// 触发 MFA 核验的阈值 (默认 40)
    pub mfa_threshold: u8,
    /// 触发直接阻断的阈值 (默认 80)
    pub block_threshold: u8,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            weight_unknown_ip: 25,
            weight_unknown_device: 25,
            weight_impossible_travel: 50,
            weight_per_failure: 15,
            mfa_threshold: 40,
            block_threshold: 80,
        }
    }
}

/// 风险评估结论
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// 综合风险分 (0..=100)
    pub score: u8,
    /// 系统风险决策
    pub decision: RiskDecision,
    /// 命中的风险判定因子清单
    pub risk_factors: Vec<String>,
    /// 评估时间戳 (UNIX 秒)
    pub evaluated_at: i64,
}

/// 自适应风险评估引擎
#[derive(Debug, Clone)]
pub struct RiskEngine {
    config: RiskConfig,
}

impl RiskEngine {
    pub fn new(config: RiskConfig) -> Self {
        Self { config }
    }

    /// 评估当前登录上下文的综合安全风险
    pub fn evaluate(&self, ctx: &RiskContext, history: &UserHistory) -> RiskAssessment {
        if !self.config.enabled {
            return RiskAssessment {
                score: 0,
                decision: RiskDecision::Allow,
                risk_factors: vec!["RISK_ENGINE_DISABLED".to_string()],
                evaluated_at: ctx.timestamp,
            };
        }

        let mut score: u32 = 0;
        let mut factors = Vec::new();

        // 1. 连续失败登录惩罚
        if ctx.consecutive_failed_attempts > 0 {
            let fail_score =
                ctx.consecutive_failed_attempts * (self.config.weight_per_failure as u32);
            score += fail_score;
            factors.push(format!(
                "CONSECUTIVE_FAILURES: count={}, +{}pts",
                ctx.consecutive_failed_attempts, fail_score
            ));
        }

        // 2. 陌生/未知 IP 判定
        let ip_clean = ctx.client_ip.trim();
        let is_known_ip = history.known_ips.iter().any(|k| k.trim() == ip_clean);
        if !history.known_ips.is_empty() && !is_known_ip {
            score += self.config.weight_unknown_ip as u32;
            factors.push(format!(
                "NEW_IP: {}, +{}pts",
                ip_clean, self.config.weight_unknown_ip
            ));
        }

        // 3. 陌生设备 / User-Agent 判定
        let ua_clean = ctx.user_agent.trim();
        let is_known_ua = history
            .known_user_agents
            .iter()
            .any(|u| u.trim() == ua_clean);
        if !history.known_user_agents.is_empty() && !is_known_ua {
            score += self.config.weight_unknown_device as u32;
            factors.push(format!(
                "NEW_DEVICE: {}, +{}pts",
                ua_clean, self.config.weight_unknown_device
            ));
        }

        // 4. 不可能移动检测 (Impossible Travel: 如 1 小时内发生跨国物理跃迁)
        if let (Some(curr_country), Some(last_country), Some(last_time)) = (
            &ctx.geo_country,
            &history.last_country,
            history.last_login_at,
        ) && curr_country != last_country
        {
            let diff_secs = (ctx.timestamp - last_time).abs();
            // 若相隔少于 2 小时 (7200秒)
            if diff_secs < 7200 {
                score += self.config.weight_impossible_travel as u32;
                factors.push(format!(
                    "IMPOSSIBLE_TRAVEL: from {} to {} in {}s, +{}pts",
                    last_country, curr_country, diff_secs, self.config.weight_impossible_travel
                ));
            }
        }

        // 封顶 100 分
        let final_score = score.min(100) as u8;

        // 根据阈值输出决策
        let decision = if final_score >= self.config.block_threshold {
            RiskDecision::Block
        } else if final_score >= self.config.mfa_threshold {
            RiskDecision::RequireMfa
        } else {
            RiskDecision::Allow
        };

        RiskAssessment {
            score: final_score,
            decision,
            risk_factors: factors,
            evaluated_at: ctx.timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_login_allows() {
        let engine = RiskEngine::new(RiskConfig::default());
        let history = UserHistory {
            known_ips: vec!["1.1.1.1".to_string()],
            known_user_agents: vec!["Mozilla/5.0 HaloTest".to_string()],
            last_country: Some("CN".to_string()),
            last_login_at: Some(1000),
            last_ip: Some("1.1.1.1".to_string()),
        };
        let ctx = RiskContext {
            client_ip: "1.1.1.1".to_string(),
            user_agent: "Mozilla/5.0 HaloTest".to_string(),
            geo_country: Some("CN".to_string()),
            geo_city: Some("Beijing".to_string()),
            timestamp: 2000,
            consecutive_failed_attempts: 0,
        };

        let res = engine.evaluate(&ctx, &history);
        assert_eq!(res.decision, RiskDecision::Allow);
        assert_eq!(res.score, 0);
    }

    #[test]
    fn test_new_ip_and_new_device_triggers_mfa() {
        let engine = RiskEngine::new(RiskConfig::default());
        let history = UserHistory {
            known_ips: vec!["1.1.1.1".to_string()],
            known_user_agents: vec!["Chrome/120".to_string()],
            last_country: Some("CN".to_string()),
            last_login_at: Some(1000),
            last_ip: Some("1.1.1.1".to_string()),
        };
        // 换了新 IP (25分) + 新设备 (25分) = 50分 -> 超过 40 阈值，要求 MFA
        let ctx = RiskContext {
            client_ip: "2.2.2.2".to_string(),
            user_agent: "Safari/17".to_string(),
            geo_country: Some("CN".to_string()),
            geo_city: Some("Beijing".to_string()),
            timestamp: 2000,
            consecutive_failed_attempts: 0,
        };

        let res = engine.evaluate(&ctx, &history);
        assert_eq!(res.decision, RiskDecision::RequireMfa);
        assert_eq!(res.score, 50);
        assert_eq!(res.risk_factors.len(), 2);
    }

    #[test]
    fn test_impossible_travel_and_failures_blocks() {
        let engine = RiskEngine::new(RiskConfig::default());
        let history = UserHistory {
            known_ips: vec!["1.1.1.1".to_string()],
            known_user_agents: vec!["Chrome/120".to_string()],
            last_country: Some("CN".to_string()),
            last_login_at: Some(1000),
            last_ip: Some("1.1.1.1".to_string()),
        };
        // 100秒内从 CN 到 US (50分) + 3 次失败尝试 (45分) = 95分 -> 超过 80 阈值，阻断
        let ctx = RiskContext {
            client_ip: "1.1.1.1".to_string(),
            user_agent: "Chrome/120".to_string(),
            geo_country: Some("US".to_string()),
            geo_city: Some("NewYork".to_string()),
            timestamp: 1100,
            consecutive_failed_attempts: 3,
        };

        let res = engine.evaluate(&ctx, &history);
        assert_eq!(res.decision, RiskDecision::Block);
        assert_eq!(res.score, 95);
    }
}
