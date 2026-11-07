# bridge

Bridge 是一个面向企业身份认证的 Rust 能力库。它提供基础登录方式、外部身份源、认证材料、OIDC 流程、Token、认证规则和安全审计模型。

Bridge 只负责身份认证和协议能力。业务用户、角色、权限、应用 Session、组织目录和具体数据库由调用方负责。

## 目录

```text
src/
├── factor/                 # 完整登录因子
│   ├── basic/              # 密码、邮箱验证码、短信验证码、TOTP、Magic Link
│   ├── social/             # GitHub、飞书、Google、微信
│   ├── enterprise/         # LDAP、SAML、企业微信、钉钉
│   ├── oidc/               # 外部 OIDC Provider 和 OAuth/OIDC 流程
│   │   └── provider/       # 外部 OIDC 身份源
│   └── passkey.rs          # 持久化 Passkey 数据模型
├── validator/              # 认证材料的签发、发送和校验
│   ├── issuer/
│   ├── sender/
│   └── verifier/
├── types/                  # 身份、认证结果、用户、OAuth、因子模型
├── store/                  # 按能力拆分的存储契约
├── token/                  # Claims、JWT 服务和 JWKS
├── rules/                  # 密码、锁定、重认证规则
├── pkg/                    # 密码、TOTP、恢复码、RSA 等算法
├── pipeline.rs             # 统一登录前、中、后的节点状态机
├── audit.rs                # 安全审计事件模型
├── risk.rs                 # 风险评分和阻断决策
└── error.rs                # 统一错误类型
```

`factor/oidc` 同时承载外部 OIDC 登录 Provider 和 OAuth/OIDC 流程参数。`factor/enterprise` 保留 LDAP、SAML、企业微信和钉钉等企业专属身份源。

## 核心边界

`factor` 负责一种完整登录方式。`validator` 负责验证码、TOTP、恢复码、Magic Link、Passkey 等认证材料的生命周期。`pkg` 提供可复用算法。`token` 负责认证结果 Token。`store` 只定义调用方实现的契约。

`state`、`nonce` 和 PKCE 属于 `factor/oidc`。它们参与协议流程校验，不属于 `validator`。

Bridge 不保存业务用户，也不执行账号绑定。Provider 只把第三方已认证资料转换为统一的 `Identity`。

## 能力状态

| 能力 | 状态 | 当前范围 |
| --- | --- | --- |
| 账号、邮箱、手机号密码 | 已实现 | `factor/basic/password` |
| 邮箱、短信、TOTP 登录 | 已实现 | `factor/basic/code` |
| 图形、滑块、旋转、点选验证码 | 已实现 | `validator/verifier/captcha` |
| 恢复码和 Magic Link | 已实现 | `validator` 和 `factor/basic/magic` |
| GitHub、飞书、Google、微信 | 已实现 | 授权地址、授权码交换、资料转换 |
| LDAP | 已实现 | 服务账号绑定、用户搜索、密码绑定、Identity 输出 |
| SAML | 已实现 | metadata、签名、Issuer、Audience、时间校验、真实 fixture、replay cache 和 SP 状态关联 |
| 企业微信、钉钉 | 已实现 | 授权码交换和 Identity 输出 |
| OIDC Authorization Code | 已实现 | state、nonce、PKCE、scope、redirect URI、Refresh Token、撤销和用户状态检查 |
| UserInfo、Introspection、隐式授权 | 边界已确定 | 不维护业务用户；调用方用 `verify_live` 组装 Introspection；只支持 Authorization Code + PKCE |
| Passkey / WebAuthn | 已实现 | 注册、认证、状态标记、计数器 CAS、`last_used_at` 和真实协议 fixture 已覆盖；状态单次消费由调用方存储保证 |
| Device | 待实现 | 当前只保留模块边界 |
| Pipeline | 已实现 | 支持输入、检查、签发、校验、后置动作、路由分支、All/Any 汇聚、有限循环、上下文传递、重试、拒绝和暂停继续 |
| 风险决策和审计模型 | 已实现 | 由调用方负责持久化和策略接入 |

## 类型和存储

公共模型位于 `types/`。

```rust
pub struct Identity {
    pub provider: String,
    pub subject: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub name: Option<String>,
}
```

存储契约位于 `store/`，按能力拆分为以下接口：

```rust
pub trait Users { /* 用户身份和凭证读取 */ }
pub trait Clients { /* OAuth/OIDC 客户端读取 */ }
pub trait Secrets { /* 临时材料和原子消费 */ }
pub trait Factors { /* TOTP 绑定读取 */ }
pub trait Passkeys { /* Passkey 保存、查询和计数器更新 */ }
pub trait Events { /* 审计事件写入 */ }
pub trait Limits { /* 发送和验证频控 */ }
```

`Passkeys::update` 使用旧计数器条件更新。调用方在返回失败时处理计数器回退或克隆风险。`Secrets::take_if` 必须由具体存储实现原子 compare-and-delete。

## 认证材料生命周期

认证材料统一经过创建、保存、过期、失败次数、单次消费和撤销处理。验证码发送由 `validator/sender` 负责，验证码生成和校验由 `validator/issuer` 与 `validator/verifier` 负责。

Magic Link 的无存储签名接口只负责签名校验。需要单次消费时使用带 `Secrets` 的接口。

## OIDC

OIDC 相关代码位于 `factor/oidc`：

- `flow.rs` 负责授权码、客户端、scope、redirect URI、PKCE 和 Refresh Token
- OIDC 流程调用必须显式传入租户上下文，客户端与授权码不会跨租户读取
- `state.rs`、`nonce.rs`、`pkce.rs` 负责流程参数生成和校验
- `server.rs` 负责 Discovery、撤销和响应模型
- `provider/` 负责外部 OIDC Claims 到 `Identity` 的转换

Discovery 只声明当前已经实现的 Authorization Code、PKCE、JWKS 和撤销能力。

## 验证

```bash
cargo check
cargo test
```

当前测试覆盖基础认证材料、密码算法、Passkey 注册认证 fixture、存储契约和计数器 CAS、OIDC 失败路径、Token rotation、Provider 资料转换以及 SAML 签名、状态关联和重放。

后续工作见 [plan.md](plan.md)，当前问题见 [issue.md](issue.md)。
