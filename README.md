# bridge

Bridge 是一个面向企业登录认证的 Rust 能力库。它提供密码、短信验证码、邮箱验证码、TOTP、Passkey、社交登录和企业身份源等能力，并提供可组合的登录流程。

完整使用方式见 [USAGE.md](https://github.com/halo-space/bridge/blob/main/USAGE.md)。

```toml
[dependencies]
halo = { package = "halo-bridge", version = "0.4" }
```

默认启用 `full` feature。只需要核心 Pipeline、类型和算法时，可以使用 `default-features = false`；邮件、短信、社交、企业和 Passkey 能力分别由 `mail`、`sms`、`social`、`enterprise`、`passkey` feature 控制。

```rust
use halo::bridge::{Context, Node, Pipeline};
```

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
│   └── passkey.rs          # Passkey 因子入口
├── validator/              # 登录过程中临时使用的信息：生成、发送和检查
│   ├── issuer/
│   │   └── captcha/      # 图形、滑块、旋转、点选验证码签发
│   ├── sender/
│   │   └── sms/          # 短信门面、阿里云、腾讯云和未知供应商错误适配
│   └── verifier/         # 验证码、TOTP、Passkey 等校验
├── types/                  # 身份、认证结果、用户、OAuth、因子模型
│   ├── passkey.rs          # 持久化 Passkey 模型
│   └── device.rs           # 持久化 Device 模型
├── store/                  # 调用方需要实现的存储接口
├── token/                  # 登录 Token 和公钥信息
├── rules/                  # 密码、锁定、重认证规则
├── pkg/                    # 密码、TOTP、恢复码、RSA 等算法
├── pipeline/               # 统一登录前、中、后的节点 DAG 和内置执行绑定
│   ├── model.rs            # 节点、上下文、事件和 Runner 契约
│   ├── run.rs              # 可恢复运行状态和进度
│   ├── engine.rs           # 图调度、汇聚、重试和执行
│   ├── config.rs           # 配置编译、能力卡片和 Schema
│   └── services/           # 按能力拆分的内置 Runner
├── audit.rs                # 安全审计事件模型
├── risk.rs                 # 风险评分和阻断决策
└── error.rs                # 统一错误类型
```

根目录 `examples/` 提供 Pipeline 组合和执行示例。

`factor/oidc` 同时承载外部 OIDC 登录 Provider 和 OAuth/OIDC 流程参数。`factor/enterprise` 保留 LDAP、SAML、企业微信和钉钉等企业专属身份源。

## 核心边界

`factor` 表示一种完整的登录方式，例如密码登录或 GitHub 登录。`validator` 负责登录过程中会短时间使用的安全信息，例如验证码、TOTP 校验结果、Passkey challenge 和 Magic Link。`pkg` 放密码、RSA、TOTP 等底层算法。`token` 负责签发和校验登录后的 Token。`store` 只规定调用方需要提供哪些读写接口。

`state`、`nonce` 和 PKCE 属于 `factor/oidc`。它们参与协议流程校验，不属于 `validator`。

Bridge 不保存业务用户，也不执行账号绑定。Provider 只把第三方已认证资料转换为统一的 `Identity`。

代码中的名称按所在模块理解即可：`validator::issuer` 是“生成”，`validator::sender` 是“发送”，`validator::verifier` 是“检查”。同名能力通过模块路径区分，例如生成验证码和检查验证码是两个不同的 `Captcha`。

## 能力状态

| 能力 | 状态 | 当前范围 |
| --- | --- | --- |
| 账号、邮箱、手机号密码 | 已实现 | `factor/basic/password` |
| 邮箱、短信、TOTP 登录 | 已实现 | `factor/basic/code` |
| 图形、滑块、旋转、点选验证码 | 已实现 | `validator/verifier/captcha` |
| 恢复码和 Magic Link | 已实现 | `validator` 和 `factor/basic/magic` |
| GitHub、飞书、Google、微信 | 已实现 | 授权地址、授权码交换、资料转换 |
| LDAP | 已实现 | 服务账号绑定、用户搜索、密码绑定、Identity 输出 |
| SAML | 已实现 | 企业单点登录、签名检查、时间检查和防重复使用 |
| 企业微信、钉钉 | 已实现 | 授权码交换和 Identity 输出 |
| OIDC Authorization Code | 已实现 | OAuth/OIDC 授权码、PKCE、state、nonce、刷新和撤销 |
| UserInfo、Introspection、隐式授权 | 边界已确定 | 不维护业务用户；调用方用 `verify_live` 组装 Introspection；只支持 Authorization Code + PKCE |
| Passkey / WebAuthn | 已实现 | 注册、登录、设备状态和计数器更新；凭证由调用方保存 |
| Device | 已实现 | RSA-SHA256 nonce 证明、启停、时间窗口和 `Devices` 存储契约 |
| Pipeline | 已实现 | 支持输入、检查、签发、发送、校验、审计、内置 `Services` 执行绑定、路由分支、All/Any 汇聚、有限循环、上下文传递、重试、拒绝和暂停继续 |
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

存储接口位于 `store/`，由调用方实现。它们只说明 Bridge 需要哪些操作，不要求调用方使用某种数据库：

```rust
pub trait Users { /* 用户身份和凭证读取 */ }
pub trait Clients { /* OAuth/OIDC 客户端读取 */ }
pub trait Secrets { /* 临时材料和原子消费 */ }
pub trait Factors { /* TOTP 绑定读取 */ }
pub trait Passkeys { /* Passkey 保存、查询和计数器更新 */ }
pub trait Devices { /* 设备保存、查询、更新和撤销 */ }
pub trait Events { /* 审计事件写入 */ }
pub trait Limits { /* 发送和验证频控 */ }
```

`Passkeys::update` 会带上旧计数器，只有旧值匹配时才允许更新，用来防止同一个 Passkey 被并发重复使用。`Secrets::take_if` 用于“检查内容并立即删除”，这两个动作必须在存储中一次完成，不能拆成两个并发不安全的操作。

Pipeline 的 `Services` 是 bridge 提供的可选默认适配器，不是能力边界。调用方可以完全替换用户名密码、验证码、TOTP、Passkey、社交和企业认证的实现；`Fallback` 会优先使用调用方处理器，再回退到默认适配器。

页面配置使用固定能力码；自定义能力使用 `custom.*` 命名空间，例如 `custom.card`，并且必须先注册后才能被页面引用。

用户输入通过 `Event::Input` 提交。`Pipeline::run` 自动推进可执行节点，遇到尚未提交的 `Input` 或 `Verify` 节点才返回 `Progress::Need`。

页面配置通过 `PipelineConfig` 编译，并使用 `Cards` 校验固定能力码；自定义能力例如 `custom.card` 必须先注册。节点的 `args` 会传给用户自己的 `Runner`。

`Cards::schema()` 可生成页面编辑器使用的 JSON Schema、能力码和每个 Card 的参数 Schema；编译时会校验参数类型、未知参数和 Secret 引用。敏感配置使用 `secret("...")` 保存引用，真实密钥由应用层解析。

发布配置后可以调用 `Cards::run` 预检查实际 Runner 是否支持所有能力和版本；它只检查兼容性，真正执行仍使用 `Pipeline::run`。

配置编译后会生成版本和 hash，运行中的 `Run` 会绑定这两个值；页面发布新配置不会改变已经开始的认证流程。`Context` 还支持 `protocol`、`connection`、`request` 和 `meta`，用于传递请求和身份源上下文。

所有可替换节点都通过 trait 扩展。内置短信使用 `SmsSender` 门面和 `Sender` 适配器；腾讯云使用 API 3.0 `SendSms` 与 TC3-HMAC-SHA256，其他供应商可以实现 `Sender` 后通过 `SmsSender::with` 接入。Pipeline 的自定义节点使用 `Runner`，可通过 `Fallback` 在保留内置能力的同时增加自己的社交、企业或业务认证逻辑。

## 登录过程中使用的安全信息

这里的“安全信息”指登录时临时使用的一段内容，不是业务用户资料。例如：

| 信息 | 用户看到什么 | Bridge 做什么 | 成功后怎么处理 |
| --- | --- | --- | --- |
| 图形、滑块、旋转、点选验证码 | 一张图片或一个操作题 | 生成题目并检查答案 | 通过后继续当前登录流程 |
| 短信或邮箱验证码 | 手机或邮箱收到的数字 | 生成数字、交给发送通道、检查用户输入 | 验证码只能使用一次，过期后失效 |
| TOTP 动态码 | 身份验证器 App 显示的 6 位数字 | 根据调用方提供的密钥检查动态码 | 不保存动态码本身 |
| Passkey challenge | 浏览器弹出的生物识别或设备确认 | 发起 WebAuthn 请求并检查浏览器返回值 | 调用方保存凭证和计数器 |
| Magic Link | 邮件中的一次性链接 | 生成链接、检查签名和有效期 | 使用后立即失效 |

这些信息都遵循同一套基本规则：

1. 先生成或发起。
2. 按需要保存一小段时间。
3. 到期自动失效。
4. 验证失败可以限制尝试次数。
5. 验证成功后通常只能使用一次。

模块职责也很直观：`issuer` 负责生成，`sender` 负责发送，`verifier` 负责检查。比如手机号登录就是“生成短信验证码 → 发送短信 → 用户输入验证码 → 检查验证码”。这些临时信息的具体保存位置由调用方通过 `Secrets` 提供，Bridge 不绑定 Redis 或数据库。

Magic Link 的签发和校验分别使用 `validator::issuer::Magic` 与 `validator::verifier::Magic`。Passkey 的浏览器流程发起和结果检查也分别由 issuer 与 verifier 负责。

## OIDC

OIDC 相关代码位于 `factor/oidc`：

- `flow.rs` 负责授权码、客户端、scope、redirect URI、PKCE 和 Refresh Token
- OIDC 流程只处理协议校验和临时凭证；客户端、授权码和业务命名空间由调用方提供
- `state.rs`、`nonce.rs`、`pkce.rs` 负责流程参数生成和校验
- `server.rs` 负责 Discovery、撤销和响应模型
- `provider/` 负责外部 OIDC Claims 到 `Identity` 的转换

Discovery 只声明当前已经实现的 Authorization Code、PKCE、JWKS 和撤销能力。

## Pipeline 示例

```bash
cargo run --example pipeline_linear
cargo run --example pipeline_graph
cargo run --example pipeline_runner
cargo run --example pipeline_custom
cargo run --example sender_custom
```

- `pipeline_linear`：手机号验证码、密码加 TOTP、密码加 Passkey
- `pipeline_graph`：风险分支、All 汇聚、Any 汇聚
- `pipeline_runner`：调用方 Runner 执行节点
- `pipeline_custom`：用户自己的用户名密码实现覆盖默认节点
- `sender_custom`：用户自己的短信供应商适配器

基于内置能力的完整手机号验证码流程见 `tests/pipeline_services.rs`，覆盖滑块校验、验证码签发、短信发送、短信校验和审计写入。

## 验证

```bash
cargo check
cargo test
cargo bench --bench pipeline
```

当前测试覆盖基础认证材料、密码算法、Passkey 注册认证 fixture、存储契约和计数器 CAS、OIDC 失败路径、Token rotation、Provider 资料转换以及 SAML 签名、状态关联和重放。

