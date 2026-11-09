# bridge 使用手册

本文说明如何把 `halo-bridge` 接入一个登录系统。示例中的数据库、Redis、HTTP 路由和用户查询都是调用方代码；bridge 只负责认证协议、安全材料和 Pipeline 执行。

## 1. 安装

```toml
[dependencies]
halo = { package = "halo-bridge", version = "0.4" }
```

统一入口：

```rust
use halo::bridge::*;
```

默认启用完整能力。如果只需要核心 Pipeline 和密码能力，可以关闭默认 feature：

```toml
[dependencies]
halo = { package = "halo-bridge", version = "0.4", default-features = false }
```

可选 feature 是 `mail`、`sms`、`social`、`enterprise` 和 `passkey`，`full` 会一次启用全部能力。

## 2. 先明确边界

bridge 是认证能力库，不是完整的账号中心。它不会自动创建用户、自动添加 MFA，也不会替调用方决定登录步骤。

| bridge 负责 | 调用方负责 |
| --- | --- |
| 密码、验证码、TOTP、Passkey、Device、OIDC、社交和企业协议 | 用户、账号、租户、应用和组织数据 |
| issuer、sender、verifier 和可选的 `Services` | `Users`、`Clients`、`Factors`、`Passkeys`、`Devices`、`Secrets`、`Events` 的实际存储 |
| Pipeline 图、状态、路由、分支、重试、拒绝和暂停恢复 | Pipeline 配置保存、发布、版本管理和登录请求加载 |
| `Identity`、Token、审计事件等标准模型 | HTTP 路由、登录页面、业务账号绑定和最终应用会话 |
| Store、Runner、Effects 等扩展契约 | 数据库、缓存、跨进程原子操作、异步超时和通知配置 |

调用方还要负责业务安全边界：

- 将租户、应用或平台编码进自己的存储 Key。
- 查询 Device、Passkey、验证码和临时凭证时校验业务归属。
- 为 Magic Link 的 `redirect_to` 配置允许域名和路径。
- 决定认证完成后签发什么应用 Token，或如何建立 Session。
- 在自己的请求层限制登录运行状态的 TTL。

## 3. 名词和模块

### 3.1 Pipeline

Pipeline 是登录流程图。它只知道节点、边、路由、汇聚、重试和状态，不知道“用户表在哪里”或“短信供应商是什么”。

### 3.2 issuer、sender、verifier

- `issuer`：生成验证码、挑战、nonce、临时凭证等材料。
- `sender`：把已经生成的内容发送到短信、邮件等通道。
- `verifier`：校验验证码、TOTP、PKCE、state、nonce、Passkey 等材料。

例如手机号登录通常拆成：

```text
手机号输入
  → 人机校验 verifier
  → 验证码 issuer
  → 短信 sender
  → 验证码 verifier
```

### 3.3 Cards、Services、Runner

- `Cards` 是配置注册表，描述某个 `type/code` 是否存在、需要哪些参数以及参数类型。
- `Services` 是 bridge 提供的默认 Runner，内部能力表把 `password`、`totp`、`sms`、`sms.send` 等能力码绑定到实现。
- `Runner` 是执行器。调用方可以完全自己实现，也可以用 `Fallback` 在默认能力之外增加自定义能力。

这三个东西不是同一份配置：

```text
PipelineConfig：业务侧保存的登录流程数据
Cards          ：发布前检查配置是否合法
Services       ：能力码到内置实现的绑定
Runner         ：实际执行节点的对象
```

每次登录只加载对应的 `PipelineConfig`；Services 的能力表通常在应用启动时创建，不保存用户流程。

## 4. 推荐接入顺序

### 第一步：实现 Store

调用方先实现 bridge 的存储契约。下面是职责示意，实际 trait 方法以源码为准：

```rust
pub trait Users {}    // 读取账号和密码凭证
pub trait Clients {}  // 读取 OAuth/OIDC 客户端
pub trait Secrets {}  // 短期验证码、state、nonce、单次凭证
pub trait Factors {}  // TOTP 绑定
pub trait Passkeys {} // Passkey 保存和计数器 CAS
pub trait Devices {}  // Device 保存、更新和撤销
pub trait Events {}   // 审计事件写入
pub trait Limits {}   // 发送和校验频控
```

这些 trait 不是数据库实现。调用方需要自行处理：

- Key 的租户、应用和平台命名空间。
- TTL、原子消费和并发更新。
- 用户是否存在、是否启用、是否被锁定。
- Passkey 计数器 CAS 和 Device nonce 的单次消费。

验证码高并发失败计数可以在 `Secrets::incr` 中接入 Redis 原子递增；如果存储不支持，bridge 会使用兼容读写路径，但生产环境应提供原子实现。

### 第二步：创建 Cards

管理端发布 Pipeline 前，用 `Cards` 注册允许页面使用的能力和参数：

```rust
use halo::bridge::{Cards, Op};

let cards = Cards::new()
    .add(Op::Verify, "password")
    .add(Op::Verify, "totp")
    .add(Op::Verify, "sms")
    .add(Op::Issue, "sms")
    .add(Op::Effect, "sms.send")
    .arg(Op::Verify, "password", "source", "string", false, false)
    .arg(Op::Issue, "sms", "scene", "string", false, false);

// 页面使用的 JSON Schema
let schema = cards.schema();
```

自定义能力使用 `custom.*` 命名空间：

```rust
let cards = cards.add(Op::Verify, "custom.employee_card");
```

页面只能引用已经注册的能力码。未知能力、错误参数类型、缺少必填参数和非法边都会在发布阶段被拒绝。

### 第三步：保存并编译 PipelineConfig

调用方可以把下面的 JSON 保存到数据库的登录方式配置中：

```json
{
  "version": 1,
  "start": "input",
  "max_steps": 128,
  "nodes": [
    {
      "id": "input",
      "type": "input",
      "fields": ["account", "password"],
      "edges": [{"to": "password"}]
    },
    {
      "id": "password",
      "type": "verify",
      "code": "password",
      "args": {"source": "company"},
      "edges": [{"to": "done"}],
      "retries": 1
    },
    {
      "id": "done",
      "type": "effect",
      "code": "audit",
      "once": true
    }
  ]
}
```

编译时校验配置：

```rust
use halo::bridge::{Pipeline, PipelineConfig};

let config: PipelineConfig = serde_json::from_str(json_text)?;
let pipeline: Pipeline = config.compile_with(&cards)?;
cards.validate_runner(&pipeline, &runner)?;
```

配置发布后会生成版本和 hash。恢复旧 Run 时必须使用相同配置；新发布的配置不会接管已经开始的认证流程。

### 第四步：创建默认 Services 或自定义 Runner

如果使用 bridge 默认能力，创建 `Services` 并注入 Store：

```rust
let services = Services::new(
    secrets,
    users,
    factors,
    passkeys,
    events,
    devices,
    notifications,
);
```

如果某一步必须使用公司自己的账号系统、风控系统或验证码服务，就实现 `Runner`：

```rust
struct CompanyRunner;

impl Runner for CompanyRunner {
    async fn run(&self, node: &Node, context: &Context) -> halo::Result<Output> {
        // 读取 node.args 和当前节点输入，调用调用方自己的服务。
        let input = context.data.get(&node.id).cloned().unwrap_or_default();
        Ok(Output::Pass {
            routes: Vec::new(),
            data: input,
            identity: Some(Identity::new("company", "employee-42")),
            at: chrono::Utc::now().timestamp(),
        })
    }
}
```

保留默认能力，同时覆盖一部分节点：

```rust
let runner = Fallback::new(CompanyRunner, services);
```

`Fallback` 会先调用自己的 Runner；只有返回 `Error::Unsupported` 时才交给后面的 Runner。

### 第五步：启动认证运行

登录请求开始时，调用方加载对应登录方式的 PipelineConfig，创建 `Context`，然后启动：

```rust
let context = Context {
    protocol: Some("password".into()),
    connection: Some("browser".into()),
    ..Context::default()
};

let (mut run, progress) = pipeline.start(context)?;
```

`Progress::Need` 表示当前节点需要调用方提供输入或执行器继续执行：

```rust
match progress {
    Progress::Need { node, kind, fields } => {
        println!("node={node}, kind={kind}, fields={fields:?}");
    }
    Progress::Done => println!("already done"),
    Progress::Retry { node, reason } => println!("retry {node}: {reason}"),
    Progress::Deny { node, reason } => println!("deny {node}: {reason}"),
}
```

### 第六步：提交用户输入

`Event::Input` 只提交当前节点的数据。提交后，调用方再次执行 Pipeline：

```rust
let progress = pipeline.resume(
    &mut run,
    Event::Input {
        node: "input".into(),
        data: serde_json::json!({
            "account": "alice",
            "password": "secret"
        }),
        at: chrono::Utc::now().timestamp(),
    },
)?;

let progress = pipeline.run(&mut run, &runner).await?;
```

只有 Pipeline 返回 `Done`，调用方才应该认为认证流程完成。`Retry`、`Deny` 和 `Need` 都不能签发最终登录结果。

### 第七步：保存和恢复 Run

如果登录需要跨 HTTP 请求继续，调用方保存序列化后的 Run：

```rust
let encoded = serde_json::to_vec(&run)?;
// 写入调用方自己的 Redis 或数据库，并设置短 TTL。
```

恢复时必须加载同一版本的 Pipeline：

```rust
let mut run: Run = serde_json::from_slice(&encoded)?;
let progress = pipeline.run(&mut run, &runner).await?;
```

Run 会拒绝持久化密码、验证码、Token、state、nonce 等敏感字段。调用方仍应在存储层设置认证流程 TTL，并在登录结束、失败或取消时删除 Run。

## 5. 常见流程示例

### 5.1 账号密码

流程：

```text
input(account, password)
  → verify(password)
  → audit
  → Done
```

节点构造：

```rust
let pipeline = Pipeline::new(
    "input",
    vec![
        Node::input("input", vec!["account".into(), "password".into()])
            .edge(None::<String>, "password"),
        Node::verify("password", "password").edge(None::<String>, "audit"),
        Node::effect("audit", "audit").once(true),
    ],
);
```

默认 `Services` 会从调用方的 `Users` Store 查询账号并校验密码。账号表、密码哈希和密码算法由调用方保存；自定义密码算法可以实现自己的 Runner 或注入 `Codecs`。

### 5.2 手机号、滑块、短信验证码

流程：

```text
input(phone)
  → verify(captcha.slider)
  → issue(sms)
  → effect(sms.send)
  → input(code)
  → verify(sms)
  → Done
```

节点构造：

```rust
let pipeline = Pipeline::new(
    "phone",
    vec![
        Node::input("phone", vec!["phone".into()])
            .edge(None::<String>, "captcha"),
        Node::verify("captcha", "captcha.slider")
            .edge(None::<String>, "issue"),
        Node::issue("issue", "sms")
            .edge(None::<String>, "send"),
        Node::effect("send", "sms.send")
            .edge(None::<String>, "code"),
        Node::input("code", vec!["code".into()])
            .edge(None::<String>, "check"),
        Node::verify("check", "sms"),
    ],
);
```

这里的职责是分开的：验证码由 issuer 生成，短信由 sender 发送，短信验证码由 verifier 校验。生产环境的验证码 Key、手机号归属和频控由调用方 Store 决定。

### 5.3 密码加 TOTP

流程：

```text
input(account, password)
  → verify(password)
  → input(code)
  → verify(totp)
  → Done
```

TOTP Secret 不由 bridge 保存。`Factors` Store 根据调用方身份返回绑定信息，调用方负责 Secret 加密、轮换和解绑。

```rust
let pipeline = Pipeline::new(
    "input",
    vec![
        Node::input("input", vec!["account".into(), "password".into()])
            .edge(None::<String>, "password"),
        Node::verify("password", "password").edge(None::<String>, "totp"),
        Node::input("totp", vec!["code".into()])
            .edge(None::<String>, "check"),
        Node::verify("check", "totp"),
    ],
);
```

### 5.4 密码加 Passkey

Passkey 通常分成签发注册/认证选项和校验浏览器返回值：

```text
password
  → issue(webauthn)
  → input(credential)
  → verify(passkey)
  → Done
```

调用方负责：

1. 先完成用户身份确认。
2. 通过 `issue(webauthn)` 获取浏览器选项和 state。
3. 把 state 短期保存到 `Secrets`。
4. 接收浏览器 Passkey 响应后提交给 `verify(passkey)`。
5. 通过 `Passkeys::update` 做计数器 CAS。

bridge 不保存浏览器 Session，也不决定一个用户是否必须启用 Passkey。

### 5.5 风险分支

密码校验可以返回命名路由：

```text
password
  ├── normal → audit → Done
  └── risk   → totp  → audit → Done
```

```rust
let pipeline = Pipeline::new(
    "password",
    vec![
        Node::verify("password", "password")
            .edge(Some("normal"), "audit")
            .edge(Some("risk"), "totp"),
        Node::input("totp", vec!["code".into()])
            .edge(None::<String>, "check"),
        Node::verify("check", "totp").edge(None::<String>, "audit"),
        Node::effect("audit", "audit").once(true),
    ],
);
```

路由由 Runner 返回：

```rust
Ok(Output::Pass {
    routes: vec!["risk".into()],
    data: serde_json::json!({"risk": "new_device"}),
    identity: Some(Identity::new("company", "employee-42")),
    at: now,
})
```

Pipeline 不解析脚本表达式；风险判断由调用方 Runner 或风险模块完成。

### 5.6 All 和 Any

`Join::All` 要求所有激活分支完成：

```rust
Node::effect("join", "audit").join(Join::All)
```

适合“密码和 Passkey 都必须通过”。任一分支不可重试失败，整体拒绝。

`Join::Any` 任一分支成功即可继续：

```rust
Node::effect("join", "audit").join(Join::Any)
```

适合“密码或 Passkey 任意一种通过”。只有所有分支失败时才拒绝。

### 5.7 有限重试和循环

节点重试次数由 `retries` 控制，循环节点还必须设置 `limit`：

```rust
Node::verify("captcha", "captcha.slider")
    .retries(2)
    .limit(3)
```

Pipeline 默认最多执行 128 步。存在回边但没有 `limit` 的图会在发布时被拒绝，避免配置错误造成无限执行。

## 6. 自定义 Runner

bridge 不规定用户名密码、账号查询或密码算法。调用方可以把自己的逻辑写在 Runner 中：

```rust
struct CompanyPassword;

impl Runner for CompanyPassword {
    async fn run(&self, node: &Node, context: &Context) -> halo::Result<Output> {
        let input = context.data[&node.id]
            .as_object()
            .ok_or(halo::Error::InvalidCredentials)?;
        let account = input["account"].as_str().unwrap_or_default();
        let password = input["password"].as_str().unwrap_or_default();

        if account != "alice" || password != "company-secret" {
            return Err(halo::Error::InvalidCredentials);
        }

        Ok(Output::Pass {
            routes: Vec::new(),
            data: serde_json::json!({"source": "company"}),
            identity: Some(Identity::new("company", account)),
            at: chrono::Utc::now().timestamp(),
        })
    }
}
```

自定义 Runner 可以读取节点配置：

```rust
let mode = node.args.get("mode").and_then(Value::as_str);
```

如果不支持当前节点，必须返回 `Error::Unsupported`，这样 `Fallback` 才会继续调用默认 Runner：

```rust
let runner = Fallback::new(CompanyPassword, services);
```

## 7. 自定义短信供应商

短信统一通过 `SmsSender` 门面，供应商只实现 `Sender`：

```rust
struct CompanySms;

impl Sender for CompanySms {
    fn send<'a>(
        &'a self,
        phone: &'a str,
        code: &'a str,
        ttl: u64,
    ) -> BoxFuture<'a> {
        Box::pin(async move {
            println!("send {code} to {phone}, ttl={ttl}");
            Ok(())
        })
    }
}

let sender = SmsSender::with(
    SmsConfig {
        enabled: true,
        access_key_id: "company".into(),
        access_key_secret: "company".into(),
        ..SmsConfig::default()
    },
    CompanySms,
);
```

腾讯云短信使用 API 3.0 `SendSms` 和 TC3-HMAC-SHA256。生产配置填写 `sdk_app_id`、`sign_name`、`template_code`、`access_key_id`、`access_key_secret` 和可选 `region`。开发环境可以注入 Mock `Sender`，生产环境建议启用严格发送失败策略。

社交和企业 Provider 默认使用 15 秒连接与请求超时。GitHub 可以配置 `api_endpoint`，Google 可以配置 `userinfo_endpoint`；测试环境可以通过 `timeout` 和这些端点替换默认值。

## 8. Secret、Effects 和超时

页面或 Pipeline JSON 中只保存 Secret 引用：

```rust
let reference = halo::bridge::secret("sms.tencent.secret");
```

真实值由调用方的 `Resolve` 或 Runner 从自己的密钥系统读取，不能把短信密钥、SMTP 密码、TOTP Secret 或私钥写入页面配置。

副作用节点可以配置只执行一次：

```rust
Node::effect("audit", "audit")
    .once(true)
    .idempotency("login-audit")
```

跨进程运行时，实现 `Effects`，并让 `begin` 在自己的存储中原子占用 Key。Pipeline 不绑定 Redis、数据库或具体 async runtime。节点的 `timeout` 只是策略值，真正的任务中断由调用方 runtime 执行。

## 9. Device 和 Passkey

Device 提供 RSA-SHA256 nonce 证明、启停、时间窗口和单次 nonce 消费。调用方保存设备公钥和状态，并在 Store 中实现 `save`、`find`、`update` 和 `revoke`。

Passkey 提供 WebAuthn 注册、认证、计数器 CAS 和凭证状态更新。认证 state 的单次保存和消费由调用方通过 `Secrets` 完成。

`Identity.subject`、`Device.subject` 和 `Passkey.subject` 都是调用方定义的稳定 opaque 值。bridge 只比较它们是否一致，不解释其业务含义。

## 10. 错误处理

认证请求不要把所有错误都转换成成功响应：

```rust
match pipeline.run(&mut run, &runner).await? {
    Progress::Need { node, fields, .. } => {
        // 返回下一步需要的输入字段
        println!("need {node}: {fields:?}");
    }
    Progress::Retry { node, reason } => {
        // 保留短期 Run，提示重新输入或重新执行
        println!("retry {node}: {reason}");
    }
    Progress::Deny { node, reason } => {
        // 删除 Run，记录失败审计，不签发应用 Token
        println!("deny {node}: {reason}");
    }
    Progress::Done => {
        // 由调用方查询自己的账号状态并签发应用登录结果
        println!("authenticated");
    }
}
```

未知能力码、未知路由、错误参数、非法回边和超出执行限制都会返回错误或 `Deny`。调用方应将详细错误写入内部日志，对外只返回统一的登录失败提示。

## 11. 运行示例

仓库中的示例可以直接查看完整节点组合：

```bash
cargo run --example pipeline_linear
cargo run --example pipeline_graph
cargo run --example pipeline_runner
cargo run --example pipeline_custom
cargo run --example sender_custom
```

- `pipeline_linear`：手机号验证码、密码加 TOTP、密码加 Passkey。
- `pipeline_graph`：风险分支、`Join::All` 和 `Join::Any`。
- `pipeline_runner`：调用方自动执行节点的 Runner。
- `pipeline_custom`：自定义用户名密码和 `Fallback`。
- `sender_custom`：自定义短信供应商。

## 12. 验证项目

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo bench --bench pipeline
```

`bridge` 不管理 HTTP 路由、Session、RBAC、业务用户、租户关系、组织目录和 OIDC UserInfo 端点；这些由应用层组合。
