# bridge 使用手册

本文说明如何把 `halo-bridge` 接入一个登录系统。示例中的数据库、Redis、HTTP 路由和用户查询都是调用方代码；bridge 只负责认证协议、安全材料和 Pipeline 执行。

## 1. 安装

在应用的 `Cargo.toml` 中使用包名 `halo-bridge`，代码中的库名仍然是 `halo`：

```toml
[dependencies]
# 包名是 halo-bridge，Rust 代码中的库名是 halo。
halo = { package = "halo-bridge", version = "0.4" }
```

业务代码通常从统一入口导入 bridge 的公共类型：

```rust
// 导入 bridge 对外暴露的 Pipeline、Store、Runner 和认证模型。
use halo::bridge::*;
```

默认启用完整能力。如果只需要核心 Pipeline 和密码能力，可以关闭默认 feature：

```toml
[dependencies]
# 关闭默认 full feature，只编译核心能力。
halo = { package = "halo-bridge", version = "0.4", default-features = false }
```

可选 feature 是 `mail`、`sms`、`social`、`enterprise`、`passkey` 和 `oidc`，`full` 会一次启用全部能力。`oidc` 只增加外部 OIDC Provider 的 HTTP 交换和 Discovery/JWKS 读取；服务端授权码、TokenResponse 和 PKCE 核心不依赖这个 feature。

关闭默认 feature 后，未启用的模块不会参与编译；例如没有 `sms` feature 时，短信 sender 类型不可用。

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

## 3. 这些模块分别做什么

### 3.1 Pipeline

Pipeline 是登录流程。你可以把它理解为一串可连接的步骤，例如“输入手机号 → 检查滑块 → 发送短信 → 检查短信验证码”。它负责步骤顺序、分支、重试和当前进度，不负责查询用户表，也不负责选择短信供应商。

### 3.2 生成、发送和检查

- `issuer`：生成登录过程中临时使用的内容，例如验证码题目、Passkey 浏览器验证请求和一次性链接。
- `sender`：把已经生成的验证码发送到短信或邮箱。
- `verifier`：检查用户提交的验证码、TOTP、Passkey 或协议参数是否正确。

同名能力通过模块路径区分，例如使用 `validator::issuer::Captcha` 生成验证码题目，使用 `validator::verifier::Captcha` 检查用户答案；`issuer::Passkey` 负责发起浏览器流程，`verifier::Passkey` 负责完成校验。

例如手机号登录通常拆成：

```text
手机号输入
  → 人机校验 verifier
  → 验证码 issuer
  → 短信 sender
  → 验证码 verifier
```

这里的箭头表示节点之间的执行顺序：用户输入由调用方提交，Pipeline 再把数据传给下一个节点；每个节点的具体实现由 issuer、sender 或 verifier 完成。

### 3.3 配置、默认执行器和自定义执行器

- `Cards` 是页面配置允许使用的能力清单。它描述某个能力是否存在、需要哪些参数以及参数类型。
- `Services` 是 bridge 提供的默认执行器。它把 `password`、`totp`、`sms`、`sms.send` 等能力连接到具体实现。
- `Runner` 是一次节点执行器。调用方可以实现自己的 Runner，接入自己的用户系统、风控系统或通知服务。
- `Fallback` 可以把两个 Runner 组合起来：先调用自定义 Runner，自定义 Runner 表示“不处理”时再使用默认 Services。

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
pub trait Passkeys {} // Passkey 保存和计数器条件更新
pub trait Devices {}  // Device 保存、更新和撤销
pub trait Events {}   // 审计事件写入
pub trait Limits {}   // 发送、校验频控和失败锁定
```

`State::new` 和 `Nonce::new` 只生成随机值；跨请求保存和单次消费由调用方负责。把值原样写入 `Secrets` 后，回调时使用 `State::take` 或 `Nonce::take`，它们通过 `Secrets::take_if` 原子消费，重复回调会失败。

例如，账号密码节点会调用 `Users`，短信验证码节点会调用 `Secrets`，TOTP 节点会调用 `Factors`，审计节点会调用 `Events`。这些接口只定义 bridge 需要什么数据，不规定调用方如何建表或如何使用 Redis。

这些 trait 不是数据库实现。调用方需要自行处理：

- Key 的租户、应用和平台命名空间。
- TTL、原子消费和并发更新。
- 用户是否存在、是否启用、是否被锁定。
- Passkey 计数器条件更新和 Device 一次性编号的单次消费。

### 1.1 注入频控和锁定

`Services` 默认使用 `Noop`，不会自行限制请求。需要限制时，实现 `Limits`，再通过 `.limits(store)` 注入。Pipeline 节点的 `args` 同时包含 `limit` 和 `window` 时才启用频控：

```rust
let services = Services::new(secrets, users, factors, passkeys, events, devices, notify)
    // store 由调用方实现，可以落到 Redis、数据库或其他原子计数服务。
    .limits(app_limits);

let sms = Node::issue("sms", "sms")
    // 60 秒内最多签发 5 次；失败锁定策略由 Limits::fail 决定。
    .args(serde_json::json!({ "limit": 5, "window": 60, "lock": 900 }));
```

`allow` 在签发或校验前调用。校验成功后调用 `clear` 清理连续失败记录；校验失败调用 `fail`，调用方可以递增失败次数并返回 `Decision::Deny { retry_after }`。bridge 只传递规则和结果，不保存计数、不创建锁定记录，也不添加租户字段。建议调用方把节点 ID、应用 ID、平台 ID 和租户 ID 加入自己的存储 key。

验证码失败次数必须通过 `Secrets::incr` 原子递增。刷新令牌轮换必须通过 `Secrets::claim` 原子占用旧令牌摘要；同一个旧令牌只有第一个并发请求可以成功。存储不支持这些原子操作时，相关校验会返回错误，调用方应接入 Redis、数据库原子命令或自己的等价实现。

审计事件使用 `Identity` 记录主体，不要求 `user_id` 或整数主键。账号密码等基础能力可以继续通过调用方的 `Users` 读取本地账号资料，但成功后统一输出 `Identity`；业务账号绑定、用户表和主体映射仍由调用方处理。

### 第二步：创建 Cards

管理端发布 Pipeline 前，用 `Cards` 建立“页面可以选择哪些能力”的白名单。它只负责配置校验和页面 Schema，不会启用登录方式，也不会执行登录。

```rust
use halo::bridge::{Cards, Op};

// 创建一个空的能力表。实际项目通常在应用启动时创建一次并复用。
let cards = Cards::new()
    // Verify 表示“校验已经提交的材料”。
    // 这里允许页面配置账号密码校验。
    .add(Op::Verify, "password")
    // 允许页面配置 TOTP 校验节点。
    .add(Op::Verify, "totp")
    // 允许页面配置短信验证码校验节点。
    .add(Op::Verify, "sms")
    // Issue 表示“生成或签发材料”。
    // 这里允许页面配置短信验证码签发节点。
    .add(Op::Issue, "sms")
    // Effect 表示“产生外部副作用”。
    // 这里允许页面配置短信发送节点。
    .add(Op::Effect, "sms.send")
    // 允许页面配置审计副作用节点。
    .add(Op::Effect, "audit")
    // 给 password 能力声明一个可选的字符串参数 source。
    // required=false：页面可以不填；secret=false：它不是密钥引用。
    .arg(Op::Verify, "password", "source", "string", false, false)
    // 给短信签发能力声明一个可选的场景参数 scene。
    .arg(Op::Issue, "sms", "scene", "string", false, false);

// 导出页面编辑器使用的 JSON Schema。
// 页面可以根据它显示能力、参数类型和必填关系。
let schema = cards.schema();
```

这段代码只注册“允许配置的能力”，不会生成下面这些登录流程：

```text
账号密码 → TOTP
手机号 → 滑块 → 短信签发 → 短信发送 → 短信校验
```

真正的登录顺序仍然保存在 `PipelineConfig.nodes` 中。例如，只有 PipelineConfig 中同时出现 `issue(sms)`、`effect(sms.send)` 和 `verify(sms)`，并且边把它们连接起来，登录时才会执行完整的短信流程。

每个参数的含义是：

```text
.add(op, code)
  op   ：节点类别，Input / Check / Issue / Verify / Effect
  code ：能力码，例如 password、totp、sms.send

.arg(op, code, name, kind, required, secret)
  name     ：页面参数名
  kind     ：参数类型，例如 string、integer、boolean、object
  required ：是否必须填写
  secret   ：是否只能保存为 {"$secret":"..."} 引用
```

例如，下面的配置会被 `Cards` 接受：

```json
{
  "id": "issue_sms",
  "type": "issue",
  "code": "sms",
  "args": {
    "scene": "login"
  }
}
```

如果页面提交了未注册的 `wechat` 能力、把 `scene` 写成数字，或者使用了没有声明的参数，`config.compile_with(&cards)` 会拒绝发布。

自定义能力使用 `custom.*` 命名空间：

```rust
// 只允许页面使用这个自定义能力码；具体执行仍由自定义 Runner 提供。
let cards = cards.add(Op::Verify, "custom.employee_card");
```

页面只能引用已经注册的能力码。未知能力、错误参数类型、缺少必填参数和非法边都会在发布阶段被拒绝。

### 第三步：保存并编译 PipelineConfig

调用方可以把下面的 JSON 保存到数据库的登录方式配置中。这个 JSON 是“登录流程”，不是 `Cards` 能力表：

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

字段含义：

- `version`：配置格式版本。
- `start`：第一次进入的节点 ID。
- `max_steps`：单次认证最多推进多少步。
- `nodes`：登录节点列表。
- `type`：节点职责，例如 `input`、`verify`、`issue`、`effect`。
- `code`：该职责使用的能力码，例如 `password`、`sms.send`。
- `args`：传给能力实现的页面参数。
- `edges`：当前节点完成后去哪里。

编译时校验配置：

```rust
use halo::bridge::{Pipeline, PipelineConfig};

let config: PipelineConfig = serde_json::from_str(json_text)?;
let pipeline: Pipeline = config.compile_with(&cards)?;
// 发布前预检查：Pipeline 中的能力是否都能由这个 Runner 执行。
// 这里只检查兼容性，不执行登录；真正执行使用 pipeline.run(...)。
cards.run(&pipeline, &runner)?;
```

`serde_json::from_str` 只负责把 JSON 读成 Rust 配置；`compile_with` 才会检查能力码、参数、节点 ID、边和回边；`cards.run` 再检查实际 Runner 是否支持这些能力。三个步骤都成功后，配置才适合发布。

配置发布后会生成版本和 hash。恢复旧 Run 时必须使用相同配置；新发布的配置不会接管已经开始的认证流程。

### 第四步：创建默认 Services 或自定义 Runner

如果使用 bridge 默认能力，创建 `Services` 并注入 Store：

```rust
let services = Services::new(
    secrets,       // 验证码、state、nonce 和单次凭证
    users,         // 账号和密码查询
    factors,       // TOTP 绑定查询
    passkeys,      // Passkey 查询和计数器更新
    events,        // 审计写入
    devices,       // Device 查询和更新
    notifications, // 短信和邮件发送
);
```

参数按顺序对应：临时材料、用户、TOTP、Passkey、审计事件、Device 和通知服务。`Services` 不创建这些依赖，只保存调用方传入的实现。

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

这个 Runner 做了三件事：读取当前节点输入、调用调用方自己的账号系统、返回一个统一的 `Identity`。它没有把用户写入 bridge，也没有创建 Session。

保留默认能力，同时覆盖一部分节点：

```rust
// CompanyRunner 优先处理它支持的节点，Services 处理其余内置节点。
let runner = Fallback::new(CompanyRunner, services);
```

这里的第一个参数优先处理节点；只有它返回 `Unsupported`，才由第二个参数处理。账号密码可以交给公司 Runner，短信、TOTP 和审计仍然交给默认 Services。

`Fallback` 会先调用自己的 Runner；只有返回 `Error::Unsupported` 时才交给后面的 Runner。

### 第五步：启动认证运行

登录请求开始时，调用方加载对应登录方式的 PipelineConfig，创建 `Context`，然后启动：

```rust
let context = Context {
    protocol: Some("password".into()), // 当前认证方式
    connection: Some("browser".into()), // 当前客户端平台
    ..Context::default()
};

// start 创建短期 Run，并返回第一个需要处理的节点。
let (mut run, progress) = pipeline.start(context)?;
```

`Context` 是本次认证的请求上下文。`protocol` 和 `connection` 是调用方传入的业务信息；`start` 会创建短期 `Run`，并返回当前需要处理的第一个节点。

Runner 收到的 `Context` 只包含当前节点沿流程继承的数据，不会把其他并行分支的输入一起传入。`request` 和 `meta` 也会先清理已知敏感字段。完整的流程记录仍保存在 `Run` 中，调用方不要把 `Context` 当作业务用户对象或 Session。

`Progress::Need` 表示当前节点需要调用方提供输入或执行器继续执行：

```rust
match progress {
    Progress::Need { node, kind, fields } => {
        // 根据 fields 收集用户输入，或调用 Runner 执行该节点。
        println!("node={node}, kind={kind}, fields={fields:?}");
    }
    Progress::Done => println!("already done"), // 流程已经完成
    Progress::Retry { node, reason } => println!("retry {node}: {reason}"), // 可重试
    Progress::Deny { node, reason } => println!("deny {node}: {reason}"), // 拒绝并结束
}
```

`Need` 表示还没有完成当前节点；`Retry` 表示可以按策略重新执行；`Deny` 表示流程被拒绝；只有 `Done` 才能进入调用方的登录成功处理。

### 第六步：提交用户输入

`Event::Input` 只提交当前节点的数据。提交后，调用方再次执行 Pipeline：

```rust
let progress = pipeline.resume(
    &mut run,
    Event::Input {
        node: "input".into(), // 必须是当前等待输入的节点
        data: serde_json::json!({
            "account": "alice",
            "password": "secret"
        }),
        at: chrono::Utc::now().timestamp(), // 调用方记录输入时间
    },
)?;

// 让 Runner 自动推进后续校验、签发、发送和审计节点。
let progress = pipeline.run(&mut run, &runner).await?;
```

第一段 `resume` 把账号密码交给当前 `input` 节点；第二段 `run` 让 Runner 自动推进后续节点。调用方不能跳过 `resume` 直接伪造 `Done`，也不能把一个节点的数据提交给另一个节点。

调用方只提交 `Event::Input`。`Event::Pass` 和 `Event::Fail` 是 Runner 返回给 Pipeline 的内部结果，不能用来手工把密码、TOTP、Passkey 或其他校验节点标记为通过。需要输入的 `Verify` 节点也使用 `Event::Input` 提交原始数据，提交后再调用 `run` 由 Runner 完成检查。

签发节点返回的临时材料会放在当前节点的 `run.context.data` 中。例如 Passkey 的 `options` 和 `state`、验证码的 `challenge` 都要先交给浏览器或用户，再提交后续输入。它们仍属于短期认证材料，Run 在材料未被消费前不能序列化保存；调用方应在自己的短期存储中设置 TTL。

只有 Pipeline 返回 `Done`，调用方才应该认为认证流程完成。`Retry`、`Deny` 和 `Need` 都不能签发最终登录结果。

### 第七步：保存和恢复 Run

如果登录需要跨 HTTP 请求继续，调用方保存序列化后的 Run，并设置自己的短期 TTL：

```rust
let run = run.expires_at(chrono::Utc::now().timestamp() + 300);
let encoded = serde_json::to_vec(&run)?;
// 写入调用方自己的 Redis 或数据库，并设置短 TTL。
```

序列化失败通常表示 Run 仍然包含密码、验证码、Token、state 或 nonce。正确做法是先执行或清理当前节点，再保存短期状态，而不是关闭敏感数据检查。

恢复时必须加载同一版本的 Pipeline：

```rust
// 只从调用方自己的可信短期存储读取，不接受浏览器直接提交的 Run JSON。
let mut run = pipeline.restore(&encoded, chrono::Utc::now().timestamp())?;
// 使用发布时的同一份 Pipeline 继续执行。
let progress = pipeline.run(&mut run, &runner).await?;
```

`Pipeline::restore` 会检查配置版本、hash、当前节点、就绪节点、步数和 `expires_at`。如果配置版本或 hash 不一致、状态过期或包含未知节点，bridge 会拒绝继续，避免新配置误接管旧认证流程。

`Context`、节点输入、Evidence 和 Run 中的 JSON 值有统一大小、深度、字段数和数组长度上限；超出限制的请求会在启动、提交输入或序列化时被拒绝。Provider 的原始响应也应由调用方在 HTTP 层限制响应体大小后再交给 Runner。

Run 会拒绝持久化密码、验证码、Token、state、nonce 等敏感字段。调用方仍应在存储层设置认证流程 TTL，并在登录结束、失败或取消时删除 Run。

`AuditEvent::with_metadata` 会在写入前递归删除密码、验证码、Token、Secret、state、nonce、credential 等敏感字段；业务 metadata 仍应控制大小，避免把完整 Provider 原始响应写入审计记录。

如果流程需要跨请求暂停，调用方先把当前节点展示给用户所需的 `challenge`、Passkey `options` 或 `state` 保存到自己的短期存储，然后调用 `run.clear()` 清理 Run 中的临时材料，再保存 Run。下一次提交输入时，把短期存储中的 `state` 或验证码材料放回 `Event::Input`，bridge 不替调用方保存这些内容。

## 5. 常见流程示例

### 5.1 账号密码

流程：

```text
1. 输入账号和密码
   input(account, password)
2. 校验账号密码
   verify(password)
3. 写入认证审计事件
   effect(audit)
4. Pipeline 返回 Done
```

这里的 `password` 是能力码，不是字段名。`verify(password)` 会读取上游 `input` 节点传下来的 `account` 和 `password`：

```text
input 节点
  输入：account、password
  作用：收集用户输入，不查询用户，也不判断密码

verify(password) 节点
  输入：account、password
  执行：调用方提供的 Users Store 查询账号，使用密码算法校验哈希
  结果：成功时输出 Identity，失败时返回 InvalidCredentials

effect(audit) 节点
  输入：认证结果和请求上下文
  执行：调用 Events Store 写入审计事件

Done
  含义：bridge 认证流程完成；调用方此时才签发自己的应用 Token 或创建 Session
```

节点构造：

```rust
let pipeline = Pipeline::new(
    // 从 input 节点开始执行。
    "input",
    vec![
        // 收集账号和密码；input 不查询用户，也不校验密码。
        Node::input("input", vec!["account".into(), "password".into()])
            // 没有命名 route，表示沿默认边进入 password。
            .edge(None::<String>, "password"),
        // 使用 password 能力校验上游传来的 account 和 password。
        Node::verify("password", "password").edge(None::<String>, "audit"),
        // 使用 audit effect 写入审计，并且同一个 Run 只执行一次。
        Node::effect("audit", "audit").once(true),
    ],
);
```

这三个节点分别表示：第一个节点收集账号和密码；第二个节点使用 `password` 能力校验；第三个节点写入审计。`.edge(None, "password")` 表示成功后沿默认边进入 `password` 节点。

默认 `Services` 会从调用方的 `Users` Store 查询账号并校验密码。账号表、密码哈希和密码算法由调用方保存；自定义密码算法可以实现自己的 Runner 或注入 `Codecs`。如果没有 `Users` Store，或者使用自己的账号系统，就用自定义 Runner 替换这个 `verify(password)` 节点。

内置密码算法中，Argon2id 和 Bcrypt 适合新密码；PBKDF2 和 SM3 使用带盐的固定格式，校验会拒绝超出允许范围的迭代次数，并使用常量时间比较。SM3 这里是 PBKDF2-HMAC-SM3，不是一次普通 SM3 摘要。调用方如果有国密或其他 KDF 要求，实现 `Codec` 后注册到 `Codecs`，不要把原始密码或私钥写入 Pipeline 配置。

### 5.2 手机号、滑块、短信验证码

流程：

```text
1. 输入手机号：`input(phone)`
2. 校验人机验证：`verify(captcha.slider)`
3. 生成短信验证码：`issue(sms)`
4. 发送短信：`effect(sms.send)`
5. 输入短信验证码：`input(code)`
6. 校验短信验证码：`verify(sms)`
7. 返回 `Done`
```

每一步的实际含义：

```text
input(phone)          只收集手机号
captcha.slider        读取用户提交的滑块结果并校验
issue(sms)            生成验证码并写入 Secrets
effect(sms.send)      从 Secrets 读取验证码并调用短信 Sender
input(code)           收集用户输入的短信验证码
verify(sms)           消费并校验验证码，成功后输出 Identity
Done                  调用方可以签发自己的应用登录结果
```

节点构造：

```rust
let pipeline = Pipeline::new(
    // 手机号是整个流程的起点。
    "phone",
    vec![
        // 收集用户输入的手机号。
        Node::input("phone", vec!["phone".into()])
            // 默认进入 captcha 节点。
            .edge(None::<String>, "captcha"),
        // 校验滑块结果；通过后进入短信签发。
        Node::verify("captcha", "captcha.slider")
            .edge(None::<String>, "issue"),
        // 生成短信验证码并把短期材料写入 Secrets。
        Node::issue("issue", "sms")
            .edge(None::<String>, "send"),
        // 从 Secrets 读取验证码并调用短信 Sender。
        Node::effect("send", "sms.send")
            .edge(None::<String>, "code"),
        // 收集用户输入的短信验证码。
        Node::input("code", vec!["code".into()])
            // 默认进入短信校验节点。
            .edge(None::<String>, "check"),
        // 消费并校验短信验证码，成功后输出 Identity。
        Node::verify("check", "sms"),
    ],
);
```

这段配置把业务步骤和能力职责一一对应：

- `phone` 是用户输入节点。
- `captcha` 是人机校验节点。
- `issue` 生成短信验证码，但不发送短信。
- `send` 执行短信发送副作用。
- `code` 是用户输入节点。
- `check` 消费并校验短信验证码。

这里的职责是分开的：验证码由 issuer 生成，短信由 sender 发送，短信验证码由 verifier 校验。生产环境的验证码 Key、手机号归属和频控由调用方 Store 决定。

### 5.3 密码加 TOTP

流程：

```text
1. 输入账号密码：`input(account, password)`
2. 校验账号密码：`verify(password)`
3. 输入动态码：`input(code)`
4. 校验 TOTP：`verify(totp)`
5. 返回 `Done`
```

这里先由密码节点建立身份，再由 `Factors` Store 按这个身份读取 TOTP 绑定。TOTP 校验成功后才算整个 Pipeline 完成；仅密码校验成功不能直接签发最终登录结果。

TOTP Secret 不由 bridge 保存。`Factors` Store 根据调用方身份返回绑定信息，调用方负责 Secret 加密、轮换和解绑。

TOTP 默认使用 SHA-1、6 位、30 秒周期和前后各一个时间步长的容错。需要其他标准参数时，调用方使用 `pkg::totp::Config` 配置 SHA-256/SHA-512、位数、周期和窗口；Secret 仍由调用方绑定和保存。

```rust
let pipeline = Pipeline::new(
    // 先从账号密码开始。
    "input",
    vec![
        // 收集账号和密码。
        Node::input("input", vec!["account".into(), "password".into()])
            // 密码成功后继续进入 TOTP。
            .edge(None::<String>, "password"),
        // 校验账号密码，成功时把身份传给 totp。
        Node::verify("password", "password").edge(None::<String>, "totp"),
        // 收集用户输入的动态码。
        Node::input("totp", vec!["code".into()])
            // 默认进入 check 节点。
            .edge(None::<String>, "check"),
        // 读取 Factors Store 中的 Secret 并校验 TOTP。
        Node::verify("check", "totp"),
    ],
);
```

这里 `password` 节点成功后把身份传给 `totp` 节点。`totp` 输入节点只收集动态码，`check` 节点才读取 TOTP Secret 并校验动态码。

### 5.4 密码加 Passkey

Passkey 使用两个独立类型：`validator::issuer::Passkey` 负责发起，`validator::verifier::Passkey` 负责完成校验。

Passkey 通常分成签发注册/认证选项和校验浏览器返回值：

```text
1. 已有身份进入 Passkey：`issue(webauthn)`
2. 把浏览器返回值提交给：`input(credential)`
3. 校验浏览器凭证：`verify(passkey)`
4. 返回 `Done`
```

`issue(webauthn)` 只生成浏览器需要的选项和 state；它不是校验。`verify(passkey)` 才会验证签名、浏览器返回的请求数据、凭证 ID 和计数器，并把新的计数器交给 `Passkeys::update` 保存。两个步骤由不同的 Passkey 类型提供。

调用方负责：

1. 先完成用户身份确认。
2. 通过 `issue(webauthn)` 获取浏览器选项和 state。
3. 把 state 短期保存到 `Secrets`。
4. 接收浏览器 Passkey 响应后提交给 `verify_once(passkey)`，让 bridge 用 `Secrets::take_if` 原子消费状态。
5. 通过 `Passkeys::update` 做计数器条件更新。

因此，`issue(webauthn)` 的结果需要返回给浏览器，浏览器返回的 credential 再由调用方提交给 `input(credential)`；这两个请求之间的 state 由调用方短期保存。直接使用 `verify` 或 `register` 时，调用方必须自己完成同样的单次消费；更安全的入口是 `verify_once` 和 `register_once`。

bridge 不保存浏览器 Session，也不决定一个用户是否必须启用 Passkey。

### 5.5 风险分支

密码校验可以返回命名路由：

```text
1. `verify(password)` 校验成功后返回一个 route
2. `normal` 路由：写审计并完成
3. `risk` 路由：先输入并校验 TOTP，再写审计并完成
```

```rust
let pipeline = Pipeline::new(
    // 密码校验是风险路由的起点。
    "password",
    vec![
        // normal 和 risk 是 Runner 返回的命名 route。
        Node::verify("password", "password")
            // 普通风险直接进入审计。
            .edge(Some("normal"), "audit")
            // 高风险先进入 TOTP 节点。
            .edge(Some("risk"), "totp"),
        // 收集高风险分支需要的动态码。
        Node::input("totp", vec!["code".into()])
            // 默认进入 TOTP 校验。
            .edge(None::<String>, "check"),
        // 只有 risk 路由会激活这个节点。
        Node::verify("check", "totp").edge(None::<String>, "audit"),
        // 记录审计；一次 Run 中只记录一次。
        Node::effect("audit", "audit").once(true),
    ],
);
```

这里的两条 `edge` 是命名路由：密码 Runner 返回 `normal` 时直接到审计；返回 `risk` 时进入 TOTP。没有返回的分支不会被激活。

路由由 Runner 返回：

```rust
Ok(Output::Pass {
    routes: vec!["risk".into()], // 选择 password 节点上的 risk 边
    data: serde_json::json!({"risk": "new_device"}), // 传给下游节点
    identity: Some(Identity::new("company", "employee-42")), // 建立或确认身份
    at: now, // 结果时间
})
```

`routes` 决定下一步走哪条边，`data` 是传给下游节点的数据，`identity` 是认证成功后建立或确认的身份，`at` 是结果时间。Pipeline 不解释 `risk` 的业务含义。

Pipeline 不解析脚本表达式；风险判断由调用方 Runner 或风险模块完成。

一个事件返回多个 `routes` 时，Pipeline 会把这些分支加入同一个 `Run` 的就绪队列，并按队列顺序逐个交给 Runner 执行；它不会在内部并发调用 Runner。调用方如果要并发处理互不相关的登录运行，应在自己的 runtime 中并发执行多个 `Run`，单个 `Run` 的状态更新仍需串行保存。

如果希望使用 bridge 内置的风险评分，可以把 `RiskEngine` 注入 `Services`，并使用 `check("risk")` 节点：

```rust
let services = Services::new(secrets, users, factors, passkeys, events, devices, notify)
    .risk(RiskEngine::new(RiskConfig::default()));

// input 节点提交 { "context": RiskContext, "history": UserHistory }。
let risk = Node::check("risk", "risk")
    .edge(Some("allow"), "normal")
    .edge(Some("mfa"), "totp")
    .edge(Some("block"), "blocked");
```

风险节点只读取调用方提交的当前请求和历史摘要，返回 `allow`、`mfa` 或 `block` 路由以及 `RiskAssessment`。它不查询用户、不保存历史、不创建锁定记录；历史数据和后续 TOTP、验证码或拒绝处理仍由调用方配置。

### 5.6 All 和 Any

`Join::All` 要求所有激活分支完成。它表示“每一条被激活的认证路径都必须成功”：

```rust
// join 是汇聚节点：所有已激活分支都成功后才执行 audit。
Node::effect("join", "audit").join(Join::All)
```

`join(Join::All)` 配置在汇聚节点上；只有前面所有已激活分支都到达这个节点，它才会执行。

适合“密码和 Passkey 都必须通过”。任一分支不可重试失败，整体拒绝。

`Join::Any` 任一分支成功即可继续。它表示“密码或 Passkey 任意一种通过即可”：

```rust
// join 是汇聚节点：任意一条已激活分支成功后即可执行 audit。
Node::effect("join", "audit").join(Join::Any)
```

`join(Join::Any)` 允许任意一条已激活分支成功后继续，其他尚未完成的备用分支会被取消。

适合“密码或 Passkey 任意一种通过”。只有所有分支失败时才拒绝。

### 5.7 有限重试和循环

节点重试次数由 `retries` 控制，循环节点还必须设置 `limit`。例如下面表示最多向 Runner 重试两次，同时整个节点最多进入三次：

```rust
// retries 控制 Runner 失败后的重试次数。
// limit 控制这个节点在整个图中的最大进入次数。
Node::verify("captcha", "captcha.slider")
    .retries(2)
    .limit(3)
```

`retries(2)` 是交给 Runner 的失败重试次数；`limit(3)` 是节点在整个图运行期间允许被激活的次数。两者用途不同，循环节点不能只设置 retries。

Pipeline 默认最多执行 128 步。存在回边但没有 `limit` 的图会在发布时被拒绝，避免配置错误造成无限执行。

Pipeline 的基础模型是有向图：没有回边时就是 DAG；需要重试或循环时可以配置带 `limit` 的回边。也就是说，bridge 不把所有流程强行限制成严格 DAG，但任何回边都必须有节点次数上限和全局步数上限。

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
            routes: Vec::new(), // 不选择命名分支，沿默认边继续
            data: serde_json::json!({"source": "company"}), // 传给下游节点
            identity: Some(Identity::new("company", account)), // 认证成功后的身份
            at: chrono::Utc::now().timestamp(), // 结果时间
        })
    }
}
```

`node.id` 用来读取当前节点的数据，`account` 和 `password` 是调用方自己约定的字段。成功返回 `Identity` 后，后续节点可以继续使用这份身份；失败返回 `InvalidCredentials`，Pipeline 会按节点策略处理。

自定义 Runner 可以读取节点配置：

```rust
// node.args 是发布配置中的非敏感参数。
let mode = node.args.get("mode").and_then(Value::as_str);
```

`node.args` 来自管理端保存的 PipelineConfig。它适合保存非敏感的行为参数；密钥、密码和 Token 应保存为 Secret 引用，由调用方解析。

如果不支持当前节点，必须返回 `Error::Unsupported`，这样 `Fallback` 才会继续调用默认 Runner：

```rust
// 把自定义 Runner 和默认 Services 组合成一个执行器。
let runner = Fallback::new(CompanyPassword, services);
```

这个组合不会复制一套登录流程，只替换节点执行者。Pipeline 仍然由同一份配置驱动。

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
            // 这里替换成调用方自己的短信 API、签名和错误处理。
            println!("send {code} to {phone}, ttl={ttl}");
            Ok(())
        })
    }
}

let sender = SmsSender::with(
    SmsConfig {
        enabled: true, // 开启发送通道
        access_key_id: "company".into(),
        access_key_secret: "company".into(),
        ..SmsConfig::default()
    },
    CompanySms,
);
```

`Sender::send` 只关心目标手机号、验证码和有效期；供应商鉴权、请求签名和 HTTP 调用都封装在调用方实现里。`SmsSender::with` 把这个供应商接入统一短信门面，Pipeline 不需要知道供应商名称。

邮件也使用同样的替换边界。实现 `validator::sender::mail::Sender`，再通过 `SmtpSender::with` 注入；接口接收目标地址、主题、HTML 和纯文本，调用方可以接入自己的邮件 API、队列或内网服务，不需要改动 `Notify` 和 Pipeline。

腾讯云短信使用 API 3.0 `SendSms` 和 TC3-HMAC-SHA256。生产配置填写 `sdk_app_id`、`sign_name`、`template_code`、`access_key_id`、`access_key_secret` 和可选 `region`。开发环境可以注入 Mock `Sender`，生产环境建议启用严格发送失败策略。

社交和企业 Provider 默认使用 15 秒连接与请求超时。GitHub 可以通过 `auth` 和 `api` 替换授权与 API 地址，Google 可以通过 `auth` 和 `userinfo` 替换授权与用户资料地址；测试环境可以通过 `timeout` 和这些端点替换默认值。

Provider 的网络连接失败、请求超时和 HTTP 5xx 会返回 `Error::Transient`，Pipeline 可以按节点 `retries` 重试；授权码无效、字段缺失、签名不匹配和其他业务拒绝返回 `Error::OAuthError`，不会被自动重试。Provider 会校验必要的 access token、subject、openid、用户资料字段和 OIDC Discovery/JWKS 字段，响应格式错误直接失败。

Provider 模块负责协议链路：生成授权地址、使用 code 换 token、读取第三方资料并转换成标准 Profile。它们不会自动注册到默认 `Services`，也不会自动绑定本地用户。要把微信、GitHub、Google、飞书、企业微信或钉钉放进 Pipeline，调用方需要实现一个 Runner：

1. 从自己的配置读取 Provider 的 client ID、Secret 和 redirect URI。
2. 在授权开始前生成并保存 state，OIDC/OAuth 场景按协议保存 PKCE verifier。
3. 回调时调用 Provider 的 code 交换方法，并校验 state、redirect URI 和错误响应。
4. 把 Provider 返回的 Profile 转成 `Identity`，或由调用方完成自己的账号绑定。
5. 返回 `Output::Pass`，让 Pipeline 继续后续审计、TOTP 或应用结果节点。

外部 OIDC Provider 的最小用法如下：

```rust
use halo::factor::oidc::{Config, Provider};

let provider = Provider::new(Config {
    issuer: "https://login.example".into(),
    client_id: "bridge-client".into(),
    client_secret: "secret".into(),
    scope: Some("openid profile email".into()),
    authorization_endpoint: None,
    token_endpoint: None,
    discovery_endpoint: None,
    jwks_endpoint: None,
});

// state、nonce 和 PKCE verifier 必须由调用方短期保存，并在回调时单次消费。
let login_url = provider.authorize_url(
    "state-from-your-store",
    "https://app.example/oidc/callback",
    Some("nonce-from-your-store"),
    Some("pkce-code-challenge"),
    Some("S256"),
)?;

// 回调时会读取 Discovery/JWKS、兑换 code，并校验 issuer、audience、过期时间和 nonce。
let profile = provider
    .exchange_code_for_profile(
        "code-from-callback",
        "https://app.example/oidc/callback",
        Some("pkce-code-verifier"),
        Some("nonce-from-your-store"),
    )
    .await?;
let identity = profile.identity();
```

这段代码不会创建本地用户，也不会保存第三方 access token。`profile.identity()` 只返回 `Identity { provider, subject, ... }`；调用方决定是否绑定已有账号、创建业务账号、要求二次验证或建立 Session。Provider 只接受 RS256 且要求 Discovery 返回的 `issuer`、`kid`、`audience`、有效期和 nonce 全部匹配。

因此，“Provider 能换到第三方身份”和“业务登录流程允许这个身份源”是两个步骤；后者由调用方 Runner 和 PipelineConfig 决定。

仓库中的 `examples/provider_pipeline.rs` 展示了 GitHub Profile 进入 Pipeline 后继续执行的最小 Runner。`tests/provider_pipeline.rs` 还覆盖了 state 校验、后续因子和身份不一致拒绝。

一个 GitHub 登录节点的完整数据流可以这样理解：

```text
input(code, state, redirect_uri)
  → verify(custom.github)
      读取当前节点 payload
      校验 state / PKCE
      调用 Github::exchange_code_for_profile
      把 SocialProfile 转成 Identity
      返回 Output::Pass
  → 后续审计、TOTP 或完成节点
  → Done
```

示例 Runner（`AppSecrets::take_state` 是调用方自己的封装，实际项目按自己的 Store 实现）：

```rust
struct GithubLogin {
    provider: Github,
    // 调用方自己的 Secrets 实现，用来保存和消费 state / PKCE。
    secrets: AppSecrets,
}

impl Runner for GithubLogin {
    async fn run(&self, node: &Node, context: &Context) -> halo::Result<Output> {
        // 当前节点的 payload 来自上一个 input 节点。
        let data = context
            .data
            .get(&node.id)
            .and_then(serde_json::Value::as_object)
            .ok_or(halo::Error::AuthFailed("Missing GitHub input".into()))?;
        let code = data
            .get("code")
            .and_then(serde_json::Value::as_str)
            .ok_or(halo::Error::AuthFailed("Missing GitHub code".into()))?;
        let state = data
            .get("state")
            .and_then(serde_json::Value::as_str)
            .ok_or(halo::Error::AuthFailed("Missing GitHub state".into()))?;
        let redirect_uri = data
            .get("redirect_uri")
            .and_then(serde_json::Value::as_str)
            .ok_or(halo::Error::AuthFailed("Missing redirect URI".into()))?;

        // 先用调用方自己的 Secrets 校验并单次消费 state / PKCE。
        self.secrets.take_state(state).await?;

        // Provider 只负责第三方协议，不查询本地用户，也不做账号绑定。
        let profile = self
            .provider
            .exchange_code_for_profile(code, redirect_uri)
            .await?;
        let identity: Identity = profile.clone().into();

        Ok(Output::Pass {
            routes: Vec::new(),
            // 只把后续流程需要的资料交给 Pipeline，不把 access_token 放进去。
            data: serde_json::to_value(profile)?,
            identity: Some(identity),
            at: chrono::Utc::now().timestamp(),
        })
    }
}
```

这个 Runner 返回 `Output::Pass` 后，Pipeline 只负责继续执行后续节点。调用方在 `Done` 之后自行决定：

- 使用 `Identity.provider` 和 `Identity.subject` 查询自己的账号。
- 没有绑定时创建业务账号，或要求用户确认绑定。
- 保存第三方资料到自己的表。
- 签发应用 Token 或创建 Session。
- 拒绝登录、记录审计或进入二次验证。

这些动作都不属于 Provider，也不属于 bridge 的默认 Services。

## 8. Secret、Effects 和超时

页面或 Pipeline JSON 中只保存 Secret 引用：

```rust
// 只生成 Secret 引用，不读取也不暴露真实密钥。
let reference = halo::bridge::secret("sms.tencent.secret");
```

这段代码生成的是配置引用，例如 `{"$secret":"sms.tencent.secret"}`，不是读取真实密钥。真实值由调用方的 `Resolve` 或 Runner 从环境变量、密钥服务或数据库读取。

真实值由调用方的 `Resolve` 或 Runner 从自己的密钥系统读取，不能把短信密钥、SMTP 密码、TOTP Secret 或私钥写入页面配置。

副作用节点可以配置只执行一次：

```rust
// once 防止同一个 Run 重复写审计。
// idempotency 用于调用方跨进程 Effects 存储的幂等 Key。
Node::effect("audit", "audit")
    .once(true)
    .idempotency("login-audit")
```

`once(true)` 让同一个 Run 不重复执行该副作用，`idempotency` 则提供跨进程幂等 Key。审计、短信发送、邮件发送等有外部影响的节点应考虑这两个字段。

跨进程运行时，实现 `Effects`，并让 `begin(key, timeout)` 在自己的存储中原子占用 Key。返回 `New { lease }` 表示当前进程拿到执行租约，返回 `Busy` 表示其他进程仍在执行，返回 `Done` 表示已经有完成结果。存储必须把 `timeout` 写入租约过期时间，进程崩溃后才能重新接管；`complete(key, lease, effect)` 和 `cancel(key, lease)` 只能由持有相同 lease 的执行者成功。Pipeline 不绑定 Redis、数据库或具体 async runtime。

节点的 `timeout` 会作为副作用租约时长，并在 Runner 返回后检查已用时间。要中断一个一直不返回的异步任务，调用方仍需在自己的 runtime 中包裹 Runner；bridge 不持有 runtime，也不会替调用方取消任务。没有配置节点 `timeout` 时，副作用租约默认 60 秒。`retries` 只对 Runner 返回的可重试存储、网络和通知错误计数，超过次数后流程进入 `Deny`。

一个 `Effects` 存储至少要保证：同一个 key 只能有一个有效 lease；过期 lease 可以被新执行接管；旧 lease 不能提交 `complete` 或 `cancel`；完成结果在后续重复执行时返回 `Done`。这套规则由调用方在 Redis、数据库或其他原子存储中实现。

## 9. Device 和 Passkey

Device 提供 RSA-SHA256 nonce 证明、启停、时间窗口和单次 nonce 消费。调用方保存设备公钥和状态，并在 Store 中实现 `save`、`find`、`update` 和 `revoke`。

Passkey 提供 WebAuthn 注册、认证、计数器条件更新和凭证状态更新。认证 state 的单次保存和消费由调用方通过 `Secrets` 完成。

SAML 响应必须使用 `SamlAuth::check` 或 `SamlAuth::check_state`，并传入调用方实现的原子重放缓存。没有重放缓存的校验入口不提供，避免同一断言被重复接受。需要身份时使用 `identity`，它同样要求重放缓存。

Token 撤销记录只使用 Token 的摘要作为存储键，不把完整 Token 写入 `Secrets` 的键名。调用方仍负责给撤销记录设置与 Token 剩余有效期一致的 TTL。

LDAP 配置支持 `timeout`，单位为秒，默认 8 秒，用于限制连接和 LDAP 操作等待时间。

`Identity.subject`、`Device.subject` 和 `Passkey.subject` 都是调用方定义的稳定身份标识。bridge 只比较它们是否一致，不解释它们在业务中的含义。

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
# 运行线性认证流程示例。
cargo run --example pipeline_linear
# 运行风险分支和 All/Any 示例。
cargo run --example pipeline_graph
# 运行自动执行节点的 Runner 示例。
cargo run --example pipeline_runner
# 运行自定义认证和 Fallback 示例。
cargo run --example pipeline_custom
# 运行自定义短信供应商示例。
cargo run --example sender_custom
```

这些命令都在 bridge 仓库根目录执行；它们只演示 Pipeline 和能力组合，不会连接真实用户库或真实短信网关。

- `pipeline_linear`：手机号验证码、密码加 TOTP、密码加 Passkey。
- `pipeline_graph`：风险分支、`Join::All` 和 `Join::Any`。
- `pipeline_runner`：调用方自动执行节点的 Runner。
- `pipeline_custom`：自定义用户名密码和 `Fallback`。
- `sender_custom`：自定义短信供应商。

## 12. 验证项目

```bash
# 检查 Rust 格式。
cargo fmt --all -- --check
# 检查 workspace 编译。
cargo check --workspace
# 执行全部测试。
cargo test --workspace --all-targets
# 执行严格 Clippy 检查。
cargo clippy --all-targets --all-features -- -D warnings
# 执行 Pipeline 基准。
cargo bench --bench pipeline
# 执行密码、TOTP、Token、Provider 和 Sender 基准。
cargo bench --bench security
```

- `fmt`：检查 Rust 格式。
- `check`：检查 workspace 是否能够编译。
- `test`：执行 Pipeline、协议、Provider 和存储契约测试。
- `clippy`：检查命名、错误处理和 Rust 代码质量。
- `bench`：测量 Pipeline 状态推进性能，不代表外部短信、数据库或网络耗时。

`bridge` 不管理 HTTP 路由、Session、RBAC、业务用户、租户关系、组织目录和 OIDC UserInfo 端点；这些由应用层组合。

## 13. 注册、取消和数据边界

`Cards::add`、`Cards::arg` 和 `Cards::version` 是公开的能力注册接口。应用启动时把内置能力和自己的 `custom.*` 能力加入 `Cards`，发布配置时调用 `compile_with`；未知能力、未知参数、类型不匹配或版本不一致都会被拒绝。`Cards` 只描述允许配置什么，不执行节点。

`Services` 只绑定固定内置能力码。调用方扩展或替换单个能力时实现自己的 `Runner`，再使用 `Fallback::new(custom, services)` 组合，不需要复制整个 `Services`。自定义 Runner 返回 `Error::Unsupported` 时才会回退；业务拒绝和临时错误会原样返回。每次登录只加载已经发布的 Pipeline，能力表在应用启动时建立。

节点 `timeout` 是 bridge 对节点结果的超时判定。调用方可以使用 `Pipeline::execute_until` 传入自己的 `deadline` 和取消信号；方法只在节点开始前和结束后检查边界，真正的网络请求中断由调用方运行时取消外层 future。带 `once` 或 `idempotency` 的副作用节点使用 `Effects` 租约，调用方存储负责原子占用、完成、取消和过期接管。

`Context`、节点输入、Evidence 和可恢复 `Run` 有 JSON 大小、深度、字段数和字符串长度限制；Provider JSON 使用 `pkg::http::json` 限制响应体大小。对有明确类型边界的 API，使用 `Sensitive<T>` 标记密码、验证码、Token 和 Secret；JSON 状态仍会执行字段清理，作为最后一道保护。持久化 Run 前调用 `Run::clear`，并由调用方存储设置 TTL。

风险节点统一读取 `RiskContext` 和 `UserHistory`，输出 `allow`、`mfa` 或 `block` 路由；调用方可以把 `mfa` 接到 TOTP、Passkey 或短信节点。频控和锁定统一使用 `limit`、`window`、`lock` 与 `Limits` trait；验证成功清除失败计数，失败交给 `Limits::fail` 决定是否锁定。重认证由 `rules::Reauth` 表达，身份、租户和策略存储仍由调用方负责。
