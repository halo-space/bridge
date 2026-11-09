# bridge 使用手册

## 安装

```toml
[dependencies]
halo = { package = "halo-bridge", version = "0.4" }
```

统一入口是：

```rust
use halo::bridge::*;
```

## 边界和责任

bridge 是认证协议和安全材料库，不是完整的登录业务系统。可以按下面的边界理解：

| bridge 提供 | 调用方提供 |
| --- | --- |
| 密码、验证码、TOTP、Passkey、Device、OIDC、社交和企业协议实现 | 用户、账号、租户、应用和组织数据 |
| issuer、sender、verifier 和可选的 `Services` | `Users`、`Clients`、`Factors`、`Passkeys`、`Devices`、`Secrets`、`Events` 的具体存储 |
| Pipeline 图状态、路由、分支、重试、拒绝和暂停恢复 | Pipeline 配置的保存、发布、版本管理和登录请求加载 |
| `Identity`、Token、审计事件等标准模型 | HTTP 路由、登录页面、业务账号绑定和最终应用会话 |
| Store、Runner、Effects 等扩展契约 | 数据库、缓存、跨进程原子操作、异步超时和通知服务配置 |

bridge 不维护本地用户，也不自动添加 MFA。是否先做密码、再做人机校验、短信、TOTP 或 Passkey，完全由调用方保存的 Pipeline 节点决定。bridge 只按配置执行节点，并把节点需要的输入、身份和结果交回调用方。

调用方还负责业务安全边界：把租户、应用或平台编码进自己的存储 Key；在查询设备、Passkey、验证码和临时凭证时完成业务范围校验；为 Magic Link 的 `redirect_to` 配置允许域名；决定认证完成后如何签发应用 Token 或建立会话。

一次登录的完整生命周期是：

1. 应用启动时创建 Store、`Cards`、`Runner` 和可选的 `Services`。`Services` 内部能力表只绑定 `code` 到实现，不保存登录流程。
2. 管理端保存登录方式对应的 `PipelineConfig` JSON。发布时用 `Cards` 校验节点、能力码、参数和边。
3. 登录请求到达时，调用方加载对应配置并编译成 `Pipeline`，创建 `Context` 后调用 `start`。
4. 调用方把用户输入通过 `resume` 提交；Pipeline 遇到可执行节点时，`Runner` 根据能力码调用密码、验证码、发送、TOTP、Passkey 等实现。
5. 如果需要跨请求恢复，调用方保存 `Run`；如果需要跨进程副作用幂等，调用方实现 `Effects`。Pipeline 返回 `Done` 后，调用方再完成自己的登录结果处理。

因此，页面配置决定“这次登录走哪些步骤”，`Cards` 决定“配置是否合法”，`Services` 能力表决定“内置能力码由哪个实现处理”，调用方的 `Runner` 决定“自定义能力如何执行”。

## Pipeline 基本用法

Pipeline 只负责节点图、状态、路由、汇聚、重试和暂停恢复。用户输入通过 `Event::Input` 提交，节点执行通过 `Runner` 提供。

页面配置使用固定能力码。自定义能力使用 `custom.*` 命名空间，例如 `custom.card`；页面只能引用已经注册的能力码。

配置先编译校验，再创建 Pipeline：

```rust
use halo::bridge::{Cards, Op, Pipeline, PipelineConfig};

let config: PipelineConfig = serde_json::from_str(json_text)?;
let cards = Cards::new()
    .add(Op::Verify, "password")
    .add(Op::Verify, "custom.card");
let pipeline: Pipeline = config.compile_with(&cards)?;
let page_schema = cards.schema();
```

创建 Runner 后调用 `cards.validate_runner(&pipeline, &runner)`，发布前即可检查实现和版本。

页面配置使用 `type`、`code` 和 `args`：

```json
{
  "version": 1,
  "start": "input",
  "nodes": [
    {
      "id": "input",
      "type": "input",
      "fields": ["username", "password"],
      "edges": [{"to": "password"}]
    },
    {
      "id": "password",
      "type": "verify",
      "code": "password",
      "args": {"source": "company"}
    }
  ]
}
```

`code` 只代表约定的能力，具体实现仍由调用方的 `Runner` 提供。`args` 会保存在节点上，用户实现可以通过 `node.args` 读取。

`PipelineConfig` 是业务侧保存并在登录时加载的流程数据；`Services` 创建时会建立内置能力表，把 `password`、`totp`、`sms`、`sms.send`、`passkey` 等能力码绑定到对应实现。能力表不保存用户流程，也不替代 Pipeline 配置。每次登录按配置读取节点，再根据能力码找到实现执行。

需要使用密钥时只保存引用，不把真实值写入页面配置：

```rust
let value = halo::bridge::secret("sms.tencent.secret");
```

应用层 Runner 负责根据这个引用从自己的密钥系统读取真实值。

`Run` 会保存配置版本和 hash。恢复运行时必须使用同一份 Pipeline，配置重新发布后不会接管旧流程。

Effect 节点可以配置 `once: true`，同一个持久化 Run 中只执行一次，适合审计、通知和发送类副作用。

节点还可以配置 `timeout`、`retries` 和 `idempotency`。Pipeline 会限制 Runner 的重试次数；超时由调用方的 async runtime 控制。需要跨进程保证副作用只执行一次时，实现 `Effects` 并调用 `run_with`，由 `begin` 的原子占用和 `complete` 保存结果。

```rust
use halo::bridge::{Context, Event, Node, Pipeline, Progress};

let pipeline = Pipeline::new(
    "input",
    vec![
        Node::input("input", vec!["username".into(), "password".into()])
            .edge(None::<String>, "password"),
        Node::verify("password", "password"),
    ],
);

let (mut run, progress) = pipeline.start(Context::default())?;

let progress = pipeline.resume(
    &mut run,
    Event::Input {
        node: "input".into(),
        data: serde_json::json!({
            "username": "alice",
            "password": "secret"
        }),
        at: 1,
    },
)?;
```

`resume` 只提交输入或外部事件；`run` 自动推进当前可以执行的节点：

```rust
let progress = pipeline.run(&mut run, &runner).await?;
match progress {
    Progress::Need { node, fields, .. } => {
        // 收集 node 需要的用户输入
        println!("need {node}: {fields:?}");
    }
    Progress::Done => println!("authenticated"),
    Progress::Retry { node, reason } => println!("retry {node}: {reason}"),
    Progress::Deny { node, reason } => println!("deny {node}: {reason}"),
}
```

## 自定义认证方式

bridge 不规定用户名密码、账号查询或密码算法。用户可以实现自己的 `Runner`，节点字段和认证逻辑完全由调用方决定。

```rust
use halo::bridge::{Context, Node, Output, Runner};

struct CompanyPassword;

impl Runner for CompanyPassword {
    async fn run(&self, node: &Node, context: &Context) -> halo::Result<Output> {
        let input = context.data[&node.id].as_object().unwrap();
        let username = input["username"].as_str().unwrap();
        let password = input["password"].as_str().unwrap();

        if username != "alice" || password != "company-secret" {
            return Err(halo::Error::InvalidCredentials);
        }

        Ok(Output::Pass {
            routes: Vec::new(),
            data: serde_json::json!({ "source": "company" }),
            identity: Some(halo::bridge::Identity::new("company", username)),
            at: 1,
        })
    }
}
```

Rust 没有传统继承，扩展使用 trait 和组合。`Fallback` 会优先执行用户实现，用户实现返回不支持时才回退到 bridge 默认实现：

```rust
let runner = halo::bridge::Fallback::new(CompanyPassword, default_runner);
```

用户可以覆盖与 bridge 相同的节点类型，也可以增加新的社交、企业或业务节点。

## 自定义短信供应商

短信统一经过 `SmsSender` 门面。供应商只需要实现 `Sender`：

```rust
use halo::bridge::{BoxFuture, Sender, SmsConfig, SmsSender};

struct CompanySms;

impl Sender for CompanySms {
    fn send<'a>(&'a self, phone: &'a str, code: &'a str, ttl: u64) -> BoxFuture<'a> {
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

内置腾讯云短信使用 API 3.0 `SendSms` 和 TC3-HMAC-SHA256。配置时填写 `sdk_app_id`、`sign_name`、`template_code`、`access_key_id`、`access_key_secret`，需要指定地域时填写 `region`。

社交和企业 Provider 默认使用 15 秒连接与请求超时。GitHub 可以分别配置 API 地址，Google 可以配置 UserInfo 地址；测试环境或兼容服务可通过 `api_endpoint`、`userinfo_endpoint` 和 `timeout` 替换默认值。

## 默认 Services

`Services` 是 bridge 提供的可选默认适配器，可以直接接入验证码、短信、邮箱、密码、TOTP、Passkey、Device 和审计节点。

它不是能力边界。用户可以完全不用 `Services`，也可以使用 `Fallback` 覆盖其中任意节点。

应用层需要实现存储契约：

```rust
pub trait Users {}
pub trait Clients {}
pub trait Secrets {}
pub trait Factors {}
pub trait Passkeys {}
pub trait Devices {}
pub trait Events {}
pub trait Limits {}
```

这些 trait 不是 bridge 内置数据库。调用方需要实现实际读写，并负责业务命名空间、过期策略和并发语义；例如验证码高并发失败计数可以在 `Secrets::incr` 中接入 Redis 原子递增。bridge 不提供数据库、缓存、业务用户、Session、权限或组织目录实现。

## Device 和 Passkey

Device 提供 RSA-SHA256 nonce 证明、启停、时间窗口和单次 nonce 消费。应用层负责保存设备公钥和设备状态。

Passkey 提供 WebAuthn 注册、认证、计数器 CAS 和凭证状态更新。认证 state 的单次保存和消费由调用方使用 `Secrets` 完成。

Passkey 的 `subject`、Device 的 `subject` 和 `Identity.subject` 都是调用方定义的稳定 opaque 值。bridge 只比较它们是否一致，不解释其业务含义。

## 运行示例

```bash
cargo run --example pipeline_linear
cargo run --example pipeline_graph
cargo run --example pipeline_runner
cargo run --example pipeline_custom
cargo run --example sender_custom
```

- `pipeline_linear`：线性验证码、TOTP、Passkey 图
- `pipeline_graph`：风险分支和 All/Any 汇聚
- `pipeline_runner`：自定义 Runner
- `pipeline_custom`：自定义用户名密码并覆盖默认节点
- `sender_custom`：自定义短信供应商

## 验证项目

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo bench --bench pipeline
```

`bridge` 不管理 HTTP 路由、Session、RBAC、业务用户和 OIDC UserInfo 端点；这些由应用层组合。
