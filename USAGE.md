# bridge 使用手册

## 安装

```toml
[dependencies]
halo = { package = "halo-bridge", version = "0.3" }
```

统一入口是：

```rust
use halo::bridge::*;
```

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
```

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
            return Err(halo::IdpError::InvalidCredentials);
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

bridge 不提供数据库、缓存、业务用户、Session、权限或组织目录实现。

## Device 和 Passkey

Device 提供 RSA-SHA256 nonce 证明、启停、时间窗口和单次 nonce 消费。应用层负责保存设备公钥和设备状态。

Passkey 提供 WebAuthn 注册、认证、计数器 CAS 和凭证状态更新。认证 state 的单次保存和消费由调用方使用 `Secrets` 完成。

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
