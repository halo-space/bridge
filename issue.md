# bridge 当前问题

## 重构约束

职责单一和简约命名约束统一记录在 [CONSTRAINTS.md](CONSTRAINTS.md)。后续拆分、命名和扩展必须先满足该文件中的约束。

## 本批次已修复

- 公共 API 已按模块上下文收敛：issuer、verifier、OIDC、Token、RSA 和通知类型不再重复添加职责后缀；旧名称不保留兼容别名。
- Magic Link 已拆分为纯载荷/签名核心、issuer 签发和 verifier 校验消费；核心不再访问 Secrets。
- Passkey 已拆分为 `validator::issuer::Passkey` 和 `validator::verifier::Passkey`，Pipeline 分别注入发起器和校验器。
- Captcha verifier 只校验并消费挑战；短期通过凭证由 Captcha issuer 单独签发，Pipeline 仍保持原有执行结果。
- Captcha 通过凭证只能在 verifier 写入一次性通过标记后由 issuer 消费签发，不能脱离校验直接伪造。
- 图形、滑块、旋转和点选验证码的生成实现已移到 `validator::issuer::captcha`，`validator::verifier::captcha` 只保留答案校验。
- Device 模型、nonce 签发和设备证明校验已拆到独立文件。
- Pipeline 的 `check(present)` 只读取当前节点 payload，不再从其他分支的历史数据中满足字段检查。
- 社交静态认证包装已移除，社交 Profile 通过已有转换实现交给调用方处理。
- `Run` 在包含密码、验证码、TOTP、Token、Passkey 输入等敏感材料时拒绝序列化；完成节点后会清理当前数据和分支 payload，审计证据只保留清理后的数据。
- Magic Link 默认密钥改为随机值，配置序列化不会输出签名密钥。
- 未知短信供应商返回明确错误，不再静默使用 Mock；通知服务增加显式 `NotifyChannel` 入口。
- `Pipeline` 已拆成模型、运行状态和执行引擎；内置 `Services` 已按签发、发送、校验、Passkey、Device、检查和审计拆分。
- 短信供应商已拆到独立文件；`Aliyun`、`Tencent` 等名称不重复添加 `Sms` 前缀。
- 密码算法已提供 `Codecs` 注册集合和 `authenticate_with` 入口；默认认证入口仍使用内置集合，调用方需要显式注入自定义集合。
- OIDC 流程已拆成授权请求、授权码、刷新和撤销模块。
- 公共错误类型改为简洁的 `Error`，库自身不再使用 `IdpError` 命名。
- 用户密码哈希、客户端密钥、TOTP Secret、SMTP 密码、短信和身份源密钥默认不参与序列化。
- Cargo feature 已拆分为 `mail`、`sms`、`social`、`enterprise`、`passkey` 和 `full`，默认完整构建，核心模式支持 `default-features = false`。

## 复查结果

### 已收口：调用方负责业务命名空间

bridge 不负责租户、应用或组织隔离。验证码、授权码、设备、Passkey 和审计 Key 的命名空间由调用方的 Store 实现决定；调用方需要自行把业务范围编码到 Key，或通过外部上下文完成归属校验。bridge 只提供材料生成、校验、单次消费和 subject 一致性检查。

### 已收口：Device 和 Passkey 绑定当前身份

Device 校验会比较 `Device.subject` 与当前 `Context.identity.subject`；Passkey 校验会比较凭证记录的 subject。调用方仍需保证 Store 返回的记录已经属于当前业务范围，并在建立 `Identity` 时传入稳定的 opaque subject。

### 已收口：Run 敏感数据检查

Run 序列化现在覆盖 `Context.data`、`Context.request`、`Context.meta`、`payloads`、`evidence` 和副作用数据；敏感字段识别覆盖 `password_hash`、`client_secret`、`access_token`、`verification_code` 等后缀和字段名。

### 已收口：Services 能力声明

`Services::supports` 已按内置检查、签发、校验、发送、审计、设备和 Passkey 能力显式声明；未同时配置 Passkey issuer 和 verifier 时不会声明 Passkey 支持。自定义 Runner 仍可按自身能力覆盖 `supports`。

Passkey 签发和校验只读取当前节点的 DAG payload，不再扫描整个 `Context.data` 查找 `subject`、`user_id` 或 `state`，避免并行分支之间混用认证材料。

短信和邮件验证码的 `scene` 已从签发节点沿 payload 传递到发送和校验节点；自定义场景不会再被 verifier 固定覆盖成 `login_sms` 或 `login_email`。

### 已收口：授权码过期检查

OIDC 换授权码时现在同时检查 `AuthCode.expires_at` 和 `Secrets` 的过期结果。

### 已收口：Captcha 失败次数原子递增契约

`Secrets` 增加可选 `incr` 契约。生产存储实现可以提供原子递增；不支持时 bridge 使用兼容读写路径，并明确保留并发限制风险。

### 已收口：外部 Provider 统一请求超时

GitHub、Google、微信、飞书、企业微信和钉钉 Provider 现在通过统一 HTTP Client 创建连接，并默认设置 15 秒连接和请求超时；调用方可以按 Provider 覆盖。

### 调用方策略：Magic Link 跳转地址

Magic Link 只负责签名和有效期；`redirect_to` 的允许域名、路径和动作策略必须由调用方在签发前校验，bridge 不拥有业务站点白名单。

### 已收口：Token 配置校验

签发和校验入口现在会拒绝空 issuer、短 HS256 密钥、非正 TTL 以及不完整的 RSA 密钥配置。

### 已收口：Passkey 使用 opaque subject

`validator::issuer::Passkey::issue` 使用随机 UUID 作为协议层 user handle，把调用方传入的 opaque subject 保存在注册状态和 Passkey 记录中，业务 subject 不再要求 UUID。

注册和认证只接受 bridge 当前的结构化 state，不再兼容旧的裸 WebAuthn state；认证成功且流程尚未有身份时，会用 Passkey subject 建立 `Identity`。

### 已收口：Provider 地址配置

GitHub 使用 `auth()` 和 `api()` 配置授权与 API 地址，Google 使用 `auth()` 和 `userinfo()` 配置授权与用户资料地址；测试环境和私有兼容服务可以替换默认地址。

### 已明确：社交和企业 Provider 的 Pipeline 边界

Provider 已有授权地址、code 换 token、资料解析、Identity 转换和本地成功/失败 fixture；默认 `Services` 不直接持有第三方配置，也不自动维护本地账号绑定。调用方通过 Runner 接入 Provider，并自行完成 state/PKCE、Profile 到 Identity 的映射和业务登录策略。

## P0

### 设计边界：Pipeline 运行状态的短期输入

`Run` 需要在当前节点执行期间暂存输入，才能把数据交给调用方 Runner；它已拒绝包含敏感材料的序列化，并在节点完成后清理数据。调用方如果需要更短生命周期，可以在自己的请求层先校验并立即消费输入，再向 Pipeline 提交结果。

### 默认密钥和静默降级不安全

Magic Link、未知短信供应商和 RSA 解密失败回退问题已修复；`decrypt_or_raw` 对疑似密文解密失败会直接返回错误。

## P1

### 可接受的结构边界：Pipeline 图校验

Pipeline 根入口已拆出模型、运行状态和执行引擎；图校验目前位于执行引擎内部，但只处理图合法性，不混入认证能力。后续只有在图规则继续增长时才单独拆模块。

### 已收口：Services 能力注册

内置 Services 已拆成按能力划分的文件，并在构造时建立集中式能力表；运行时按 `type/code` 查表后进入对应实现。调用方通过 `Runner` 和 `Fallback` 增加或覆盖自定义能力，不需要修改内置分派。

### OIDC Flow 职责混合

OIDC Flow 已拆成授权请求、授权码、刷新和撤销文件；PKCE、state、nonce 仍保持协议参数独立模块。

### Sender 文件职责混合

短信门面和供应商实现已拆分到独立文件，并保持 `Tencent`、`Aliyun` 这类简约命名。

### Store 契约依赖因子实现

Passkey 和 Device 数据模型已迁移到 `types`，`store::Passkeys` 和 `store::Devices` 不再依赖 `factor`，认证协议方法仍留在 `factor`。

### 自定义密码算法没有接入认证因子

密码算法已提供 `Codecs` 注册集合和 `authenticate_with` 入口；默认认证入口仍使用内置集合，调用方需要显式注入自定义集合。

### 已收口：通知通道显式选择

通知服务使用显式 `NotifyChannel` 入口，已移除根据目标字符串推断通道的旧方法。

## P1

### Passkey 状态消费依赖调用方

WebAuthn 注册、认证、持久化读取、计数器 CAS、完整凭证状态更新、`last_used_at` 和错误 challenge 已有真实协议 fixture 测试。bridge 不管理 Session，认证状态的单次保存与消费仍必须由调用方通过单次凭证存储完成。

## P2

### Device 已补齐，仍需应用层存储实现

`factor/enterprise/device.rs` 已提供设备状态、RSA-SHA256 nonce 证明、启停和时间窗口校验；`store::Devices` 提供保存、查询、更新和撤销契约。具体设备数据仍由调用方实现存储。

### 审计流程接入不足

Pipeline 内置 `Services` 已支持 `Effect("audit")` 自动调用 `Events::record_event`。非 Pipeline 认证入口仍由应用层显式记录事件。

### 能力扩展和数据隔离

短信已统一为 `SmsSender` + `Sender` 适配器，所有 Pipeline 节点都可以由调用方通过 `Runner` 实现或覆盖，`Services` 只是可选默认适配器。节点输入沿 DAG payload 传递，不再依赖全局字段扫描；Device nonce 在 Pipeline 校验时单次消费。

配置编译、能力码校验、节点参数传递、Run 版本绑定、Verify 输入状态、Card 参数 Schema、Secret、Effect 单次执行、节点重试上限和完整子图校验已补齐。Provider HTTP 业务错误响应已有本地 fixture 覆盖。

严格 Clippy 检查已经清零，公共 API 保留的参数聚合函数和 OIDC 生成入口使用了局部 lint 说明。

### 已收口：配置 Schema

`Cards::schema()` 现在导出完整页面 JSON Schema 和每个 Card 的参数 Schema。编译阶段同时校验参数类型、未知参数、必填参数和敏感参数引用格式。

### 节点执行策略尚未由 bridge 强制执行

`retries` 已由 Pipeline 记录实际执行次数并限制 Runner 调用次数。`timeout` 和 `Effects` 的边界已经确定：bridge 保存策略和契约，调用方使用自己的 async runtime 中断任务，并提供跨进程原子存储。

### 已收口：图校验

回边检查现在覆盖所有节点子图，发布校验也会拒绝重复 route、空能力码和空边目标。

## 文档和测试

- README 已按当前目录和能力状态整理
- Provider 已覆盖 GitHub、Google、微信、飞书、企业微信和钉钉的本地成功链路、网络失败和业务错误响应；真实服务商凭证和线上网络仍需调用方环境验收。
- Pipeline 的主要成功和失败路径已覆盖；新增能力仍按实际接入继续补充场景测试。

应用层调用方迁移不属于当前 bridge 范围。
