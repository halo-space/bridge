# bridge 实施计划

范围只包含 `bridge`。应用层数据库、缓存、HTTP 路由和调用方迁移不纳入本计划。

## 重构原则

- 所有新增和修改遵守 [CONSTRAINTS.md](CONSTRAINTS.md)。
- 优先拆职责边界，再补实现；不通过继续扩大总入口文件解决新能力。
- 保持公共 API 的词汇简短清晰，具体实现文件不重复父模块表达的能力名。

## 当前重构批次

- [x] P0：隔离 Run 的短期认证输入，清理完成节点的敏感数据。
- [x] P0：移除固定 Magic Link 密钥，未知通知供应商显式报错。
- [x] P1：拆分 Pipeline 模型、状态和执行引擎。
- [x] P1：拆分内置 Services 为按能力划分的文件。
- [x] P1：拆分 OIDC Flow 和短信供应商实现。
- [x] P1：让 Store 契约依赖中立模型。
- [x] P2：接通可注册密码算法和显式通知通道。
- [x] P2：移除 RSA `decrypt_or_raw` 的静默回退。
- [x] P2：统一 bridge 公共命名、日志目标和 feature 边界。
- [x] P1：收敛重复公共命名并按 issuer、verifier 拆分 Magic Link、Passkey 和 Captcha 职责。

## 已完成

### 架构整理

- [x] OIDC 统一归入 `factor/oidc`
- [x] 外部 OIDC Provider 归入 `factor/oidc/provider`
- [x] `types.rs` 拆成 `types/`
- [x] `store.rs` 拆成 `store/`
- [x] Token 拆成 Claims、Service、JWKS
- [x] Captcha 拆成模型、服务和具体类型
- [x] 企业 OIDC、SAML 拆成配置、模型和协议服务
- [x] Store 契约使用 Users、Clients、Secrets、Factors、Passkeys、Events、Limits

### 认证能力

- [x] 密码、邮箱验证码、短信验证码、TOTP
- [x] 图形、滑块、旋转、点选验证码
- [x] 恢复码和 Magic Link
- [x] GitHub、飞书、Google、微信
- [x] LDAP、企业微信、钉钉
- [x] OIDC Authorization Code、PKCE、state、nonce
- [x] Refresh Token rotation 和撤销
- [x] Passkey 数据模型、注册结果、条件计数器更新契约

## 阶段一：Passkey 完整闭环

- [x] 增加真实 WebAuthn 注册 fixture
- [x] 增加真实 WebAuthn 认证 fixture
- [x] 验证重复 Credential ID 和计数器竞争
- [x] 明确 `last_used_at`、backup 状态和重放处理

验收条件是注册、认证、持久化读取和计数器更新都能通过真实协议数据测试。`Passkey` 保存注册时的用户验证和备份标记，`Auth` 返回认证时的最新标记、`needs_update` 和更新后的 native 数据。`Passkeys::update` 使用旧计数器 CAS 原子保存完整凭证状态。认证状态必须由调用方以单次凭证保存并消费，bridge 不管理 Session；错误 challenge 已有失败测试。

## 阶段二：SAML 完整闭环

- [x] 增加真实 IdP metadata 和签名响应 fixture
- [x] 增加断言重放测试
- [x] 增加 SP 发起流程状态关联
- [x] 明确 replay cache 的契约和失败策略

验收条件是签名、Issuer、Audience、时间窗口、状态关联和重放控制都有失败测试。`SamlAuth::start` 返回 tracker，`check_state` 强制关联 tracker 与 replay cache。

## 阶段三：Pipeline 编排

- [x] 支持认证方式顺序
- [x] 支持认证强度和有效期
- [x] 支持失败终止
- [x] 支持追加因子
- [x] 支持密码加 TOTP、社交加验证码、密码加 Passkey
- [x] 保持 Pipeline 不管理 Session、权限和业务用户

验收条件是 Pipeline 能表达输入、检查、签发、发送、校验和后置动作，由内置 `Services` 绑定现有 issuer、sender、verifier、factor 和 store，并通过可序列化运行状态输出下一步、路由分支、All/Any 汇聚、有限循环、重试、拒绝或完成结果。

## 阶段四：协议扩展

- [x] 决定 UserInfo 是否进入核心实现
- [x] 决定 Introspection 是否进入核心实现
- [x] 继续保持 Discovery 与实际能力一致
- [x] 明确是否实现隐式授权

结论：bridge 只提供 OIDC 流程校验、Token 校验和外部 Provider 资料转换，不维护业务用户，因此不提供 UserInfo 端点；Introspection 由调用方使用 `Token::verify_live` 后组装响应；Discovery 只声明 Authorization Code、PKCE、JWKS 和撤销；隐式授权不实现，统一使用 Authorization Code + PKCE。

## 阶段五：企业设备因子

- [x] 定义 Device 的认证协议
- [x] 定义设备密钥和设备状态模型
- [x] 定义设备注册、撤销和校验接口
- [x] 决定 Device 是否进入 `factor/enterprise`

## 阶段六：安全审计

- [x] 移除 Users、Clients、Factors、Passkeys 和 Devices 的租户参数；命名空间由调用方控制
- [x] 明确 Token 撤销校验的统一入口
- [x] 补充 Refresh Token 对用户状态的检查边界
- [x] 设计 RSA 密钥持久化和轮换契约
- [x] 区分邮件短信 Mock 与生产发送失败
- [x] 明确 Events 写入失败、幂等和追踪字段
- [x] 增加 Provider 网络错误和失败响应测试
- [x] 删除未导出的企业目录同步遗留代码

## 阶段七：Pipeline 执行闭环

- [x] 增加 `Event::Input`，区分原始输入和节点通过结果
- [x] 增加 `Pipeline::run`，自动推进可执行节点
- [x] 增加内置 `Services`，统一绑定 issuer、sender、verifier、factor 和 store
- [x] 覆盖滑块、短信签发、短信发送、短信校验、TOTP、密码和审计流程
- [x] 增加 Pipeline 基准程序和外部流程验证

验收结果：滑块 → 验证码签发 → 短信发送 → 短信校验 → 审计、TOTP 和密码流程均已通过集成测试；Release 基准中 10,000 轮纯 Pipeline 状态推进约 5.05µs/轮。

## 阶段八：统一扩展能力

- [x] 增加短信 `Sender` 适配器和 Tencent API 3.0 实现
- [x] 增加 `Fallback` 组合自定义 Pipeline 节点
- [x] 允许调用方覆盖与内置能力同名的节点实现
- [x] 按 DAG payload 传递输入，避免分支字段混用
- [x] 增加 Device nonce 单次消费

## 阶段九：配置执行闭环

- [x] 页面配置使用 `PipelineConfig` 和固定 `type/code/args` 结构
- [x] 使用 `Cards` 校验已注册能力码和必需参数
- [x] 自定义 Runner 通过 `node.args` 获取页面参数
- [x] Run 绑定 Pipeline 配置版本和 hash
- [x] Verify 节点区分用户输入和上游继承数据
- [x] Effect 节点按当前 payload 读取数据，避免并行分支混用
- [x] 增加每个 Card 的完整参数 Schema 和页面 Schema 导出
- [x] 增加基础能力 Schema 导出
- [x] 增加 Secret 配置引用
- [x] 增加 Effect 单次执行策略
- [x] 增加节点 timeout/retry/idempotency 策略字段
- [x] 增加 Runner 能力和版本校验
- [x] 将内置 Services 的能力码分派收敛为显式注册表
- [x] 增加完整 Card 参数 Schema 和页面配置 Schema
- [x] 增加参数类型、未知参数、Secret 引用和边路由校验
- [x] 增加所有节点子图的回边和执行策略校验
- [x] 增加 `Effects` 原子副作用声明、完成和取消契约
- [x] 让 `retries` 落实为 Runner 执行次数上限
- [x] 清理 Clippy 严格检查问题
- [x] Run 序列化覆盖 request、meta 和副作用数据的敏感字段
- [x] 内置 Services 显式声明支持的能力码
- [x] Passkey 节点只读取当前 DAG payload，禁止跨分支扫描认证材料
- [x] 短信和邮件验证码 scene 沿 Pipeline payload 贯穿签发、发送和校验
- [x] OIDC 授权码兑换检查自身 expires_at
- [x] Passkey 注册使用 opaque subject，不要求业务 ID 为 UUID
- [x] Passkey 状态只使用结构化 state，并在独立登录时输出 Identity
- [x] Token 拒绝无效密钥、issuer 和 TTL

## 阶段十：调用方执行边界

- [x] 明确 `Effects` 由调用方提供跨进程原子实现
- [x] 明确 `timeout` 由调用方 async runtime 负责中断
- [x] Provider 增加 HTTP 业务错误响应 fixture
- [x] Provider 增加本地 HTTP 成功链路 fixture
- [x] Provider 统一 HTTP client、连接超时和请求超时
- [x] Provider 完善可替换的用户资料端点
- [x] 明确社交和企业 Provider 通过调用方 Runner 接入 Pipeline
- [x] Captcha 失败次数增加调用方可选的原子递增契约

## 阶段十一：公共命名与职责边界收口

- [x] issuer、verifier 和 OIDC 类型改为模块上下文下的简短命名
- [x] Magic Link 拆分纯签名核心、issuer 签发和 verifier 消费
- [x] Passkey 拆分 issuer 发起和 verifier 完成校验
- [x] Captcha 拆分挑战签发、答案校验和通过凭证签发
- [x] Captcha 通过凭证必须绑定 verifier 的一次性成功标记
- [x] Captcha 具体类型拆分 issuer 生成和 verifier 校验
- [x] Device 拆分模型、nonce 签发和证明校验
- [x] Pipeline present 检查只读取当前节点 payload
- [x] Token、RSA、通知门面和社交静态包装完成命名收口

`Cards::schema()` 现在导出 JSON Schema、能力码和每个 Card 的参数 Schema。Pipeline 会拒绝重复节点、重复 route、空能力码、错误参数类型、未知参数、非法 Secret 引用和未限制的任意子图回边。`Effects` 提供跨进程幂等所需的原子 begin/complete/cancel 契约；bridge 不选择具体数据库或缓存。`retries` 由 Pipeline 记录每个节点实际交给 Runner 的次数并执行上限，`timeout` 由调用方的异步运行时负责中断，bridge 不绑定具体 runtime。

结论：`verify_token` 只做签名和 Claims 校验；需要实时状态的请求统一使用 `verify_live`。Refresh Token 换发通过 `Users` 检查用户存在和 `is_active`，业务命名空间、租户关系和用户数据由调用方管理。RSA 使用 `from_private_pem` 加载持久化密钥，`private_key_pem` 导出，`rotate` 显式轮换；全局生成只作为默认兼容入口。短信和邮件 sender 的 `strict` 模式用于生产失败闭环，关闭时保留开发 Mock 行为。Events 使用 `event.id` 幂等，并支持 trace/request 字段；写入失败由存储实现返回错误。

## 调用方命名空间边界

bridge 不感知租户，也不为验证码、授权码、设备、Passkey 或审计事件生成租户隔离规则。调用方应在自己的存储实现中把租户、应用、平台或其他业务范围编码进 Key，并使用 `Identity.subject`、Store 参数或外部上下文完成归属校验。bridge 只负责协议、材料生命周期和调用方传入 subject 的一致性检查。

## 验收命令

```bash
cargo check
cargo test
```
