# bridge 后续完成计划

这份计划只记录当前还没有完成的能力和架构收口项。每项完成后必须同时更新代码、测试、USAGE 和 README，再勾选对应项目。

## 范围

bridge 负责认证协议、认证材料、Token、Pipeline 和可复用扩展契约。

调用方负责 HTTP 路由、Session、业务用户、账号绑定、租户、组织、权限、数据库、缓存、UserInfo 端点和 Introspection 端点。

bridge 不新增 RBAC、业务用户中心、Session 管理和租户字段。

## P0：先完成核心闭环

### 1. OIDC 服务端核心闭环

- [x] 授权码兑换可以完成统一的 TokenResponse。
- [x] 根据 scope 生成 access token、refresh token 和 ID token。
- [x] 校验 client、redirect_uri、PKCE、nonce、client authentication、scope 和 grant type。
- [x] 明确 Token 的过期时间、token_type、scope 和 ID token claims。
- [x] Refresh Token 轮换失败时不能产生半完成状态。
- [x] 增加授权码兑换、TokenResponse、ID token 和 refresh rotation 的完整测试。

完成标准：调用方只提供身份主体和 Token 配置，bridge 可以返回标准 OAuth/OIDC TokenResponse；bridge 不创建用户、不保存 Session。

### 2. 统一身份主体模型

- [x] 定义不依赖本地数据库 ID 的主体模型。
- [x] OIDC 授权码、Refresh Token、Passkey、TOTP、Provider 和审计统一使用主体或 Identity。
- [x] 移除协议核心对 User 和 i64 user_id 的强制依赖。
- [x] 为现有账号密码能力保留调用方适配入口，不把本地账号模型变成 bridge 的中心模型。
- [x] 增加不同 Provider、不同主体格式和身份不一致的测试。

完成标准：bridge 可以处理字符串主体、外部 Provider 主体和调用方自定义主体，不要求业务用户表使用整数 ID。

### 3. 外部 OIDC Provider 完整流程

- [x] 增加授权地址构造。
- [x] 增加 authorization code 兑换。
- [x] 增加 Discovery 和 JWKS 读取契约。
- [x] 校验 ID token 签名、issuer、audience、过期时间、nonce 和 PKCE。
- [x] 将验证后的 claims 转换为统一 Profile 和 Identity。
- [x] 外部 OIDC Provider 失败、过期、错误 issuer、错误 audience 和错误 nonce 必须有测试。

完成标准：外部 OIDC 登录可以从授权地址、回调 code 一直到标准 Identity，调用方再决定是否绑定业务用户。

## P1：生产安全和扩展边界

### 4. 短期凭证原子生命周期

- [x] 扩展 Secrets，提供统一的原子占用或消费能力。
- [x] Refresh Token 轮换使用原子占用。
- [x] OIDC state、nonce、Passkey state 和 Device nonce 支持过期、单次消费和并发安全。
- [x] 授权码和 Device nonce 的存储键改为摘要或随机句柄，不直接使用凭证值。
- [x] 增加并发重复消费测试。

### 5. 频控和锁定接入 Pipeline

- [x] Services 支持调用方注入 Limits。
- [x] 短信、邮件、验证码、密码和 TOTP 节点可以使用频控。
- [x] 接入锁定规则的读取、失败递增、成功清零和锁定时间。
- [x] 风险引擎可以作为 Pipeline 的可选检查节点使用。
- [x] 频控和锁定仍由调用方提供存储，bridge 不添加租户字段。

### 6. Pipeline 执行边界

- [x] timeout 支持调用方明确传入执行租约或取消边界。
- [x] Effects 的占用契约包含租约有效期、完成、取消和接管规则。
- [x] 明确 fan-out 是顺序执行还是由调用方并发执行，并在 API 和文档中统一说明。
- [x] 明确 Pipeline 是严格 DAG，还是允许带上限的回边图；代码、命名和测试保持一致。
- [x] Runner 错误区分临时错误和业务拒绝，不能把所有 OAuth、短信和邮件错误都自动重试。
- [x] 运行状态支持可信存储边界、TTL 和配置版本校验；不允许不可信客户端直接修改 Run。

### 7. 密码和 TOTP 安全能力

- [x] PBKDF2、SM3 和 TOTP 校验统一使用常量时间比较。
- [x] SM3 改为适合密码存储的 KDF 形式，或明确限制为兼容算法并给出安全边界。
- [x] PBKDF2 参数增加上限，避免恶意参数造成 CPU 消耗。
- [x] TOTP 支持调用方配置算法、位数、周期和允许偏移。
- [x] TOTP Secret 增加绑定、启用、停用和替换时的调用方存储契约说明。

### 8. Passkey 状态和存储闭环

- [x] 注册和认证状态明确由调用方以短期单次凭证保存和消费。
- [x] 状态过期、重复使用、错误主体和错误凭证必须拒绝。
- [x] 计数器 CAS、凭证主体和认证结果更新保持一个明确的原子边界。
- [x] 未知 Credential ID 不能被当作认证成功。
- [x] 增加并发认证、重复状态和跨主体认证测试。

### 9. 通知和 Provider 扩展

- [x] 邮件发送增加与短信一致的可替换 Sender 契约。
- [x] Notify 支持调用方注入自定义邮件和短信通道。
- [x] GitHub、Google、微信、飞书、企业微信和钉钉统一输出 Profile 或 Identity。
- [x] Provider 统一错误分类、超时、重试和响应字段校验。
- [x] Provider 仍由调用方 Runner 接入 Pipeline，不自动绑定本地用户。

## P2：结构、性能和维护质量

### 10. Services 和能力注册

- [x] Services 的内置能力表继续保持显式注册，移除重复兼容别名。
- [x] 自定义能力使用公开注册接口，不修改 bridge 内部字符串分派。
- [x] issuer、sender、verifier 可以独立替换，不要求调用方替换整个 Services。
- [x] 每个能力码、参数、版本和 Runner 支持情况保持一致。

### 11. 运行状态和数据保护

- [x] 为 Context、Evidence、Run 和 Provider 原始资料增加大小边界。
- [x] 敏感数据由显式类型或字段标记控制，不只依赖字段名猜测。
- [x] 审计 metadata 在写入前完成敏感字段清理。
- [x] 运行状态序列化、恢复、过期和清理流程补齐测试。

### 12. 审计和规则模型

- [x] 内置审计节点覆盖支持的审计事件，未支持事件显式返回错误。
- [x] 审计模型不强制依赖本地 user_id，可直接记录 Identity 或主体。
- [x] 风险、锁定、重认证规则和 Pipeline 节点的输入输出格式统一。

### 13. Feature 和依赖拆分

- [x] OIDC 核心、外部 OIDC Provider、社交 Provider、企业 Provider 和 Passkey 的 feature 边界独立。
- [x] 不使用某个 Provider 时不引入对应 HTTP 或协议依赖。
- [x] 完成默认 feature、无 feature、social、enterprise、passkey 的编译矩阵。

### 14. 测试和发布质量

- [x] 增加 OIDC、Refresh Token、Passkey、验证码和 Effects 的并发测试。
- [x] 增加 Pipeline 配置、Provider 响应、Token claims 和存储状态的属性测试或模糊测试。
- [x] 增加真实协议样例和可控 Mock 服务测试。
- [x] 增加密码、TOTP、Token、Pipeline、Provider 和 Sender 的 benchmark。
- [x] 增加 CI、MSRV、clippy、rustdoc、依赖安全检查和 feature 矩阵。

## 每项完成时的验收

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo check --no-default-features
cargo check --no-default-features --features "social,enterprise"
cargo test --workspace --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --no-default-features --lib -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
git diff --check
```

代码、测试、README、USAGE 和本计划必须一起更新，未通过验收的项目不能勾选完成。
