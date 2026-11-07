# bridge 实施计划

范围只包含 `bridge`。应用层数据库、缓存、HTTP 路由和调用方迁移不纳入本计划。

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
- [ ] 支持失败终止
- [x] 支持追加因子
- [x] 支持密码加 TOTP、社交加验证码、密码加 Passkey
- [x] 保持 Pipeline 不管理 Session、权限和业务用户

验收条件是 Pipeline 能表达完整的认证步骤，并输出可继续执行的结果。

## 阶段四：协议扩展

- [x] 决定 UserInfo 是否进入核心实现
- [x] 决定 Introspection 是否进入核心实现
- [x] 继续保持 Discovery 与实际能力一致
- [x] 明确是否实现隐式授权

结论：bridge 只提供 OIDC 流程校验、Token 校验和外部 Provider 资料转换，不维护业务用户，因此不提供 UserInfo 端点；Introspection 由调用方使用 `TokenService::verify_live` 后组装响应；Discovery 只声明 Authorization Code、PKCE、JWKS 和撤销；隐式授权不实现，统一使用 Authorization Code + PKCE。

## 阶段五：企业设备因子

- [ ] 定义 Device 的认证协议
- [ ] 定义设备密钥和设备状态模型
- [ ] 定义设备注册、撤销和校验接口
- [ ] 决定 Device 是否进入 `factor/enterprise`

## 阶段六：安全审计

- [x] 补齐 Users 和 Clients 的租户上下文
- [x] 明确 Token 撤销校验的统一入口
- [x] 补充 Refresh Token 对用户状态的检查边界
- [ ] 设计 RSA 密钥持久化和轮换契约
- [ ] 区分邮件短信 Mock 与生产发送失败
- [ ] 明确 Events 写入失败、幂等和追踪字段
- [ ] 增加 Provider 网络错误和失败响应测试
- [x] 删除未导出的企业目录同步遗留代码

结论：`verify_token` 只做签名和 Claims 校验；需要实时状态的请求统一使用 `verify_live`。Refresh Token 换发通过 `Users` 检查租户、用户存在和 `is_active`，bridge 不维护用户数据。

## 验收命令

```bash
cargo check
cargo test
```
