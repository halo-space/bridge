# IDP 重构计划

目标：把 `idp` 收敛为用户身份认证能力库。模块职责单一，命名简洁，存储由调用方实现。

## 阶段一：边界收敛

- [x] 移除 `AuthUser` 中的角色和权限字段
- [x] 明确认证结果和身份资料模型
- [x] 移除 Users 的外部身份查询和绑定职责
- [x] 收敛 Users、Factors、Passkeys 的职责
- [x] 移除社交 Provider 内的本地账号查询和绑定逻辑

## 阶段二：身份源统一

- [x] 社交 Provider 输出 `Identity`
- [x] 企业微信、钉钉和 SAML Provider 输出 `Identity`
- [x] LDAP、OIDC、SAML、企业微信、钉钉统一结果模型
- [x] 飞书 Provider 通过 `SocialProfile` 转换为 `Identity`
- [x] 保留 Provider 自身协议差异

## 阶段三：认证材料

- [x] 统一 issuer、sender、verifier 的生命周期
- [x] 完成验证码过期接口
- [x] 提供验证码发送频控接口
- [x] 统一验证码场景
- [x] 完成验证码失败次数和上限
- [x] 完成验证码单次消费接口
- [x] 绑定验证码类型并保证成功校验的原子单次消费
- [x] 将 `Secrets` 原子 compare-and-delete 纳入必需存储契约
- [x] 完成 TOTP 和恢复码的签发与校验
- [x] 完成 Magic Link 的签发与校验拆分
- [x] 提供 Magic Link 的外部存储登记和单次消费接口
- [x] 完成 Passkey 标准注册与验签接口
- [x] 定义 Passkey 计数器和存储契约
- [x] Passkey 计数器更新带旧值条件，避免并发覆盖

## 阶段四：密码和规则

- [x] 完成 Argon2id、Bcrypt、PBKDF2 扩展接口
- [x] 接入带 Salt 的 SM3 兼容方案
- [x] 支持密码算法标识和升级判断
- [x] 统一密码强度、失败锁定和重认证规则
- [x] 提供重认证有效期判断

## 阶段五：协议和结果

- [x] 修复 OAuth/OIDC 授权码消费和 PKCE 流程
- [x] 完成 redirect URI、scope 和 client 校验
- [x] 完成 nonce 校验接入 ID Token
- [x] 完成 Refresh Token 验证和换发
- [x] 区分 Access Token 和 Refresh Token
- [x] 接入 Token 撤销检查
- [x] 授权码保留 OIDC nonce，错误 PKCE 请求不提前消费授权码

## 阶段六：认证编排

- [x] 选定 `pipeline` 作为认证编排模型
- [x] Pipeline 支持密码、验证码、TOTP、Passkey、社交和企业身份源的结果匹配
- [x] 输出认证方式和认证强度

## 约束

- `idp` 不维护业务用户、角色、权限、应用 Session 或组织目录
- `state`、`nonce`、PKCE 归 `oidc`
- 底层算法归 `pkg`
- 本地存储和第三方发送由调用方实现
- 每次改动保持 `cargo test` 通过

## 待完成的核心迁移

- [x] 基础 factor 提供 `Identity` / `AuthResult` 输出，认证结果不再依赖 `AuthUser` 作为对外模型
- [x] 完成 OIDC 外部身份源 claims 到 `Identity` 的 Provider 解析
- [x] 完成验证码发送频控的默认调用链和场景绑定
- [ ] 迁移调用方到新的 `validator` 和 `factor` API（应用层范围，按当前任务边界暂不处理）

## 下一阶段计划

本阶段只完善 `crates/idp`。应用层 Store 的具体数据库、缓存和 Provider 配置实现不纳入验收。

### 阶段七：能力清单校正

- [x] 将 README 按“已实现、部分实现、待实现”重排
- [x] 删除 Discovery 中尚未实现的 response type 和端点声明
- [x] 修正审计事件数量、`AuthResult`、Passkey 字段和多租户说明
- [ ] 为每项已实现能力补充至少一个成功和失败测试

验收条件：README 的每一项能力都能在 `src` 中找到对应入口，未完成能力明确标记状态。

### 阶段八：Passkey 闭环

- [x] `WebAuthn` 注册结果直接形成 `factor::passkey::Passkey`
- [x] 补齐注册数据、用户句柄、显示名称和认证时间
- [x] 明确 Passkeys 的保存、查询、列表和条件更新语义
- [x] 校验重复 Credential ID
- [x] 校验计数器回退
- [x] 增加计数器回退判断测试
- [x] 增加注册状态、重复注册、计数器竞争测试
- [ ] 增加真实 WebAuthn 注册和认证 fixture 测试

验收条件：Passkey 可以完成注册、读取、认证和计数器条件更新，协议层不依赖具体数据库。

### 阶段九：OIDC 能力收敛

- [x] 完善 state、nonce 和 PKCE 的生成接口
- [x] 补齐授权码跨客户端、scope、redirect URI 和 nonce 失败测试
- [x] 明确 UserInfo 和 Introspection 暂作为后续能力
- [x] 只在 Discovery 中声明已经实现的能力
- [x] 验证 Refresh Token rotation 和撤销后的再次使用

验收条件：Discovery、flow、token 的声明和实际行为一致。

### 阶段十：外部身份源

- [x] Google 补齐授权码换 Token 和用户资料获取
- [x] 微信补齐授权码换 Token 和用户资料获取
- [x] LDAP 增加连接、搜索、密码验证和 `Identity` 输出边界
- [x] SAML 增加断言解析、签名、Issuer、Audience 和时间校验
- [ ] 增加真实 SAML IdP fixture、断言重放和 SP 状态关联测试
- [ ] 明确 Device 的协议和数据模型，再决定是否进入核心导出

验收条件：每个 Provider 都能完成协议输入、校验和统一 `Identity` 输出，不承担本地账号绑定。

### 阶段十一：Pipeline 最小编排

- [ ] 支持认证方式顺序
- [ ] 支持认证强度和有效期判断
- [ ] 支持失败终止和追加因子
- [ ] 保持 Pipeline 不管理 Session、权限和业务用户
- [ ] 增加密码、验证码、TOTP、Passkey 组合测试

验收条件：Pipeline 能表达基础登录、密码加 TOTP、社交加验证码等组合。

### 阶段十二：核心质量审计

- [ ] 检查所有一次性材料是否使用原子消费
- [ ] 检查所有外部输入是否有长度、格式和过期校验
- [ ] 检查所有 Provider 是否避免本地账号维护
- [ ] 检查所有公开命名是否简洁、职责单一
- [ ] 固定 `cargo check` 和 `cargo test` 作为验收命令
