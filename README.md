# bridge

Halo IdP (Identity Provider & Protocol Engine)

> **Halo 核心企业级身份认证、多因素认证 (MFA)、安全风控决策与 OIDC 协议引擎**
> 基准规格：**Rust 2024 Edition**（Rust 2024）、**零数据库硬依赖（Zero-DB Dependency）**、纯异步高并发（`async-trait` + `tokio`）。

---

## 一、 架构与设计原则

### 当前边界

`idp` 只负责用户身份认证能力，不负责业务权限、应用 Session、组织目录同步或 REST 接口。

```text
factor      完整登录方式
validator   认证材料的签发、发送和校验
pkg         可复用安全算法
rules       认证规则和安全决策
token       认证结果 Token
oidc        OAuth/OIDC 协议流程
store       由应用层实现的存储契约
```

`validator` 下面的职责固定为：

```text
issuer      生成并签发验证码、TOTP Secret、恢复码等材料
sender      发送短信和邮件等外部通知
verifier    校验用户提交的验证码、TOTP、恢复码、Passkey 等材料
```

`state`、`nonce`、`PKCE` 是 OAuth/OIDC 协议流程参数，统一归 `factor/oidc`，不归 `validator/verifier`。

密码、RSA、TOTP、恢复码等底层算法归 `pkg`；`factor` 只负责组合用户登录方式并调用这些能力。

企业通讯录和组织同步暂不属于当前 `idp` 核心边界，后续是否保留及如何拆分另行讨论。

1. **零数据库耦合 (Trait-driven Architecture)**
   - `bridge` 为纯领域逻辑与协议层，不绑定 PostgreSQL、MySQL 或任何特定 ORM。
   - 所有数据持久化、多租户检索、凭证读取与缓存核销通过 `store/` 中按能力拆分的异步 Trait（`Users`、`Factors`、`Clients`、`Secrets`、`Limits`、`Passkeys`、`Events`）抽象，由宿主应用按需注入实现。

2. **多租户隔离可注入 (Multi-tenant Ready)**
   - 用户、TOTP、Passkey 和审计接口携带租户上下文；其他数据的租户边界由宿主应用在 Store 实现中约束。

3. **端到端密码学防护与防重放 (Zero Trust Cryptography)**
   - **传输与存储安全**：支持客户端 RSA-OAEP 前端非对称加密传输防窃听，密码哈希采用 Argon2id；
   - **动态凭证防重放**：OTP 验证码、OAuth Code、人机验证 Token 均采用单次消费（Take & Consume）模型；
   - **非对称认证中心**：JWT 采用 RS256 私钥签名，支持下游按 RFC 7517 规范拉取 JWKS 公钥无状态验签。

---

## 二、 模块目录树与功能职责

```
src/
├── lib.rs                   # 统一导出入口与核心类型门面
├── error.rs                 # 统一错误枚举 (IdpError) 与 Result 定义
├── store/                   # 异步持久化 Trait 契约，按能力拆分
├── risk.rs                  # 自适应风控引擎（异地瞬移、新设备/IP、暴力破解评分）
├── audit.rs                 # 安全审计事件标准（对齐 SOC 2 / 等保 2.0 三级标准）
├── factor/                  # 登录因子
│   ├── basic/               # 基础凭证认证
│   │   ├── password/        # 账号、邮箱、手机号密码登录
│   │   └── code/            # 邮箱、短信、TOTP 登录
│   ├── social/              # 社交快捷登录
│   ├── enterprise/          # 企业身份源与设备登录
│   ├── oidc/                # OIDC / OAuth2 登录因子与协议流程
│   └── passkey.rs           # WebAuthn / Passkey
├── validator/              # 认证材料能力
│   ├── issuer/              # 签发
│   │   ├── captcha.rs       # 人机验证码
│   │   ├── code.rs          # 邮箱、短信验证码
│   │   ├── totp.rs          # TOTP Secret
│   │   └── recovery.rs      # 恢复码
│   ├── sender/              # 发送
│   └── verifier/            # 校验
├── pkg/                    # 可复用安全组件
│   ├── password.rs          # 密码算法与编码接口
│   ├── recovery.rs          # 恢复码算法
│   ├── rsa.rs               # RSA-OAEP 解密与密钥管理
│   └── totp.rs              # TOTP 算法
├── rules/                  # 认证规则
├── token/                   # 令牌中心，按 Claims、JWT 服务和 JWKS 拆分
└── types/                  # 公共认证类型，按身份、认证、OAuth 和因子拆分
```

---

## 三、 各目录与模块详细功能说明

### 1. 认证核心 (`src/factor/`)
- **`factor/basic/`**：
  - `password/`：账号、邮箱、手机号密码登录；密码算法通过 `pkg/password.rs` 的 `PasswordCodec` 接入。
  - `code/email.rs`：邮箱验证码登录。
  - `code/sms.rs`：短信验证码登录。
  - `code/totp.rs`：账号 + TOTP 登录。
- **`factor/social/`**：
  - `github.rs`：生成 GitHub OAuth 授权跳转 URL，提供服务端 Code 换取 Access Token 与多重邮箱拉取。
  - `feishu.rs`：飞书网页免密扫码与授权登录，支持应用凭据换发及标准化资料转换。
  - `wechat.rs` / `google.rs`：微信开放平台扫码登录与 Google OAuth 2.0 授权解析。
  - `mod.rs`：统一社交资料到 `Identity` 的转换；本地账号映射由调用方处理。
- **`factor/enterprise/`**：
  - `dingtalk.rs`：钉钉统一免密登录，服务端 Code 换取 `userAccessToken` 并提取企业员工档案。
  - `wecom.rs`：企业微信网页与内嵌登录，通过 `corpid` + `corpsecret` 换取成员唯一 `userid`。
  - `ldap.rs`：企业现有 LDAP / Active Directory 目录服务的连接、搜索和密码认证。
  - `saml/`：SAML 配置、断言模型和协议校验。
- **`factor/oidc/provider/`**：外部 OIDC 身份源的配置、Claims 解析和 `Identity` 转换。
- **`factor/passkey.rs`**：持久化 Passkey 模型。
- **`validator/verifier/passkey.rs`**：`WebAuthn` 协议实现，负责标准注册、认证验签、RP/origin 校验和计数器结果。

### 2. 认证材料校验 (`src/validator/verifier/`；OIDC 位于 `src/factor/oidc/`)
- **`validator/verifier/captcha/`**：人机验证码模型、校验服务和四类验证码实现。
- **`validator/verifier/passcode.rs`**：短信、邮箱验证码校验和单次消费。
- **`validator/verifier/totp.rs`**：TOTP 动态口令校验。
- **`validator/verifier/recovery.rs`**：恢复码校验和消费。
- **`validator/verifier/passkey.rs`**：Passkey 认证材料校验入口，基于 `webauthn-rs` 完成标准注册和认证验签。
- **`validator/verifier/captcha/image.rs`**：SVG 矢量动态干扰字符验证码（支持扭曲、干扰线、杂色，大小写自适应匹配）。
- **`validator/verifier/captcha/slider.rs`**：SVG 拼图滑块验证码（背景渐变凹槽与浮动拼图切块，支持 ±5px 像素级容差判定）。
- **`validator/verifier/captcha/rotate.rs`**：SVG 旋转角度验证码（随机初始角度，客户端角度修正，支持 ±8° 角度容差）。
- **`validator/verifier/captcha/click.rs`**：文字顺序点选验证码（随机中文字符点选，支持基于欧几里得距离的 26px 命中判定）。

### 3. 认证材料签发 (`src/validator/issuer/`)
- **`validator/issuer/totp.rs`**：签发 TOTP Secret、绑定 URI 和二维码；
- **`pkg/totp.rs`**：RFC 6238 底层算法（Google Authenticator / 1Password 兼容）；
  - 内置无依赖 Base32 编解码、HMAC-SHA1 动态截断算法；
  - 支持 `±1` 周期（30 秒窗口）时间偏差容错；
  - 内置基于 `qrcode` 的 SVG 格式与 Data URI 格式的二维码直出。
- **`validator/issuer/recovery.rs`**：签发恢复码和恢复码哈希；
- **`pkg/recovery.rs`**：恢复码底层生成与哈希算法；
  - 格式如 `A8B2-C9D4`；
  - 密文存储：仅持久化 SHA-256 哈希散列，单次消费立即销毁。

### 4. 令牌中心与公钥服务 (`src/token/`)
- **`token/service.rs`**：
  - 支持 **RS256**（非对称私钥签名/公钥验签）与 **HS256**（对称秘钥）自适应双模式；
  - 签发带类型标记的 Access Token 与 Refresh Token，并支持动态扩展声明；
  - 支持精确验证 Audience、Issuer、过期时间、Token 类型和实时撤销状态。
- **`token/claims.rs`**：Access、Refresh 和 ID Token 的 Claims 模型。
- **`token/jwks.rs`**：
  - RFC 7517 标准规范输出；
  - 支持从 RSA 公钥或组件一键导出 `/.well-known/jwks.json`（Base64URL 格式的模数 `n` 与指数 `e`），微服务无需共享私钥即可独立校验。

### 5. OIDC / OAuth 2.0 协议引擎 (`src/factor/oidc/`)
- **`factor/oidc/provider/`**：外部 OIDC 登录 Provider。
- **`factor/oidc/server.rs`**：RFC 8414 标准 Discovery 元数据模型（`/.well-known/openid-configuration`），端点自适应拼接。
- 当前 Discovery 只声明已实现的 Authorization Code、PKCE、JWKS 和撤销能力；UserInfo、Introspection 和隐式授权仍是数据模型或后续能力。
- **`factor/oidc/flow.rs`**：
  - RFC 7636 **PKCE** 防拦截校验（原生支持 `S256` SHA-256 与 `plain` 模式）；
  - OAuth `state` 和 OIDC `nonce` 的流程绑定与校验；
  - 标准 Authorization Code 授权码生成、暂存与防重放单次兑换；严格校验 grant type、redirect URI、scope、客户端密钥和公共客户端 PKCE；
  - `exchange_refresh_token`：校验 Refresh Token 类型、客户端、撤销状态和有效期后重新签发 Token；
  - RFC 7009 **Token 撤销机制**：支持分布式黑名单实时吊销已颁发令牌。

### 6. 自适应安全风控决策 (`src/risk.rs`)
- **`RiskEngine`**：自适应 Step-up MFA 与动态阻断决策引擎；
- 评分因子权重模型（0-100 分）：
  - **连续登录失败**（加权累计）；
  - **未知新 IP 登录**；
  - **未知新设备指纹**；
  - **异地瞬移 (Impossible Travel)**：短时间跨国家/跨大洲地理位置跃迁判定；
- 决策输出：`Allow`（直接放行）、`RequireMfa`（提权二次认证）、`Block`（直接阻断拦截并记录证据链）。

### 7. 企业组织通讯录同步（暂不属于当前核心边界）
现有 `factor/enterprise/sync.rs` 保留为待评估文件，不参与当前 crate 编译和导出。后续如果需要支持企业目录同步，再单独确定模块或 crate 边界。

### 8. 通讯与通知通道 (`src/validator/sender/`)
- **`validator/sender/mail.rs`**：基于 `lettre` 的异步企业级 SMTP 客户端，支持 STARTTLS（587）、TLS（465）与纯文本；内置自适应企业品牌样式的响应式 HTML 验证码邮件模版；具备未配置静默无损降级特性。
- **`validator/sender/sms.rs`**：短信网关。内置标准阿里云短信 RPC 协议，实现 RFC 3986 百分号编码规范与完整的 HMAC-SHA1 签名计算；提供腾讯云接口及开发联调专用的 Mock 通道。
- **`validator/sender/notify.rs`**：统一通知门面（Facade），自动根据目标格式识别邮箱（含 `@`）与手机号（纯数字），实现验证码智能路由与发送。

### 9. 邮件魔术链接免密登录 (`src/factor/basic/magic.rs`)
- 提供 Passwordless 无密魔术链接签发；
- 采用 **HMAC-SHA256** 防篡改签名，URL 友好 Base64URL 编码；
- 内置 JTI 唯一防重放标识与过期时间戳检测。

### 10. 安全合规审计标准 (`src/audit.rs`)
- 包含 16 种身份生命周期事件（如密码登录、MFA 绑定/核销、Passkey 认证、防爆破锁定、异地风控阻断、组织同步等）；
- 事件模型参考 **SOC 2** 与 **中国网络安全等保 2.0 三级** 的认证审计要求。

---

## 四、 存储接口契约体系 (`src/store/`)

宿主应用只需针对持久化层实现对应 Trait 即可插拔运行：

```rust
pub trait Users: Send + Sync { ... }     // 由调用方提供的认证身份和凭证读取接口
pub trait Clients: Send + Sync { ... }   // OAuth2 / OIDC 应用凭据
pub trait Secrets: Send + Sync { ... }       // 验证码、Token、单次凭证原子消费
pub trait Passkeys: Send + Sync { ... }  // FIDO2 / Passkey 持久化与计数器更新
pub trait Factors: Send + Sync { ... }     // TOTP Secret 绑定
pub trait Events: Send + Sync { ... }    // 安全事件日志持久化
```

---

## 五、 测试与质量保障

Crate 包含完整的单元测试与集成测试矩阵：
```bash
cargo test
```
- **13 项模块单元测试**：覆盖 SMTP 配置自适应、自适应风控评分决策、Magic Link 防篡改与时效检测、短信签名与统一通知路由等。
- **15 项系统级集成测试**：覆盖多种密码算法、RSA 密文解密、多社交平台授权 URL 解析、RS256 JWT 与 JWKS 动态导出、PKCE S256 算法、授权码 nonce 与防提前消费、四大类行为人机验证码全闭环、魔术链接单次消费、TOTP 容差计算与恢复码批量哈希。


## 六、认证能力建设基线

本节作为后续重构和功能实现的总基线。认证能力参考 Ory Kratos、Keycloak、ZITADEL 和 Authing 的成熟做法，按登录方式、认证材料和协议流程拆分。

### 当前实现状态

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| 基础密码、邮箱验证码、短信验证码、TOTP | 已实现 | 由 `factor/basic` 提供登录因子 |
| 图形验证码、恢复码、Magic Link | 已实现 | 由 `validator` 和 `pkg` 提供生命周期能力 |
| Passkey / WebAuthn | 部分实现 | 协议验签和存储契约已完成，完整应用闭环待补测试 |
| GitHub、飞书 | 已实现 | 支持授权码交换和资料标准化 |
| Google、微信 | 已实现 | 支持授权地址、授权码交换和资料解析，真实网络集成测试待补齐 |
| LDAP | 已实现 | 支持服务账号绑定、用户搜索、用户密码绑定和 `Identity` 输出 |
| SAML | 部分实现 | `SamlAuth` 已接入元数据、签名、Issuer、Audience 和时间窗口校验，真实 IdP fixture 与重放存储测试待补齐 |
| Device | 待实现 | 当前只保留模块边界 |
| OAuth/OIDC Authorization Code | 已实现 | 包含 PKCE、state、nonce、Refresh Token 和撤销 |
| UserInfo、Introspection、隐式授权 | 待实现 | Discovery 不再宣称这些能力 |
| Pipeline | 部分实现 | 当前支持认证结果匹配，执行编排仍待补齐 |

### 1. 认证材料生命周期

所有认证材料都需要具备统一的生命周期：创建、保存、过期、失败次数、单次消费、撤销和审计引用。魔术链接使用 `MagicLinkService::create` 写入调用方的 `Secrets`，再用 `take` 原子消费。无存储的 `create_magic_link` 和 `verify_token` 仅适合签名校验，不提供单次消费保证。

适用对象包括图形验证码、滑块验证码、旋转验证码、点选验证码、短信验证码、邮箱验证码、TOTP Secret、恢复码、Magic Link 和 Passkey / WebAuthn Challenge。

### 2. 验证码使用场景

短信和邮箱验证码是通用认证材料，可以用于不同场景：

```text
login          登录
register       注册
verify_email   邮箱验证
verify_phone   手机验证
reset_password 重置密码
bind_factor    绑定认证因子
factor_check   流程中的额外校验
```

短信和邮件是发送通道。验证码的生成、保存、过期和校验由 `validator` 负责，具体使用场景由后续认证编排决定。

### 3. 认证方式和认证编排

每个认证因子既可以作为独立登录方式，也可以被认证流程追加使用：

```text
账号 + TOTP
密码 → TOTP
社交登录 → TOTP
密码 → 短信验证码
密码 → Passkey
```

`factor` 负责一种完整登录方式，`validator` 负责认证材料的签发、发送和校验。认证方式处于第几步由后续 `flow` 或 `pipeline` 决定。

### 4. Passkey 凭证模型

Passkey / WebAuthn 需要保存完整数据：

```text
credential_id
public_key
user_handle
sign_count
aaguid
display_name
created_at
last_used_at
passwordless
```

认证成功后，应用层先用 `Passkey::can_update` 判断计数器，再调用 `Passkeys::update` 做带旧值的条件更新。

同时支持独立 Passkey 登录和流程中的 Passkey 校验。设备注册、签名验证、计数器更新和克隆检测必须分开处理。

### 5. 认证结果和强度

认证结果应记录本次完成的认证方式和完成时间，供后续编排判断认证是否满足当前要求：

```rust
pub struct AuthResult {
    pub method: Method,
    pub completed_at: i64,
    pub level: u8,
}
```

`level` 表示认证结果强度，不把短信、TOTP 或 Passkey 固定绑定为某一个步骤。

### 6. 重新认证和有效期

认证规则需要支持独立配置密码重新输入时间、外部身份源认证有效期、TOTP 或其他认证因子有效期、认证因子绑定前的重新认证要求、修改密码或联系方式前的重新认证要求，以及密码过期和登录失败锁定。

### 7. 恢复码

恢复码是认证因子不可用时的后备材料，需要支持批量生成、只展示一次、只保存哈希、单个消费、显示剩余数量，以及重新生成时废弃旧码。

### 8. 外部身份源

社会化身份源和企业身份源统一输出 `Identity`。它表示第三方身份源已经认证成功后对外返回的身份资料：

```rust
pub struct Identity {
    pub provider: String,
    pub subject: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub name: Option<String>,
}
```

Provider 负责第三方协议交互，并将资料转换为 `types::Identity`。本地账号、账号绑定和业务用户管理由调用方负责。

### 9. 实现顺序

后续按以下顺序逐项完成：

1. 统一认证材料生命周期和存储接口；
2. 完善验证码、短信和邮箱验证码的签发、发送、校验；
3. 完善 TOTP、恢复码和 Passkey 的签发与校验；
4. 补齐密码算法渐进升级和认证规则；
5. 完善外部身份源统一接口；
6. 完善认证结果、认证强度和重新认证规则；
7. 最后设计 `flow` 或 `pipeline` 编排层。

OIDC 的 `state`、`nonce`、PKCE 归 `factor/oidc` 协议模块。业务权限、应用 Session 和企业组织同步不属于当前 `idp` 核心范围。
