# bridge 当前问题

## P1

### Passkey 状态消费依赖调用方

WebAuthn 注册、认证、持久化读取、计数器 CAS、完整凭证状态更新、`last_used_at` 和错误 challenge 已有真实协议 fixture 测试。bridge 不管理 Session，认证状态的单次保存与消费仍必须由调用方通过单次凭证存储完成。

## P2

### Device 已补齐，仍需应用层存储实现

`factor/enterprise/device.rs` 已提供设备状态、RSA-SHA256 nonce 证明、启停和时间窗口校验；`store::Devices` 提供保存、查询、更新和撤销契约。具体设备数据仍由调用方实现存储。

### 审计流程接入不足

Pipeline 内置 `Services` 已支持 `Effect("audit")` 自动调用 `Events::record_event`。非 Pipeline 认证入口仍由应用层显式记录事件。

## 文档和测试

- README 已按当前目录和能力状态整理
- Provider 网络失败测试已覆盖 GitHub、Google、微信、飞书、企业微信和钉钉；真实服务商业务错误响应仍由各 Provider 的错误字段解析负责。
- Pipeline 的主要成功和失败路径已覆盖；新增能力仍按实际接入继续补充场景测试。

应用层调用方迁移不属于当前 bridge 范围。
