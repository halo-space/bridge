# bridge 当前问题

## P1

### Passkey 状态消费依赖调用方

WebAuthn 注册、认证、持久化读取、计数器 CAS、完整凭证状态更新、`last_used_at` 和错误 challenge 已有真实协议 fixture 测试。bridge 不管理 Session，认证状态的单次保存与消费仍必须由调用方通过单次凭证存储完成。

## P2

### Device 尚未实现

`factor/enterprise/device.rs` 当前只有模块占位，没有设备注册、密钥、撤销和认证流程。

### 审计流程接入不足

RSA、发送通道和 Events 契约边界已补齐。认证流程尚未自动发出审计事件，应用层需要在认证入口调用 `Events::record_event`。

## 文档和测试

- README 已按当前目录和能力状态整理
- Provider 的真实网络失败响应测试仍需补充
- 每项已实现能力还没有完整覆盖成功和失败路径

应用层调用方迁移不属于当前 bridge 范围。
