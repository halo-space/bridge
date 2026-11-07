# bridge 当前问题

## P1

### Passkey 状态消费依赖调用方

WebAuthn 注册、认证、持久化读取、计数器 CAS、完整凭证状态更新、`last_used_at` 和错误 challenge 已有真实协议 fixture 测试。bridge 不管理 Session，认证状态的单次保存与消费仍必须由调用方通过单次凭证存储完成。

## P2

### Device 尚未实现

`factor/enterprise/device.rs` 当前只有模块占位，没有设备注册、密钥、撤销和认证流程。

### Pipeline 失败终止边界待明确

Pipeline 已支持步骤顺序、认证强度、有效期和追加因子。认证因子失败不会进入 Pipeline，当前仍需要明确调用方收到失败结果后的终止策略。

### 密钥和发送通道生产约束不足

RSA 全局密钥的持久化和轮换、短信邮件 Mock 与生产错误策略、审计事件可靠写入都需要应用层契约配合。

## 文档和测试

- README 已按当前目录和能力状态整理
- Provider 的真实网络失败响应测试仍需补充
- 每项已实现能力还没有完整覆盖成功和失败路径

应用层调用方迁移不属于当前 bridge 范围。
