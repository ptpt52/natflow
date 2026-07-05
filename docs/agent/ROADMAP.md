# Natflow 开发路线图

更新时间：2026-07-04

本文记录当前仓库的下一步开发目标。它是智能体和维护者的任务入口，不替代 `SYSTEM_DESIGN_SPEC.md`；具体实现仍以源码为准。

## 使用规则

- 做任务前先确认目标是否在本文中；不在本文中的较大改动应先补目标。
- 完成目标后更新状态，并把行为或接口变化同步到 `README.md` 和 `SYSTEM_DESIGN_SPEC.md`。
- 涉及内核数据面、字符设备 ABI、用户态控制面的大改，需要先拆成设计任务。

## P0：近期目标

### P0-1：维护仓库路线图

状态：Done（初版已落地；后续维护按需更新）

目标：把后续开发方向固化在仓库内，避免只存在于对话上下文。

退出条件：

- 新增或更新本文。
- `AGENTS.md`、`docs/agent/MEMORY.md` 和 `README.md` 能指向本文。

### P0-2：明确未完成行为

状态：Planned

目标：把当前已知但未完整实现的行为逐项分类为“实现”、“保留为不支持”或“废弃”，并同步用户文档和规格。

当前必须覆盖：

- [x] Host ACL 的 `redirect` action 当前没有完整重定向实现。（已实现基于 302 的拦截与配置）
- `conntrackinfo_ctl` 的 `kickall` 当前没有实际清理行为。
- `/dev/userinfo_event_ctl` 写接口当前返回 `-ENOSYS`。
- `userinfo_ctl`、`userinfo_event_ctl`、`urllogger_queue` 小 buffer read 当前返回 `-EINVAL`，不是 partial read。

退出条件：

- 每个未完成行为都有明确状态和用户可见说明。
- 若选择实现，补对应验证；若选择不支持，`README.md` 和 `SYSTEM_DESIGN_SPEC.md` 明确写出限制。

## P1：质量和兼容性

### P1-1：修复小 buffer read 兼容性

状态：Planned

目标：把 `userinfo_ctl`、`userinfo_event_ctl`、`urllogger_queue` 的小 buffer 读取从直接 `-EINVAL` 改为更兼容的 partial read 或 per-open buffer 行为。

注意：这是用户可见行为变化，必须同步文档。

### P1-2：增强控制输入长度校验

状态：Planned

目标：对 auth rule、bypass ipset、QoS set、zone/vline ifname 等固定长度输入做显式长度校验，减少静默截断导致的误配置。

注意：若为了兼容继续保留截断语义，必须在文档中明确。

### P1-3：重构 vline IPv6 ND/NOARP skb 处理

状态：Planned

目标：把 plain vline IPv6 Ethernet/NOARP 的 Neighbor Advertisement 构造路径改为更明确的 skb length/tailroom helper 流程，并补回归验证。

## P2：产品化和架构目标

### P2-1：建立构建和回归验证矩阵

状态：Planned

目标：形成可重复的验证入口，至少覆盖基础构建、`CONFIG_NATFLOW_PATH`、`CONFIG_NATFLOW_URLLOGGER`、`NO_DEBUG=1`，并逐步补 URL parser、QoS、认证状态机和 vline 回归验证。

### P2-2：评估用户态控制面/authd/portal

状态：Planned

目标：决定是否在本仓库增加用户态控制面，例如 authd、portal/web server、配置下发工具或事件消费程序。

边界：

- 当前仓库仍是内核模块仓库，不自动引入用户态守护进程。
- 如果要做用户态控制面，先写设计文档，明确进程职责、字符设备协议、事件模型、配置持久化、权限边界和部署方式。
- 用户态控制面不得改变内核模块现有 ABI，除非先记录兼容性决策。

退出条件：

- 形成“做/不做/拆到其他仓库”的明确决策。
- 若决定做，新增独立设计文档和任务拆分。

### P2-3：降低内核私有状态风险

状态：Planned

目标：评估并逐步替代 `net_device->flags` 高位和 `dev->name` 隐藏字节等低层状态存储方式，降低与未来内核或驱动冲突的风险。

注意：这是大改，必须先设计兼容层和回退策略。
