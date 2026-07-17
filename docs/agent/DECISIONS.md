# 智能体决策记录

本文件记录需要后续智能体长期遵守的仓库级决策。小型实现细节不要放在这里。

## ADR-0001：采用“仓库即智能体记忆”结构

日期：2026-07-04

状态：Accepted

### 背景

Natflow 是一个跨内核版本、跨网络子系统的 C 内核模块。单次 AI 会话容易丢失上下文，重复扫描成本高，也容易遗漏字符设备协议、fast path 回退、兼容层和热路径约束。

### 决策

将可复用的智能体上下文直接版本化到仓库中：

- `AGENTS.md` 作为所有智能体的启动入口。
- `docs/agent/MEMORY.md` 保存压缩项目记忆。
- `docs/agent/WORKFLOW.md` 保存任务闭环和记忆维护规则。
- `docs/agent/TASK_TEMPLATE.md` 提供后续任务输入格式。
- `SYSTEM_DESIGN_SPEC.md` 继续作为实现级长期规格。
- `README.md` 继续作为人类用户手册。

### 后果

- 后续智能体应先读取仓库内记忆，而不是从空白上下文开始。
- 行为、接口和设计约束变化时，文档更新成为改动的一部分。
- 记忆必须保持短、准、可验证，避免把聊天记录或推测写入仓库。
- 这个结构不引入运行时代码，不改变内核模块行为。

## ADR-0002：DPI 采用有界 detector 框架而非 nDPI 全量内核移植

日期：2026-07-10

状态：Accepted

### 背景

Natflow 需要识别 HTTP/TLS/QUIC 以外的应用流量，用于后续审计、过滤和 QoS。但仓库是 Linux 内核模块，数据面处在转发热路径，同时还要和 fast path、conntrack、Host ACL、认证、QoS、旧内核兼容和可选硬件 offload 协作。把 nDPI 全库或大正则/大签名库直接移入内核，会引入不可控的 CPU、内存、ABI 和维护成本。

### 决策

DPI 能力采用有界 L7 detector 框架：

- 复用现有 HTTP Host、TLS SNI、QUIC Initial SNI 解析，但不把 DPI 限定为域名分类。
- 非 HTTP/TLS/QUIC 流量通过编译期内置的小状态机 detector 进入，首批只选择 DNS、STUN、SSH、BitTorrent handshake/DHT、WireGuard 等高确定性协议中的子集。
- nDPI 只作为参考来源：DPI detector、`host_match[]` 域名、IP/证书/cache/复合协议能力必须分层评审；Natflow UAPI 不复制 nDPI enum。
- 默认应用规则包只纳入 nDPI 可落地的域名项；IP-only/CDN、证书、缓存和品牌私有 detector 不作为 M1 域名包能力。
- M1 拆成 M1a gate/ABI、M1b HTTP/TLS/QUIC+domain、M1c DNS/SSH/WireGuard、M1d STUN/BitTorrent 子集，避免一次性重写整个 L7 子系统。
- 每个 detector 必须声明方向、包数、字节数、候选裁剪、误判模型、资源上限和 corpus；默认正反向各不超过 4 个 payload 包。
- 端口、IP/CIDR、DNS 关联和其他弱证据不能单独触发阻断。
- 结果以 Natflow 自有 `proto_id`、`detector_id`、`app_id`、confidence 和 terminal reason 输出，不复制 nDPI enum 作为 UAPI。

### 后果

- 后续实现必须先完成 `NF_FF_DPI_USE`/`NF_FF_BUSY_USE` gate、统一 packet view、detector dispatcher、事务规则、版本化事件和资源硬上限；`nf->status` 非原子风险被接受为当前工程约束，不因 DPI 引入 path 侧 repair。
- 新增 detector 必须逐个评审，不能通过通用 payload contains、回溯正则、用户态 bytecode 或线性规则扫描绕过热路径约束。
- M1 默认 audit-only 和 fail-open；drop/reset/QoS 必须等 shadow 数据证明误判可控后再分阶段开放。
- 这个决策改变的是目标设计，不代表当前源码已经提供 DPI ABI 或应用识别行为。

## ADR-0003：L7 统一命名和 URL/HostACL ABI

日期：2026-07-11

状态：Amended 2026-07-12

### 背景

现有 `natflow_urllogger.c` 同时承担 HTTP/TLS/QUIC 元数据提取、URL event 存储、Host ACL、reset/redirect/drop 动作和 sysctl 控制。后续 DPI 需要复用这些 parser，但不能把现有用户接口直接改名为 DPI，也不能让 URL logger 和 DPI 并行重复解析同一 payload。

### 决策

内部统一抽象命名为 `natflow_l7`：

- `natflow_l7` 负责 read-only packet view、bounded prefix、HTTP/TLS/QUIC parser、hostname normalize、共享 context、consumer fan-out 和资源生命周期。
- legacy URL logger 与 Host ACL 是 L7 的 URL consumer，继续保留 `/dev/hostacl_ctl`、`/proc/sys/urllogger_store/*` 和 `CONFIG_NATFLOW_URLLOGGER`；URL queue 用户接口为 `/dev/natflow_urllogger_queue`，输出版本化二进制 URL event。
- DPI 是 L7 的 classifier consumer，新增 `/dev/natflow_dpi_ctl`、`/dev/natflow_dpi_queue` 和 `CONFIG_NATFLOW_DPI`。
- `/proc/sys/urllogger_store/enable=0` 仍表示 URL event 和 Host ACL 都不执行；DPI host consumer 可独立使用 HTTP/TLS/QUIC host parser，但 DPI enable 不能让 Host ACL 悄悄生效。
- M1 阶段 DPI protocol-only hook 继续由 `natflow_dpi.c` 独立持有，不合并进 L7 URL common path，也不受 `urllogger_store/enable` 控制；只有在 L7 dispatcher、consumer mask 和 DPI context 生命周期落地后，才重新评审统一入口。
- MVP 常驻 flow result 仍只有 `app_id`，其他分类细节进入 terminal event。

### 后果

- 实现应先拆出 L7 core，再迁移 legacy URL logger 消费 shared features，最后接入 DPI consumer。
- 可以调整内部文件和函数名，但不能破坏当前 URL/Host ACL 命令、sysctl 路径或事件格式。
- URL queue 已从旧 CSV ABI 迁移到 `/dev/natflow_urllogger_queue` 二进制 ABI；后续审查以源码、`README.md` 和 `SYSTEM_DESIGN_SPEC.md` 的当前 ABI 为准。

## ADR-0004：L7 配置变化不清理已标记连接

日期：2026-07-18

状态：Accepted

### 背景

DPI enable、ruleset commit/clear 和 URL consumer enable 变化后，可以通过全局 conntrack registry 枚举并强制完成已经设置 `NF_FF_L7_USE` 的连接，也可以把配置变化限定为后续流量准入。前一种方案会增加 conntrack 引用、全局状态、drain 同步和旧内核兼容复杂度。

### 决策

- 运行时配置变化只控制后续数据包看到的 active consumer 和 active ruleset。
- 不为 enable、rules commit、rules clear 或模块退出枚举 conntrack，不强制退出、补写 terminal 或清理已经标记的连接。
- 已设置 `IPS_NATFLOW_L7_HANDLED` 的连接不重新武装。
- 仍在自然解析路径中的连接若再次分类，读取当时发布的 active ruleset，不 pin arm 时 generation。
- 已标记连接允许自然终态，也允许保留 L7 owner/done 状态直到 conntrack 生命周期结束；配置切换不保证立即恢复其 fast path。
- 后续只有 parser/detector 本身确需更强跨包状态时，才评审最小 context，不得以配置清理为理由引入全局 conntrack registry。

### 后果

- DPI `enable=0`、`rules_clear` 和规则替换保持常数级控制面操作，不执行全表扫描或 drain。
- 配置切换后的验证必须使用新连接；不能用既有连接判断新规则是否生效。
- 运维若要求立即应用新配置，需要在用户态显式重建相关连接；内核 ABI 不提供隐式连接清理。
