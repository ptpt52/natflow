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
- MVP 常驻分类结果仍只有 `app_id`；8 字节瞬态预算 context 不属于分类结果，其他分类细节进入 terminal event。

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

## ADR-0005：DPI detector 按需声明流量方向

日期：2026-07-18

状态：Accepted

### 背景

L7 reply 入口只准入 DPI packet consumer，`NF_FF_L7_DPI_PACKET_DONE` 是连接级单一终态。URL、Host ACL 和 domain host producer 继续 original-only；方向预算避免任一方向首包过早关闭另一个方向。

### 决策

- 编译期 detector metadata 必须声明 `ORIGINAL_ONLY`、`REPLY_ONLY`、`EITHER` 或 `BOTH`，方向模式不作为首期规则参数开放。
- URL logger、Host ACL、HTTP request Host、TLS ClientHello SNI、QUIC client Initial SNI 和 DNS QNAME domain 保持 original-only；reply 首期只进入 DPI packet consumer。
- `ORIGINAL_ONLY` 不等待 reply；`REPLY_ONLY` 只消费 reply；`EITHER` 允许任一方向确认但一侧未命中不能关闭另一侧；`BOTH` 必须有界关联两个方向，禁止简单拼接上下行字节。
- 只有等待方向或后续 packet 的 detector 才使用 `natflow_t` 尾部 8 字节 bounded context。常驻 conntrack 分类结果仍只有 `app_id`；context 仅保存双向预算和 detector mask。
- context 等待期间使用 `NF_FF_DPI_USE` 阻止 fast path；任一 detector 命中，或所有 active detector 因 FIN/RST、packet/byte budget 终态后，连接级 DPI packet consumer 才终态。
- context 存续期间允许 `NF_FF_L7_USE | NF_FF_DPI_USE` 同时存在，分别表示 shared hook 继续提供 packet view 和 DPI context owner；不能在 owner bit 交接中产生无 busy-bit 窗口。其他 consumer 已写入 `app_id` 时，packet consumer 以 `APP_EXISTS` 终态。
- 初始预算为 original/reply 各 4 个 payload 包，不设置时间 deadline。所需方向始终无 payload时，context 可保留到 conntrack 生命周期结束；配置变更不枚举、drain 或清理 context。

### 后果

- packet view 和 detector dispatcher 必须先补齐 direction 与 client/server port 语义，再放开 reply hook。
- 单向 detector 不为无关方向付出等待成本，双向 detector 也不能被任一方向首包提前关闭。
- 事件 ABI 后续需要独立记录 evidence direction，同时保持 original tuple 作为稳定连接身份；该 ABI 变化不属于本 ADR 的当前实现步骤。

## ADR-0006：L7 最低线程栈和单帧预算

日期：2026-07-18

状态：Amended 2026-07-18

### 背景

完整 URLLogger+DPI 构建在 x86_64 GCC 9.4 下测得模块内部最坏累计 L7
调用链约 1936 字节。累计值之外还存在 Netfilter/conntrack 上游和外部内核
函数栈，不能把单函数无告警当作整条数据面调用链安全。

### 决策

- 启用 `CONFIG_NATFLOW_URLLOGGER` 或 `CONFIG_NATFLOW_DPI` 时要求
  `THREAD_SIZE >= 8192`，更小的平台在编译期拒绝。
- `natflow_l7.o`、`natflow_dpi.o` 和 `natflow_urllogger.o` 的单函数栈帧
  上限为 512 字节，并由对象级 `-Werror=frame-larger-than=512` 转为构建
  失败，不依赖调用方是否覆盖全局 `EXTRA_CFLAGS`。
- 512 字节单帧限制不替代累计调用链审核；目标架构和工具链仍须用
  `-fstack-usage` 复核，8 KiB 平台还须做运行时栈余量测试。

### 后果

- 完整 L7 功能不支持 4 KiB 内核线程栈。
- 后续 parser、detector 和 consumer 不得通过拆函数规避累计栈预算；累计链
  接近当前约 2 KiB 基线时，应优先复用 view、缩短调用链或使用有明确并发
  归属的 per-CPU scratch，再扩大识别能力。
- 第一阶段通过显式传递 narrowed consumer mask 和复用入口 packet view，
  把同一 x86_64 GCC 9.4 完整配置的模块内部最坏累计链从约 1936 字节降至
  约 1624 字节；当前不引入 per-CPU hostname scratch。
