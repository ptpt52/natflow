# Natflow 开发路线图

更新时间：2026-08-15

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

状态：Done

目标：把当前已知但未完整实现的行为逐项分类为“实现”、“保留为不支持”或“废弃”，并同步用户文档和规格。

当前必须覆盖：

- [x] Host ACL 的 `redirect` action 当前没有完整重定向实现。（已实现基于 302 的拦截与配置）
- [x] `natflow_conntrackinfo_ctl` 的 `kickall` 已实现为过滤后的 `conntrack -F`
  语义：清理 `init_net` 中除 fakeuser 和 NATCAP peer 外的已确认 conntrack，
  并要求 `CAP_NET_ADMIN`。
- [x] `/dev/natflow_userinfo_queue` 写接口不再返回 `-ENOSYS`，已统一为 queue `cache=N` 协议。
- [x] `natflow_userinfo_queue`、`natflow_urllogger_queue`、`natflow_dpi_queue` 已支持单次 `read()` 返回多条完整记录；三个 queue 仍不拆分单条记录，小于单条记录的用户 buffer 返回 `-EINVAL`，这是当前 ABI 限制。
- [x] `natflow_userinfo_ctl` 小 buffer read 已改为 per-open residual buffer partial read，与 `conntrackinfo_read()` 行为一致。（P1-1 Done）

退出条件：

- 每个未完成行为都有明确状态和用户可见说明。
- 若选择实现，补对应验证；若选择不支持，`README.md` 和 `SYSTEM_DESIGN_SPEC.md` 明确写出限制。

## P1：质量和兼容性

### P1-1：评估 `natflow_userinfo_ctl` 小 buffer read 兼容性

状态：Done

目标：评估是否把 `natflow_userinfo_ctl` 的小 buffer 读取从直接 `-EINVAL` 改为更兼容的 partial read 或 per-open buffer 行为，或明确保留当前限制。

结果：采用方案 A（per-open residual buffer），在 `userinfo_user` 中增加 `data_off`/`data_len` 字段跟踪残留数据，仿照 `conntrackinfo_read()` 模式实现 partial read。改动约 15 行净变化，不引入新分配，不改变输出格式和遍历逻辑。已同步 `README.md`、`SYSTEM_DESIGN_SPEC.md` 和 `ROADMAP.md`。三个 `natflow_*_queue` 已明确为 batch complete-record read，不纳入本项改造范围。

### P1-2：增强控制输入长度校验

状态：Planned

目标：对 auth rule、bypass ipset、QoS set、zone/vline ifname 等固定长度输入做显式长度校验，减少静默截断导致的误配置。

注意：若为了兼容继续保留截断语义，必须在文档中明确。

### P1-3：重构 vline IPv6 ND/NOARP skb 处理

状态：Planned

目标：把 plain vline IPv6 Ethernet/NOARP 的 Neighbor Advertisement 构造路径改为更明确的 skb length/tailroom helper 流程，并补回归验证。

### P1-4：降低 L7 数据面累计栈占用

状态：Done（第一阶段完成）

目标：在不改变 URLLogger、Host ACL 和 DPI 行为的前提下，把 x86_64
GCC 9.4 完整配置约 1936 字节的模块内部最坏累计调用链降到 1792 字节
以内。第一阶段已通过显式传递 consumer mask 和复用入口 packet view 降至
约 1624 字节；实际 8 KiB 栈目标的运行时复核仍保留为部署验证项。

优先顺序：

1. 消除仅为收窄 `consumer_mask` 创建的 `packet_view` 副本。
2. 让 TCP/UDP producer 在调用方拥有的可写 packet view 上补齐 L4/payload
   字段，避免 dispatcher 和 IPv4/IPv6 helper 重复保留完整 view。
3. 收敛 URL consumer/fallback 的长参数列表，降低 outgoing argument 和保存
   寄存器形成的栈帧。
4. 只有证明重入、CPU migration 和嵌套 hook 归属安全后，才考虑把 hostname
   scratch 改为 per-CPU；不得在 URL allocation fallback 中新增依赖成功分配的
   `GFP_ATOMIC` scratch。

退出条件：完整构建矩阵通过；目标工具链 `.su` 单帧不超过 512 字节；重新
核算入口到 consumer 的累计链；8 KiB 目标完成 stack tracer 压力验证。

## P2：产品化和架构目标

### P2-1：建立构建和回归验证矩阵

状态：In Progress

目标：形成可重复的验证入口，至少覆盖基础构建、`CONFIG_NATFLOW_PATH`、`CONFIG_NATFLOW_URLLOGGER`、`NO_DEBUG=1`，并逐步补 URL parser、QoS、认证状态机和 vline 回归验证。

当前进度：`tools/build-matrix.sh` 已固化七组合 clean build；用户态 v3 ABI 已抽到 `tools/natflow-dpi-event.h`，`tools/natflow-dpi-reader.c`、`tools/natflow-dpi-queue-smoke.c` 和 `tools/natflow-dpi-ctl-smoke.sh` 已提供 DPI queue、结构边界、真实事件固定头和静态控制面冒烟入口；`tests/dpi/run-corpus.sh` 已建立双向 TCP/UDP 注入和 queue event 断言框架，IPv4 首批 51 项于 2026-07-26 真机全部通过；runner 使用 conntrack state match 消除对 path 开关和系统既有 conntrack 使用者的依赖后，同日在 path disabled 状态完成 IPv6 DNS/SSH 20 项和 UDP protocol 31 项真机验证，IPv6 首批 51 项同样全部通过。`tools/natflow-dpi-queue-pressure.c` 和 runner 的 `--queue-pressure` 模式已补小 cache、并发 producer、drop-new 和 lost/accounting 自动化，默认 cache=8/generated=32 已于 2026-07-26 真机通过；`--queue-stream` 的默认 cache=64/generated=128/parallel=16 同日真机通过，128 条事件全部读取且零丢失。IPv6 extension header 明确不支持；精确 TCP segmentation、non-linear skb 专项验证和长时间 soak 暂缓。当前回归矩阵后续重点保留 URL parser corpus、QoS、认证状态机和 vline 自动化。

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

### P2-4：设计并开发 DPI 能力

状态：Hardcoded Classifier Redesign Accepted，M6 Done

目标：在现有 URL logger、Host ACL、conntrack、user/auth、QoS、zone 和 fast path 协作基础上，先统一 L7 parser/context/consumer 生命周期，再实现轻量 DPI 能力，用于协议/应用分类、审计记录和后续策略匹配。

当前 shared L7 基线仍由 `DPI_DESIGN.md` 描述。2026-08-15 已接受
`DPI_HARDCODED_STATE_MACHINE_DESIGN.md` 的分类器重设计：取消用户 domain/proto
规则，改为固定 app catalog 和第五层手写 C 应用状态机，终态直接发布固定
`app_id`；保留 enable、统计和事件观测。M4 已同步删除旧 ruleset 的实现、控制 ABI、
测试假设和当前规格；旧设计章节仅保留为历史记录。

当前迁移进度：M0 设计、ADR 和路线图已冻结；M1 已固定首批 18 个协议应用 ID、
category ID 和 metadata catalog；M2 已让 DPI enabled 直接激活全部内置 protocol
detector，按 proto O(1) 查固定 catalog，并通过 `cmpxchg` 终态提交固定 app/category。
M3 已增加 YouTube=`0x1001`、Netflix=`0x1002`、Telegram=`0x2001` 和 14 项静态域名
表，由 HTTP Host、TLS/QUIC SNI 进入单步硬编码应用机器；exact 优先，suffix 按长度
降序且要求 label boundary。DNS QNAME 只增加 `dns_app_intents`，DNS flow 仍终态为
DNS。M4 已删除 domain/proto ruleset、pending/active RCU 对象、规则 parser/count 和
全部规则 ctl 命令；ctl 只保留 enable、catalog、counters 和 `events_clear`。

实现进度：M0-M1e 的 shared L7、控制/事件 ABI、A 级 detector、双向 bounded context 和测试工具已完成。M2 已加入 FTP、SMTP、POP3、IMAP、SIP、RTSP、MQTT、RESP、MySQL、PostgreSQL、RDP、SMB 共 12 个 audit-only detector；它们按文本、数据库、二进制三组复用剩余 detector mask bit，不扩大 8 字节 conntrack 瞬态 context，并有协议专属正反 corpus。M3 增加 11 项 HTTP Host 静态应用正反 corpus。M5 已把 context 最后两个字节迁移为 16 位 `dpi_automaton`，并以 RDP 实现首台 claimed machine：original X.224 request 与 reply confirm 通过 CAS 单调汇合后才终态，claimed 后不再运行其他 detector。TCP sequence corpus 已覆盖顺序、反序、同时发送、重传、预算和 transport end，当前自动 corpus 共 93 项。M6 已使用 OpenWrt Linux 5.4.281 arm64/GCC 8.4 工具链完成七组合 clean build、静态 fixture/tool/script 检查以及 M4 基线栈和体积对比；DPI packet consumer 栈帧保持 240 字节，完整模块 text 增加 992 字节。审查收口已补齐 conntrack 锁串行、app/context/done 原子终态、packet-only 有界 pull、bridge/inet 去重、`events_clear` quiesce 和 SMB NBSS 长度校验。按维护者“编译验证即可”的验收边界，本轮未加载 arm64 模块，并发双向 packet、bridge、non-linear skb、并发 reset 及新增 corpus 的运行态回归保留为后续目标机验证项。

边界：

- 本仓库仍以 Linux 内核模块为核心；DPI 设计不默认引入完整用户态 DPI daemon、web 服务或大型签名库。
- 现有能力已经覆盖 HTTP Host/URI、TCP TLS SNI、QUIC v1 Initial SNI 和 Host ACL；实现应先抽出 `natflow_l7` 共享 core，让 URL consumer 与 DPI consumer 消费同一次 parser 结果，避免重复实现并行 parser。
- DPI 首期定位为机会性分类和审计能力，不承诺成为强安全 WAF、反规避网关或完整应用识别引擎；ECH、加密内层元数据、异常分片、混淆流量和弱证据端口/IP 命中必须明确降级语义。
- 数据面热路径必须保持有界解析、无阻塞、无大栈对象、无无界循环、少分配；shared L7 等待时使用 `NF_FF_L7_USE`，`natflow_t` 内 DPI 瞬态 context 等待时使用 `NF_FF_DPI_USE`。维护者接受 `nf->status` 非原子 writer 的已知并发丢位风险。
- 新增字符设备命令、sysctl、输出格式、状态位、编译宏或兼容层时，必须同步 `README.md`、`SYSTEM_DESIGN_SPEC.md` 和必要的 `docs/agent/` 记忆。

实现基线：`docs/agent/DPI_IMPLEMENTATION_CHECKLIST.md` 记录每步实现前后的自审口径、legacy URL/Host ACL 兼容基线、conntrack/fast path 约束和自动检查建议。

既有 M0-M4 历史计划保留为当前实现来源。新迁移计划：

1. M0：冻结硬编码分类器设计、固定 ID、状态合同和 ABI 迁移边界。
2. M1：增加固定 app catalog、静态 metadata 和统一 terminal commit helper。
3. M2：让现有 18 个 protocol detector 直接产生固定 `app_id`，同步 corpus。
4. M3：加入 HTTP/TLS/QUIC/DNS 结构化 feature 驱动的静态域名应用状态机。
5. M4：删除用户 ruleset、RCU 规则发布和相关 ctl 命令，同步 README/规格/工具。
6. M5：在不扩大 8 字节 context 的前提下引入 compact automaton word，并只为
   确有多包证据需求的协议实现 A -> B -> C。
7. M6：已完成构建矩阵、静态 corpus/tool 检查、栈和代码体积验证；目标机运行态
   corpus/queue 按本轮验收边界保留为部署验证项。

历史实现阶段：

1. M0：建立 `natflow_l7` core，抽出 read-only packet view、hostname normalize、共享 HTTP/TLS/QUIC parser、bounded prefix 和 consumer mask，保持 legacy URL/Host ACL ABI。
2. M1a：完成 DPI owner bit gate、`app_id` 尾增、layout guard、terminal state、enable/disable、空 ruleset 事务和版本化事件骨架；默认关闭并 fail-open。仅在后续 parser 确需更强跨包状态时增加最小 context，不为配置变化实现 conntrack drain。
3. M1b：完成 domain exact/suffix ruleset，让 URL logger、Host ACL 和 DPI 消费同一次 HTTP/TLS/QUIC parser 结果。
4. M1c：加入 DNS QNAME domain 分类，以及 DNS、SSH、WireGuard 三个首批非 HTTP/TLS/QUIC protocol-only detector，全部 audit-only。
5. M1d：加入 STUN/TURN protocol-only、BitTorrent TCP handshake 和 UDP uTP/DHT 子集，补齐 shadow 统计。
6. M1e：增加 packet direction、方向感知 detector dispatcher、bounded DPI context 和 reply DPI packet consumer；保持 URL/Host ACL/domain host producer original-only。
7. M2：运行生产 shadow，对比 legacy 行为并统计 detector coverage、protocol-only rate、app hit、unknown reason、资源丢失和性能，再按数据加入 B 级 detector。
8. M3：在明确既有 Host ACL/QoS 优先级后，分步评估 app drop/reset 和“仅填空”的 app QoS。
9. M4：仅根据 shadow 数据分别评审 HTTP path/UA、payload signature、JA4、用户态 DNS correlation、更多 QUIC 变体、nDPI IP/证书/cache 类特征或 C 级复杂 detector，不把它们作为首期承诺。

退出条件：

- 设计文档明确统一 L7 core、legacy URL consumer、DPI consumer、能力范围、非目标、ABI、数据面状态机、兼容策略和验证矩阵。
- MVP 不破坏现有 URL logger、Host ACL、user/auth、QoS 和 fast path 行为。
- 新增或修改的用户可见接口在 `README.md` 和 `SYSTEM_DESIGN_SPEC.md` 中有完整说明。
- 至少完成基础构建和 `CONFIG_NATFLOW_PATH` + `CONFIG_NATFLOW_URLLOGGER` 构建验证；若环境缺少内核头文件，必须记录未验证原因。

主要风险：

- 内核热路径解析过重导致转发性能下降。
- 加密、ECH、异常分片和规避流量导致识别率不可控。
- 输出格式或控制 ABI 设计不当会增加后续兼容成本。
- DPI 与 fast path、Host ACL、QoS、认证状态机的状态同步错误可能导致策略绕过或误拦截。
- 运行时 enable 变化不枚举、不退出、不清理已标记连接；既有连接允许自然终态或保留 L7 状态直到 conntrack 生命周期结束。
