# Natflow 开发路线图

更新时间：2026-07-18

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
- `natflow_conntrackinfo_ctl` 的 `kickall` 当前没有实际清理行为。
- [x] `/dev/natflow_userinfo_queue` 写接口不再返回 `-ENOSYS`，已统一为 queue `cache=N` 协议。
- [x] `natflow_userinfo_queue`、`natflow_urllogger_queue`、`natflow_dpi_queue` 已支持单次 `read()` 返回多条完整记录；三个 queue 仍不拆分单条记录，小于单条记录的用户 buffer 返回 `-EINVAL`，这是当前 ABI 限制。
- `natflow_userinfo_ctl` 小 buffer read 当前返回 `-EINVAL`，不是 partial read；是否改善已作为 P1-1 兼容性任务保留。

退出条件：

- 每个未完成行为都有明确状态和用户可见说明。
- 若选择实现，补对应验证；若选择不支持，`README.md` 和 `SYSTEM_DESIGN_SPEC.md` 明确写出限制。

## P1：质量和兼容性

### P1-1：评估 `natflow_userinfo_ctl` 小 buffer read 兼容性

状态：Planned

目标：评估是否把 `natflow_userinfo_ctl` 的小 buffer 读取从直接 `-EINVAL` 改为更兼容的 partial read 或 per-open buffer 行为，或明确保留当前限制。

注意：这是用户可见行为变化，必须同步文档。三个 `natflow_*_queue` 已支持 batch complete-record read，且当前 ABI 明确不返回 partial record，不再纳入本项改造范围。

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

当前进度：`tools/build-matrix.sh` 已固化七组合 clean build；用户态 v3 ABI 已抽到 `tools/natflow-dpi-event.h`，`tools/natflow-dpi-reader.c`、`tools/natflow-dpi-queue-smoke.c` 和 `tools/natflow-dpi-ctl-smoke.sh` 已提供 DPI queue、结构边界、真实事件固定头和空 ruleset 控制事务入口；`tests/dpi/run-corpus.sh` 已建立 IPv4 network namespace、双向 TCP/UDP 注入和 queue event 断言框架，首批 corpus 已覆盖 DNS、SSH、WireGuard、STUN/TURN 和 BitTorrent 正反样本。真机执行、队列满/并发流量、URL parser corpus、QoS、认证状态机和 vline 自动回归仍未完成。

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

状态：M1e Done，M2 Preparation

目标：在现有 URL logger、Host ACL、conntrack、user/auth、QoS、zone 和 fast path 协作基础上，先统一 L7 parser/context/consumer 生命周期，再实现轻量 DPI 能力，用于协议/应用分类、审计记录和后续策略匹配。

当前设计基线：`DPI_DESIGN.md`。Draft v7 把内部目标统一为 `natflow_l7` core：共享 read-only packet view、bounded prefix、HTTP/TLS/QUIC parser、hostname normalize、consumer fan-out 和资源生命周期；legacy URL logger/Host ACL 作为 URL consumer 保持外部 ABI，DPI 作为 classifier consumer 新增独立控制和事件 ABI；运行时配置变化不枚举或清理已标记连接；protocol detector 按 `ORIGINAL_ONLY`、`REPLY_ONLY`、`EITHER` 或 `BOTH` 声明方向，并仅在等待方向、跨包或关联状态时分配 bounded context。本文档仍是目标设计，不代表源码已实现全部规划行为。

实现进度：源码已完成 M0b 的 DPI busy bit、`app_id` 尾增和 layout guard，完成 M0c 的 `natflow_l7` hook lifecycle 骨架、共享 feature/normalize 基础结构、URL/DPI shared hook ops、签名兼容包装迁移、PPPoE normalize/restore 和 packet view/host view 传递、L7 consumer mask/API 与 packet dispatcher、HTTP Host parser、TLS ClientHello/SNI 搜索、TCP HTTP/TLS producer 迁移、TCP TLS SNI cache 生命周期迁移、QUIC Initial header/CRYPTO frame/SNI 搜索迁移、QUIC cache/crypto 生命周期迁移、QUIC UDP producer 迁移、DNS QNAME parser 和 `natflow_l7_host_view` consumer 输入 contract，完成 M0d 的 Host ACL 与 URL record 分配解耦，完成 M1a 的 DPI ctl/queue 设备骨架，完成 M1b 的 domain exact/suffix ruleset、match event producer、DPI host consumer 独立激活和复用 urllogger host 的 `app_id` 写入，完成 M1c 的 DNS 标准 query、SSH banner 和 WireGuard 结构校验 protocol-only detector，并完成 M1d 的 STUN/TURN、BitTorrent TCP handshake、UDP uTP/DHT 子集、source/reason counters 和 `events_clear` 测试辅助命令；DPI protocol-only detector 已从独立 hook 收敛到 L7 shared hook 的 packet-view consumer，根据 active protocol mask 只运行已配置 detector，端口只选择解析候选而不直接分类。M1e 已完成 packet view direction、方向感知端口、静态 detector metadata dispatcher、`natflow_t` 尾部 8 字节 bounded context，以及 reply DPI packet consumer；URL、Host ACL 和 domain host producer 保持 original-only。当前进入 M2 准备阶段，DPI event ABI v3 已增加独立 evidence direction，match/event、domain、双向 packet 和 context shadow counters 已补齐；七组合构建、v3 queue 参考 reader、queue/ctl smoke 和首批 protocol-only 黑盒 corpus 已建立，后续运行真机 ABI/corpus 回归和生产 shadow。生产 shadow 数据尚未实现。

边界：

- 本仓库仍以 Linux 内核模块为核心；DPI 设计不默认引入完整用户态 DPI daemon、web 服务或大型签名库。
- 现有能力已经覆盖 HTTP Host/URI、TCP TLS SNI、QUIC v1 Initial SNI 和 Host ACL；实现应先抽出 `natflow_l7` 共享 core，让 URL consumer 与 DPI consumer 消费同一次 parser 结果，避免重复实现并行 parser。
- DPI 首期定位为机会性分类和审计能力，不承诺成为强安全 WAF、反规避网关或完整应用识别引擎；ECH、加密内层元数据、异常分片、混淆流量和弱证据端口/IP 命中必须明确降级语义。
- 数据面热路径必须保持有界解析、无阻塞、无大栈对象、无无界循环、少分配；shared L7 等待时使用 `NF_FF_L7_USE`，`natflow_t` 内 DPI 瞬态 context 等待时使用 `NF_FF_DPI_USE`。维护者接受 `nf->status` 非原子 writer 的已知并发丢位风险。
- 新增字符设备命令、sysctl、输出格式、状态位、编译宏或兼容层时，必须同步 `README.md`、`SYSTEM_DESIGN_SPEC.md` 和必要的 `docs/agent/` 记忆。

实现基线：`docs/agent/DPI_IMPLEMENTATION_CHECKLIST.md` 记录每步实现前后的自审口径、legacy URL/Host ACL 兼容基线、conntrack/fast path 约束和自动检查建议。

计划：

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
- 运行时 enable 和 ruleset 变化不枚举、不退出、不清理已标记连接；既有连接允许自然终态或保留 L7 状态直到 conntrack 生命周期结束。
