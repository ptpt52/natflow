# Natflow 智能体记忆

更新时间：2026-07-18

本文是给智能体快速恢复上下文的压缩记忆，不替代源码。遇到冲突时以源码为准，并修正文档。

## 项目一句话

Natflow 是一个 Linux 内核模块，通过慢路径学习连接和转发信息，再用软件 fast path 或可选硬件 NAT/WED offload 加速后续包，同时提供用户认证、QoS、URL/SNI 记录、Host ACL、zone 标记和 conntrack 观测接口。

## 当前仓库形态

- 主要语言：C，Linux kernel module。
- 构建入口：`Makefile`、`Makefile.dkms`、`dkms.conf`。
- 公共用户文档：`README.md`。
- 实现规格记忆：`SYSTEM_DESIGN_SPEC.md`。
- 智能体入口：`AGENTS.md`。
- 智能体流程和任务记忆：`docs/agent/`。
- 当前开发路线图：`docs/agent/ROADMAP.md`。

当前仓库没有完整用户态 portal/authd/web server 实现，源码重点是内核模块接口与网络策略执行点。

## 模块地图

| 文件 | 主要职责 |
| --- | --- |
| `natflow_main.c` | 模块入口、`/dev/natflow_ctl`、子模块初始化和退出顺序。 |
| `natflow_common.c/.h` | 日志、兼容封装、conntrack 扩展探测、NAT/ipset 包装。 |
| `natflow.h` | 核心数据结构、fastnat 节点、状态位、哈希与超时常量。 |
| `natflow_l7.c/.h` | L7 hook 生命周期骨架和共享 feature core；当前持有 URL/DPI shared hook ops、内核 hook 签名兼容包装、PPPoE normalize/restore、基础 conntrack 过滤、TCP HTTP/TLS producer、QUIC UDP producer、TCP TLS SNI cache、QUIC cache/crypto、DPI packet consumer 调度和注册/注销流程，向 legacy urllogger consumer 或 DPI-only host classifier 传入 host view，并提供 host/URI normalize、feature/host view 结构、HTTP Host parser、TLS ClientHello/SNI 搜索、QUIC Initial header/CRYPTO frame/SNI 搜索和 DNS QNAME parser。L7 packet view 由 producer 填充 L3/L4/payload 指针、conntrack direction、当前 packet `sport/dport`、payload 长度和已线性化的有界 payload 窗口，并提供方向感知的 client/server port helper；当前入口仍跳过 reply。 |
| `natflow_dpi.c/.h` | DPI 控制/事件接口；当前提供默认关闭的 `/dev/natflow_dpi_ctl`、domain exact/suffix ruleset、DNS QNAME domain 分类、DNS/SSH/WireGuard/STUN/TURN/BitTorrent protocol-only ruleset、L7 packet-view consumer、SSH banner/WireGuard/BitTorrent/STUN/TURN 有界 payload detector、match event 队列、source/reason counters、`events_clear` 测试辅助命令和 `app_id` 写入。DPI packet consumer 只消费 L7 packet view，根据 active protocol mask 运行已配置 detector；DNS/payload detector 使用编译期静态 metadata 声明 L4、方向模式和双向 packet/byte budget，pull API 使用 direction 与 server port，端口只选择解析候选，不直接分类。当前仍是 original-only 单包终态。 |
| `natflow_path.c/.h` | fast path、路由学习、vline/relay、设备 notifier、硬件 offload。 |
| `natflow_user.c/.h` | fakeuser、认证、QoS、用户信息控制设备和 `/dev/natflow_userinfo_queue` 二进制认证事件队列。 |
| `natflow_urllogger.c/.h` | Legacy URL consumer；通过 `natflow_urllogger_consume_host_view()` 消费 L7 host view，处理 URL record、Host ACL、DPI classify 和 ACL 回复策略，保留 HTTP Host/URI、TLS/QUIC SNI 的 URL 记录、URL store、Host ACL、302/RST 动作和 sysctl 资源。`/dev/natflow_urllogger_queue` 只允许一个 reader；没有 reader 或 reader 未写入正数 `cache=N` 时 URL/SNI record 在 ACL/DPI 处理后直接丢弃，不缓存到 URL store。 |
| `natflow_zone.c/.h` | LAN/WAN zone 规则、设备 zone 标记、zone notifier。 |
| `natflow_conntrack.c/.h` | `/dev/natflow_conntrackinfo_ctl` conntrack dump。 |
| `natflow_compat.h` | 跨内核版本 API 差异兼容。 |
| `docs/agent/DPI_IMPLEMENTATION_CHECKLIST.md` | DPI/L7 实现阶段的每步自审基线，覆盖 legacy URL/Host ACL、conntrack layout、fast path gate 和 DPI ABI。 |

## 长期约束

- 源码是最高优先级事实来源，`SYSTEM_DESIGN_SPEC.md` 是反向整理的长期规格。
- 字符设备命令大多要求单行命令以 `\n` 结束，单条命令长度上限为 `MAX_IOCTL_LEN = 256`。
- `/dev/natflow_userinfo_ctl` 的 `idle_time` 复用 fakeuser 内部 `timestamp` 计算，输出值为经过秒数；timestamp 创建/获取 fakeuser 时写入，user pre hook 中普通活动最多每 32 秒刷新一次，新连接包超过 2 秒可刷新；不要用当前 `no_flow_timeout` 和 conntrack 剩余超时反推。
- path 默认关闭，通常通过 `/dev/natflow_ctl` 的 `disabled=0` 开启。
- `CONFIG_NATFLOW_PATH` 控制 fast path、vline/relay 和硬件 offload 相关能力。
- `CONFIG_NATFLOW_URLLOGGER` 控制 URL logger、Host ACL 和相关 sysctl。
- `DPI_DESIGN.md` Draft v7 把 P2 统一为 `natflow_l7` core：共享 packet view、bounded prefix、HTTP/TLS/QUIC/DNS parser、hostname normalize、consumer fan-out 和生命周期；legacy URL/HostACL 是 URL consumer，DPI 是 classifier consumer。当前 URL queue 外部接口已统一命名为 `/dev/natflow_urllogger_queue`，输出版本化二进制 URL event；`/dev/hostacl_ctl`、`/proc/sys/urllogger_store/*` 和 `CONFIG_NATFLOW_URLLOGGER` 继续保持。新增 DPI 使用 `/dev/natflow_dpi_ctl`、`/dev/natflow_dpi_queue` 和 `CONFIG_NATFLOW_DPI`。MVP flow result 只在 `natflow_t` 尾部常驻 `u32 app_id`，其他 `proto_id`、`detector_id`、`rule_id`、generation、direction、evidence、confidence 和 reason 只进 active context 或 terminal event。protocol detector 按 `ORIGINAL_ONLY`、`REPLY_ONLY`、`EITHER` 或 `BOTH` 声明方向，只有等待方向、跨包或关联状态时才分配 bounded context。
- 当前源码已把 bit 19 收敛为 `NF_FF_L7_USE` shared L7 fast-path pause 位，`NF_FF_DPI_USE_BIT=21` 仍预留给后续独立 DPI context 并纳入 `NF_FF_BUSY_USE`，`NF_FF_L7_URL_DONE_BIT=22`、`NF_FF_L7_DPI_DOMAIN_DONE_BIT=23` 和 `NF_FF_L7_DPI_PACKET_DONE_BIT=24` 在 `natflow_t.status` 中分别记录 URL、DPI domain 与 DPI packet consumer 终态，已在 `natflow_t` 尾部追加 `app_id`，`natflow_probe_ct_ext()` 已前置到 main 并可返回 layout guard 错误；`natflow_l7` 已持有 URL/DPI shared hook ops、签名兼容包装、PPPoE normalize/restore、基础 conntrack 过滤、TCP HTTP/TLS producer、QUIC UDP producer、TCP TLS SNI cache、QUIC cache/crypto 和注册/注销流程，并提供共享 packet view、host/URI normalize、feature/host view 结构、HTTP Host parser、TLS ClientHello/SNI 搜索、QUIC Initial header/CRYPTO frame/SNI 搜索、DNS QNAME parser、`NATFLOW_L7_CONSUMER_URL/DPI_DOMAIN/DPI_PACKET` mask 和 packet dispatcher；active mask 按 `urllogger_store/enable` 发布 URL consumer，按 DPI domain/proto 规则分别发布 DPI domain 与 DPI packet consumer。L7 入口先检查 `IPS_NATFLOW_L7_HANDLED` L7_SKIP 派生 hint，未命中时再用 `natflow_session_in()` 统一确保终态有 `natflow_t.status` 可写，创建失败则 fail-open 跳过解析；创建成功后扣除对应 done bit，URL done 不关闭 DPI，DPI packet done 不关闭仍在等待 SNI/DNS QNAME 的 DPI domain，DPI domain done 不关闭 URL，active consumer 全部 done 后才清 `NF_FF_L7_USE` 并设置 L7_SKIP hint。该 hint 不替代 per-consumer done bit，运行时新启用的 URL/DPI consumer 或新提交规则不会自动重新武装已 L7_SKIP 的旧连接。legacy urllogger 通过 `natflow_urllogger_consume_host_view()` 消费 L7 host view；DPI-only 时 L7 直接调用 `natflow_dpi_classify_host()`；HTTP/TLS/QUIC host fan-out 已收敛到 `natflow_l7_host_view`，Host ACL 已用 `urllogger_acl_lookup` 与 URL record 分配解耦；`natflow_dpi` 已提供 ctl/queue、domain exact/suffix ruleset、DNS QNAME domain 分类、DNS/SSH/WireGuard/STUN/TURN/BitTorrent protocol-only ruleset、L7 packet-view consumer、match event producer、source/reason counters、`events_clear` 测试辅助命令和 `app_id` 写入。HTTP/TLS/QUIC host 分类、DNS QNAME domain 分类和 protocol-only detector 均从 L7 shared hook 入口消费，不依赖 `/proc/sys/urllogger_store/enable`；DPI packet consumer 现在直接消费 L7 producer 填好的 L4/payload 指针、payload 长度和 `payload_linear_len`，不再自行重解析 IPv4/IPv6 skb；`CONFIG_NATFLOW_URLLOGGER_LOCAL_IN` 只收窄 URL logger，若同时编译 DPI，L7 额外注册 DPI-only FORWARD/bridge hook；protocol-only detector 是端口/payload 子集 MVP，其中 SSH payload 识别 TCP original direction 的 `SSH-<version>-` banner，BitTorrent payload 已按 TCP handshake 与 UDP uTP/DHT 分流，uTP 会校验版本、类型和扩展号；误判 corpus 和生产 shadow 数据尚未实现。维护者接受 `nf->status` 非原子 writer 风险，不做 path 侧 repair。实现阶段每步先按 `docs/agent/DPI_IMPLEMENTATION_CHECKLIST.md` 做自审，人工流量验证和生产 shadow 可暂时跳过但要记录。
- 2026-07-18 新约束：运行时 URL/DPI enable、DPI `rules_commit` 和 `rules_clear` 只控制后续 active consumer/ruleset，不枚举、不退出、不清理已经标记的连接，也不因配置变化引入全局 conntrack registry。已设置 L7_SKIP 的连接不重新武装；仍在自然解析路径中的连接可以继续终态，也可以保留原 L7 owner/done 状态直到 conntrack 生命周期结束。配置切换不保证立即恢复既有连接的 fast path。
- 2026-07-18 protocol-only detector 收紧为直接协议证据：DNS 必须解析为 TCP/UDP 53 标准 query，SSH 必须匹配 original-direction banner，WireGuard 必须通过 UDP message type/reserved bytes/长度校验；TCP 22 和 UDP 51820 不再直接分类。数据面通过 active protocol mask 跳过未配置 detector。
- 2026-07-18 双向 DPI 设计合同：reply 首期只进入 DPI packet consumer，URL/Host ACL/HTTP-TLS-QUIC host/DNS QNAME domain 保持 original-only；detector 编译期声明 `ORIGINAL_ONLY`、`REPLY_ONLY`、`EITHER` 或 `BOTH`，初始预算为每方向 4 个 payload 包和 4 秒，等待状态使用 bounded context 与 `NF_FF_DPI_USE`，不能因无关方向未出现永久阻塞 fast path。当前源码尚未实现 reply 准入。
- 2026-07-18 M1e 方向基础设施已在 packet view 增加 conntrack direction、当前 packet `sport/dport` 和方向感知的 client/server port helper；IPv4/IPv6 TCP/UDP producer 对称填充。reply 仍在公共入口被过滤，运行行为尚未改为双向。
- 2026-07-18 M1e detector dispatcher 已改为固定 metadata 表：DNS、STUN/TURN、SSH、WireGuard、BitTorrent 声明 L4、方向模式、original/reply packet/byte budget，payload 最多按固定顺序尝试 4 个 detector family；pull length 同时依据 consumer mask、active proto mask、direction 和 server port。当前 metadata 均为 `EITHER`，但 reply 仍被入口过滤，context/跨方向终态尚未实现。
- `/dev/natflow_userinfo_queue`、`/dev/natflow_urllogger_queue` 和 `/dev/natflow_dpi_queue` 只允许一个 reader，默认 cache 为 0；三者都使用 reader count + cache limit 控制入队，reader 打开时清空残留队列并要求同一个 O_RDWR fd 写入正数 `cache=N` 才缓存新事件，最多缓存 N 条，队列满时丢弃新事件；写入 `cache=0` 或关闭 fd 会关闭缓存并清空未读事件；未知 queue 写命令返回 `-EINVAL`。三个队列 `read()` 空队列都返回 0，不挂起，不返回 partial record；用户 buffer 足够时单次 `read()` 可返回多条完整记录，`poll()` 在有可读事件时返回 readable。URL logger 的 `memsize_limit/memsize/count_limit` sysctl 已废弃，`count` 只观测当前待读 URL 记录数；DPI 不再有固定 1024 事件上限。DPI 事件 `timestamp` 是 uptime 秒数，与 URL logger 一致；事件 ABI 为 v2 固定头并包含 original tuple 的 `family/l4proto/tuple_dir/sport/dport/sip/dip`。URL 输出 v2 `natflow_urllogger_event_hdr` 加不带结尾 NUL 的 `host + uri` payload；userinfo 输出 v2 固定头 `natflow_userinfo_event_hdr`，字段语义与 `/dev/natflow_userinfo_ctl` 文本快照一致。
- 慢路径依赖 Linux 原生 Netfilter、conntrack、NAT、路由和 bridge 行为，fast path 不能破坏慢路径回退。
- 旧内核兼容是项目价值的一部分，修改 API 适配时要确认版本分支。
- 非 seek 字符设备使用 `natflow_no_llseek()` 保持 `-ESPIPE`，不要直接依赖新旧内核是否暴露 `no_llseek`。
- 热路径要优先考虑性能、RCU/锁语义、skb 可写性、校验和、MTU、TTL/hop-limit、VLAN/PPPoE 和设备生命周期。
- QUIC crypto/HKDF/shash 临时缓冲放在 L7 per-CPU `natflow_l7_quic_crypto_ctx` 中，避免包处理路径栈膨胀和 `CONFIG_VMAP_STACK` scatterlist 风险；crypto 初始化失败只禁用 QUIC hostname parser，不导致 URL logger 或 L7 初始化失败。
- L7/DPI 数据面栈预算按入口到 consumer 的整条调用链评估，不按单个函数帧孤立评估；HTTP host view 可携带原始 Host 和 `host_flags`，URL/DPI consumer 在边界 normalize，已规范化的 URL/ACL/DNS host 走 DPI normalized classify，URL record 分配失败的 `urllogger_acl_lookup` 大对象只应出现在异常 fallback。
- 2026-07-12 对 `11824c1..9dbcba7` 的 L7/DPI 收尾确认结论：代码审查未发现阻断问题，`git diff --check HEAD~2..HEAD` 和串行构建矩阵通过，维护者真机测试未发现问题。已覆盖 default、`CONFIG_NATFLOW_URLLOGGER`、`CONFIG_NATFLOW_DPI`、URLLOGGER+DPI、PATH+URLLOGGER+DPI、NO_DEBUG PATH+URLLOGGER+DPI，以及 `CONFIG_NATFLOW_URLLOGGER_LOCAL_IN` 和 LOCAL_IN+DPI 的 `-Wall -Werror -Wno-stringop-overread` 构建面；当前 Kbuild 未生成 `.su` 栈用量文件，栈结论仍基于源码审查和编译告警。
- 2026-07 对 `e3c6601..5430b33` 的提交审核结论：本仓库风格是慢路径保持 Linux 原生语义、fast path 做机会性加速；新增能力后通常继续收紧边界、资源归属、RCU 和 ABI 文档。
- 包处理路径访问头部前必须先证明数据可读，写 skb 前必须确认可写；`pskb_may_pull()`、`skb_try_make_writable()`、`skb_cow_head()`、trim/csum 后要重新获取 `iph`/`l4`/payload 指针。
- 策略模块在等待认证、URL/SNI/QUIC 解析、L7 detector 或 Host ACL 决策时必须设置对应 busy bit，完成后再清除，避免 fast path 提前接管。
- 控制面写、数据面读的共享对象优先采用“mutex 串行构造新对象 + RCU 发布 + grace period 后释放”的模式；临时 cache、skb/data buffer 必须有清晰唯一 owner，attach 成功后调用方不要再释放。
- 所有外部输入和内核状态值都按不可信处理：`sscanf` 要有宽度，字符串要保留 NUL，zone id、ifindex、TCP state、QUIC/TLS 长度字段都要先做边界检查。
- PPPoE bridge 场景会临时调整 `skb->protocol`、`network_header` 和 data 指针；任何等待更多数据、drop、reset、redirect 或错误返回都必须走统一恢复路径。

## 常用验证

文档或格式检查：

```sh
git diff --check
```

基础构建：

```sh
make
```

启用常用能力构建：

```sh
make EXTRA_CFLAGS="-DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER"
```

关闭调试日志的构建：

```sh
make NO_DEBUG=1 EXTRA_CFLAGS="-DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER"
```

当前环境可能缺少目标内核头文件。无法构建时要记录失败原因，不要把未验证说成已验证。

## 记忆维护协议

智能体完成任务时按影响面维护记忆：

- 改了用户可见行为：更新 `README.md`。
- 改了内部流程、状态、兼容约束或数据结构：更新 `SYSTEM_DESIGN_SPEC.md`。
- 改了智能体协作方式或后续任务入口：更新 `AGENTS.md` 或 `docs/agent/WORKFLOW.md`。
- 做了长期架构取舍：更新 `docs/agent/DECISIONS.md`。
- 发现关键事实可压缩成后续上下文：更新本文件。

记忆应该短、准、可验证。不要把临时推测、未确认结论或长篇源码复述写成长期记忆。

## 后续工作展开方式

有了智能体仓库后，后续任务应从“补上下文”变成“执行闭环”：

1. 用 `docs/agent/TASK_TEMPLATE.md` 描述目标、边界、验证标准和交付物。
2. 对齐 `docs/agent/ROADMAP.md` 中的目标和优先级。
3. 智能体读取本文件、相关源码和规格。
4. 智能体实施最小改动并运行验证。
5. 智能体把新增事实写回对应记忆文件。
6. 下一轮智能体从更新后的记忆继续工作，不从零开始。
