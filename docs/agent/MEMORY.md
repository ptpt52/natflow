# Natflow 智能体记忆

更新时间：2026-07-11

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
| `natflow_l7.c/.h` | L7 hook 生命周期骨架和共享 feature core；当前持有 URL hook ops、内核 hook 签名兼容包装、PPPoE normalize/restore、基础 conntrack 过滤和注册/注销流程，向 legacy urllogger consumer 传入 packet view，并提供 host/URI normalize、feature/host view 结构、HTTP Host parser、TLS ClientHello/SNI 搜索、QUIC Initial header/CRYPTO frame/SNI 搜索和 DNS QNAME parser；QUIC crypto context/cache 生命周期仍由 URL logger 持有。 |
| `natflow_dpi.c/.h` | DPI 控制/事件接口；当前提供默认关闭的 `/dev/natflow_dpi_ctl`、domain exact/suffix ruleset、DNS QNAME domain 分类、DNS/SSH/WireGuard/STUN/TURN/BitTorrent protocol-only ruleset、SSH banner/BitTorrent/STUN/TURN 有界 payload detector、match event 队列、source/reason counters、`events_clear` 测试辅助命令和 `app_id` 写入。 |
| `natflow_path.c/.h` | fast path、路由学习、vline/relay、设备 notifier、硬件 offload。 |
| `natflow_user.c/.h` | fakeuser、认证、QoS、用户事件、用户信息控制设备。 |
| `natflow_urllogger.c/.h` | Legacy URL consumer；通过 `natflow_urllogger_consume_url_view()` 消费 L7 packet view，使用公共 host fan-out helper 处理 URL record、Host ACL、DPI classify 和 ACL 回复策略，保留 HTTP Host/URI、TLS/QUIC SNI 的 URL 记录、URL store、Host ACL、302/RST 动作、sysctl 和 QUIC/SNI cache/crypto 资源。 |
| `natflow_zone.c/.h` | LAN/WAN zone 规则、设备 zone 标记、zone notifier。 |
| `natflow_conntrack.c/.h` | `/dev/conntrackinfo_ctl` conntrack dump。 |
| `natflow_compat.h` | 跨内核版本 API 差异兼容。 |
| `docs/agent/DPI_IMPLEMENTATION_CHECKLIST.md` | DPI/L7 实现阶段的每步自审基线，覆盖 legacy URL/Host ACL、conntrack layout、fast path gate 和 DPI ABI。 |

## 长期约束

- 源码是最高优先级事实来源，`SYSTEM_DESIGN_SPEC.md` 是反向整理的长期规格。
- 字符设备命令大多要求单行命令以 `\n` 结束，单条命令长度上限为 `MAX_IOCTL_LEN = 256`。
- `/dev/userinfo_ctl` 的 `idle_time` 复用 fakeuser 内部 `timestamp` 计算，输出值为经过秒数；timestamp 创建/获取 fakeuser 时写入，user pre hook 中普通活动最多每 32 秒刷新一次，新连接包超过 2 秒可刷新；不要用当前 `no_flow_timeout` 和 conntrack 剩余超时反推。
- path 默认关闭，通常通过 `/dev/natflow_ctl` 的 `disabled=0` 开启。
- `CONFIG_NATFLOW_PATH` 控制 fast path、vline/relay 和硬件 offload 相关能力。
- `CONFIG_NATFLOW_URLLOGGER` 控制 URL logger、Host ACL 和相关 sysctl。
- `DPI_DESIGN.md` Draft v5 把 P2 统一为 `natflow_l7` core：共享 packet view、bounded prefix、HTTP/TLS/QUIC/DNS parser、hostname normalize、consumer fan-out 和生命周期；legacy URL/HostACL 是 URL consumer，DPI 是 classifier consumer。外部 `/dev/urllogger_queue`、`/dev/hostacl_ctl`、`/proc/sys/urllogger_store/*` 和 `CONFIG_NATFLOW_URLLOGGER` 保持兼容，不直接重命名；新增 DPI 使用 `/dev/natflow_dpi_ctl`、`/dev/natflow_dpi_queue` 和 `CONFIG_NATFLOW_DPI`。MVP flow result 只在 `natflow_t` 尾部常驻 `u32 app_id`，其他 `proto_id`、`detector_id`、`rule_id`、generation、evidence、confidence 和 reason 只进 terminal event。
- 当前源码已把 bit 19 收敛为 `NF_FF_L7_USE` shared L7 fast-path pause 位，`NF_FF_DPI_USE_BIT=21` 仍预留给后续独立 DPI context 并纳入 `NF_FF_BUSY_USE`，已在 `natflow_t` 尾部追加 `app_id`，`natflow_probe_ct_ext()` 已前置到 main 并可返回 layout guard 错误；`natflow_l7` 已持有 URL hook ops、签名兼容包装、PPPoE normalize/restore、基础 conntrack 过滤和注册/注销流程，并提供共享 packet view、host/URI normalize、feature/host view 结构、HTTP Host parser、TLS ClientHello/SNI 搜索、QUIC Initial header/CRYPTO frame/SNI 搜索、DNS QNAME parser、`NATFLOW_L7_CONSUMER_URL/DPI` mask 和 URL dispatcher；active mask 按 `urllogger_store/enable` 发布 URL consumer，按 DPI enable 和 domain rule 发布 DPI host consumer，统一使用 `IPS_NATFLOW_L7_HANDLED` 控制 shared L7 入口 one-shot。legacy urllogger 通过 `natflow_urllogger_consume_url_view()` 消费 L7 packet view，HTTP/TLS/QUIC host fan-out 已收敛到消费 `natflow_l7_host_view` 的公共 helper，Host ACL 已用 `urllogger_acl_lookup` 与 URL record 分配解耦；`natflow_dpi` 已提供 ctl/queue、domain exact/suffix ruleset、DNS QNAME domain 分类、DNS/SSH/WireGuard/STUN/TURN/BitTorrent protocol-only ruleset、match event producer、source/reason counters、`events_clear` 测试辅助命令和 `app_id` 写入。HTTP/TLS/QUIC host 分类仍依赖 `CONFIG_NATFLOW_URLLOGGER` parser，但不再要求 `/proc/sys/urllogger_store/enable=1`；DNS QNAME domain 分类由 DPI hook 自己解析 TCP/UDP 53 query 第一问；protocol-only detector 是端口/payload 子集 MVP，其中 SSH payload 识别 TCP original direction 的 `SSH-<version>-` banner，BitTorrent payload 已按 TCP handshake 与 UDP uTP/DHT 分流，uTP 会校验版本、类型和扩展号；M1 阶段 DPI protocol-only hook 暂不合并进 L7 URL common path，也不受 `urllogger_store/enable` 控制，等 L7 dispatcher、consumer mask 和 DPI context 生命周期落地后再评审合并入口；QUIC crypto/cache 生命周期迁移、误判 corpus 和生产 shadow 数据尚未实现。维护者接受 `nf->status` 非原子 writer 风险，不做 path 侧 repair。实现阶段每步先按 `docs/agent/DPI_IMPLEMENTATION_CHECKLIST.md` 做自审，人工流量验证和生产 shadow 可暂时跳过但要记录。
- 慢路径依赖 Linux 原生 Netfilter、conntrack、NAT、路由和 bridge 行为，fast path 不能破坏慢路径回退。
- 旧内核兼容是项目价值的一部分，修改 API 适配时要确认版本分支。
- 非 seek 字符设备使用 `natflow_no_llseek()` 保持 `-ESPIPE`，不要直接依赖新旧内核是否暴露 `no_llseek`。
- 热路径要优先考虑性能、RCU/锁语义、skb 可写性、校验和、MTU、TTL/hop-limit、VLAN/PPPoE 和设备生命周期。
- QUIC URL logger 的 crypto/HKDF/shash 临时缓冲放在 per-CPU `urllogger_quic_crypto_ctx` 中，避免包处理路径栈膨胀和 `CONFIG_VMAP_STACK` scatterlist 风险。
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
