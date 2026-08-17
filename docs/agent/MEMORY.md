# Natflow 智能体记忆

更新时间：2026-08-17

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
| `natflow_l7.c/.h` | L7 hook 生命周期和共享 feature core；packet view 携带 direction、当前 `sport/dport` 和 conntrack original client/server ports。reply 在公共 FORWARD 入口被收窄为 DPI packet consumer，URL、Host ACL 和 domain host producer 保持 original-only；DPI 另有 DNS-only LOCAL_IN。 |
| `natflow_dpi.c/.h` | DPI 控制/事件接口；DPI enabled 后 packet consumer 根据 L4、方向和 discovery machine-class mask 运行 26 个固定原生协议机器，使用 `natflow_t` 的 8 字节瞬态 context。单包机器命中直接提交固定 app/category；RDP、SOCKS、WhatsApp 使用 compact automaton，DNS reply 要求 response header/question 结构证据。 |
| `natflow_path.c/.h` | fast path、路由学习、vline/relay、设备 notifier、硬件 offload。 |
| `natflow_user.c/.h` | fakeuser、认证、QoS、用户信息控制设备和 `/dev/natflow_userinfo_queue` 二进制认证事件队列。 |
| `natflow_urllogger.c/.h` | Legacy URL consumer；通过 `natflow_urllogger_consume_host_view()` 消费 L7 host view，处理 URL record、Host ACL、DPI classify 和 ACL 回复策略，保留 HTTP Host/URI、TLS/QUIC SNI 的 URL 记录、URL store、Host ACL、302/RST 动作和 sysctl 资源。`/dev/natflow_urllogger_queue` 只允许一个 reader；没有 reader 或 reader 未写入正数 `cache=N` 时 URL/SNI record 在 ACL/DPI 处理后直接丢弃，不缓存到 URL store。 |
| `natflow_zone.c/.h` | LAN/WAN zone 规则、设备 zone 标记、zone notifier。 |
| `natflow_conntrack.c/.h` | `/dev/natflow_conntrackinfo_ctl` conntrack dump；`kickall` 清理 `init_net` 中除 fakeuser 和 NATCAP peer 外的已确认 conntrack。 |
| `natflow_compat.h` | 跨内核版本 API 差异兼容。 |
| `docs/agent/DPI_IMPLEMENTATION_CHECKLIST.md` | DPI/L7 实现阶段的每步自审基线，覆盖 legacy URL/Host ACL、conntrack layout、fast path gate 和 DPI ABI。 |

## 长期约束

- 源码是最高优先级事实来源，`SYSTEM_DESIGN_SPEC.md` 是反向整理的长期规格。
- 字符设备命令大多要求单行命令以 `\n` 结束，单条命令长度上限为 `MAX_IOCTL_LEN = 256`。
- `/dev/natflow_conntrackinfo_ctl` 的精确 `kickall` 命令要求 `init_net` 的 `CAP_NET_ADMIN`，通过内核 cleanup iterator 同步删除除 `IPS_NATFLOW_USER` 和 `IPS_NATCAP_PEER` 外的已确认 conntrack；普通业务流即使关联 fakeuser 仍会删除，fakeuser/NATCAP peer 对象自身保留。
- `/dev/natflow_userinfo_ctl` 的 `idle_time` 复用 fakeuser 内部 `timestamp` 计算，输出值为经过秒数；timestamp 创建/获取 fakeuser 时写入，user pre hook 中普通活动最多每 32 秒刷新一次，新连接包超过 2 秒可刷新；不要用当前 `no_flow_timeout` 和 conntrack 剩余超时反推。
- path 默认关闭，通常通过 `/dev/natflow_ctl` 的 `disabled=0` 开启。
- `CONFIG_NATFLOW_PATH` 控制 fast path、vline/relay 和硬件 offload 相关能力。
- fakeuser 的 `ifname` 归 user 模块维护且规格依赖 path：普通 TCP/UDP 单播由 user pre hook 通过 `rroute[!dir]` accessor 同步，original 覆盖用户主动连接，外网主动连接在已关联用户后的 LAN reply 方向仅当 fakeuser 地址与 reply 源地址一致时刷新来源，避免 LAN-to-LAN/hairpin 污染，且不进入认证；空 ifname 绕过活动节流先尝试补齐。广播、组播和 ICMP/ICMPv6 保持 NETDEV ingress 原有校验及早退顺序，只在对应分支内由局部包装器独立校验 IP 长度及 IPv4 checksum 后调用 user 专用入口；入口仅接受 LAN zone 设备或其 bridge slave和有效 Ethernet 头，只查找已有 fakeuser，不创建用户、不更新 MAC，已有非零用户 MAC 必须匹配报文源 MAC，验证后记录原始 `skb->dev` 并在变化时发布事件。ARP 不经过该入口；path 未启用或未启用 NETDEV ingress 时字段允许为空。
- 字符设备初始化必须返回并记录 `class_create()`/`device_create()` 的真实 `PTR_ERR()`；zone/path netdevice notifier 注册返回值必须检查，失败时中止初始化并只回滚已经成功注册的资源。
- `NETDEV_UNREGISTER` 必须在任何动态分配或 work 排队之前无条件推进 path magic；正常 work 和 allocation/queue failure 的同步 fallback 都要经过 `synchronize_net()`，保证旧 generation 的在途 fast-path 读者退出后才释放设备引用。
- `CONFIG_NATFLOW_URLLOGGER` 控制 URL logger、Host ACL 和相关 sysctl。
- L7 shared hook 固定注册 IPv4、IPv6 和 bridge `NF_INET_FORWARD`；URLLogger 和 DPI 共享该完整 FORWARD pipeline，由 active consumer mask 独立启停。`CONFIG_NATFLOW_DPI` 另注册 IPv4/IPv6 `NF_INET_LOCAL_IN` DNS-only 入口，只处理 conntrack original tuple 为 TCP/UDP 目的端口 53 的 original query，不运行 URL/Host ACL、HTTP/TLS/QUIC、其他 packet machine 或 LOCAL_OUT。
- `DPI_DESIGN.md` Draft v7 把 P2 统一为 `natflow_l7` core。`app_id` 是唯一常驻分类结果；`natflow_t` 尾部另有 8 字节瞬态 DPI context，仅在 `NF_FF_DPI_USE` 时保存双向预算和 16 位 `dpi_automaton`。`bit15=0` 时低 8 位是 discovery machine-class mask；`bit15=1` 时 `bits14..8` 是 claimed machine、`bits7..0` 是 state。RDP、SOCKS、WhatsApp 是当前 claimed machine；context 不保存证据字符串、规则详情或指针。
- `natflow_t` 在 8 字节 DPI context 后保留不属于 context 的 4 字节显式 `layout_pad`，保证固定为 8 的 `__ALIGN_64BITS` 在 32/64 位目标上都能通过布局约束。32 位 `sizeof(natflow_t)` 从 92 补齐为 96，但 conntrack ext 原已分配对齐后的 96 字节，不增加实际分配。
- 当前源码已把 bit 19 收敛为 `NF_FF_L7_USE` shared L7 fast-path pause 位，`NF_FF_DPI_USE_BIT=21` 标记 `natflow_t` 内瞬态 DPI context 并纳入 `NF_FF_BUSY_USE`，三个 URL/DPI consumer done bit 独立记录终态。L7 core 持有共享 FORWARD hook、packet/host view、HTTP Host、TLS/QUIC SNI 和 DNS parser；URL consumer、DPI domain 和 DPI packet consumer 消费共享结果。DPI enable 直接发布静态 host 和固定原生协议/App consumer，不再有 domain/proto ruleset。DPI packet consumer 直接消费 L7 producer 提供的 L4/payload 指针和有界 `payload_linear_len`，按固定 machine step 识别 26 个协议和 App payload；源码没有 detector struct、metadata 数组或通用 detector dispatcher。HTTP/TLS/QUIC host 分类、DNS QNAME 意图和原生机器均不依赖 `/proc/sys/urllogger_store/enable`。维护者接受 `nf->status` 非原子 writer 风险，不做 path 侧 repair。
- 2026-07-18 新约束：运行时 URL/DPI enable、DPI `rules_commit` 和 `rules_clear` 只控制后续 active consumer/ruleset，不枚举、不退出、不清理已经标记的连接，也不因配置变化引入全局 conntrack registry。已设置 L7_SKIP 的连接不重新武装；仍在自然解析路径中的连接可以继续终态，也可以保留原 L7 owner/done 状态直到 conntrack 生命周期结束。配置切换不保证立即恢复既有连接的 fast path。
- 2026-08-16 DPI 固定 catalog revision=3，共 45 项：26 个协议和 19 个品牌应用。第二批新增腾讯视频、Spotify、WhatsApp、Messenger、Discord、Zoom、Facebook、Instagram、X/Twitter、微博，以及 NTP、SNMP、RADIUS、TFTP、LDAP、NFS、SOCKS、CoAP。94 项 exact/label-boundary suffix 域名来自既有表和本地 nDPI；Meta/腾讯具体子域优先于父域，不采用宽泛 substring，共享 CDN 只登记完整 exact hostname。DNS QNAME 仍只累计 `dns_app_intents`，不写目标 App。
- 2026-08-16 App packet step 复用 TEXT discovery class：TCP 最多 pull/解析 512 字节 HTTP 单包 request/response，header 上限 32，提供 Host/User-Agent/Content-Type 和可见 body；第一批只有严格 request Host 可终态，不做 TCP 重组、chunked、解压或无来源 body 关键字。钉钉 TCP、QQ/OICQ UDP、爱奇艺 UDP `PPStream` 采用 nDPI 直接 payload 特征，source=22..24。通用原生 parser 仍只检查前 96 字节；爱奇艺 121..299 字节候选 pull 完整 UDP payload。8 字节 context 保持不变，只有以后确需保存跨分段/跨方向 HTTP 事实时才评审扩大 `natflow_t`。
- 2026-07-18 protocol-only 识别收紧为直接协议证据：DNS 必须解析为 TCP/UDP 53 标准 query，SSH 必须在 TCP 任一方向匹配 banner，WireGuard 必须通过 UDP message type/reserved bytes/长度校验；TCP 22 和 UDP 51820 不再直接分类。2026-08-15 M2 后 protocol mask 固定为全部内置协议，不再由用户规则选择；每包仍按 L4、方向、candidate mask 和预算跳过无关 parser。
- 2026-07-18 双向 DPI 设计合同：reply 首期只进入 DPI packet consumer，URL/Host ACL/HTTP-TLS-QUIC host/DNS QNAME domain 保持 original-only；初始预算为每方向 4 个 payload 包，不设置时间 deadline。2026-08-17 增加 acct 总包数兜底后，acct 存在的连接在第 257 包终态；acct 缺失时，所需方向始终无 payload 的 `NF_FF_DPI_USE` 仍可保留到 conntrack 生命周期结束。
- 2026-07-18 M1e 已开放 reply DPI packet consumer；reply 不进入 URL、Host ACL、HTTP/TLS/QUIC host 或 DNS QNAME domain。IPv4/IPv6 TCP/UDP producer 对称填充 direction 和端口。
- 2026-07-18 M1e bounded context 位于 `natflow_t` 尾部 8 字节。未命中不立即写 packet done；命中、已有 app、FIN/RST 或所有 active machine class 双向预算耗尽时清 context 并终态。耗尽方向不再运行原生协议机器。
- 2026-07-18 DNS query/response 第一问共享 compression name walker：最多 16 次 pointer 跳转，记录访问 offset 并拒绝环、越界、非法 label 和展开后超过 host 上限；reply 仍只提供 protocol 证据，不进入 domain rules。
- 2026-07-19 DPI M2 shadow counters 把全部规则命中 `matches*` 与成功入队 `events*` 解耦；`events_suppressed` 统计无 reader/cache，`events_lost` 统计分配失败/队列满，并增加 domain lookup、original/reply packet inspect/match 和 bounded context transition 累计计数。conntrack 自然销毁不回调 DPI，因此不提供 active-context gauge，也不能用 arm/clear 差值推导当前 occupancy。
- 2026-08-15 可重复验证入口：`tools/build-matrix.sh` 执行七组合 clean build；`tools/natflow-dpi-reader.c` 是严格校验 78 字节 v3 event header 的 queue 参考消费者；`tools/natflow-dpi-ctl-smoke.sh` 验证固定 catalog 状态、enable 切换、`events_clear` 和旧规则命令均返回 `-EINVAL`，并恢复原 enable。它会清空 DPI 事件和统计，只适用于隔离测试环境。
- 2026-07-19 queue ABI 冒烟入口：`tools/natflow-dpi-event.h` 是 reader/smoke 共享的用户态 v3/78 字节定义；`tools/natflow-dpi-queue-smoke.c` 默认验证单 reader、`-ESPIPE`、小 buffer `-EINVAL`、cache=0 空队列、未知命令、cache 开关和 close/reopen 清理，`-w` 额外等待真实事件并校验当前 v3 固定头。打开 smoke 会清空残留事件并独占 reader，不能与生产 reader 并行；队列满和并发压力仍需真机补测。
- 2026-07-26 queue pressure 入口：`tools/natflow-dpi-queue-pressure.c` 持有单一 reader 并在 injector 运行期间暂停读取，随后验证保留事件的 v3 ABI、测试 tuple/source/app/rule 和严格 cache 上限；`tests/dpi/run-corpus.sh --queue-pressure [cache [generated]]` 复用隔离 IPv4 FORWARD 拓扑并发生成不同目的端口的 STUN 流，核验 `matches=generated`、`events=cache`、`events_lost=generated-cache`、`events_suppressed=0`、STUN 分项和总计数恒等式。默认 cache=8/generated=32；2026-07-26 维护者真机执行通过，确认保留 8、lost 24 且环境清理成功。
- 2026-07-26 queue stream 入口：同一用户态工具的 `-w` 模式在 injector 运行期间持续 poll/read，按测试目的端口 bitmap 拒绝重复、遗漏和环境事件；`tests/dpi/run-corpus.sh --queue-stream [cache [generated [parallel]]]` 默认 cache=64/generated=128/parallel=16，producer 分批并发，要求每条事件恰好读一次、结束后队列为空、`matches=events=generated` 且 lost/suppressed 为 0。2026-07-26 维护者真机执行通过，128 条事件经 127 次 poll/read 全部读出、无丢失且环境清理成功。
- 2026-07-26 IPv6 corpus 入口：`tools/natflow-dpi-traffic.c` 根据地址文本选择 AF_INET/AF_INET6 socket，`tools/natflow-dpi-corpus.c` 拒绝混合地址族并按 family 比较 4/16 字节 original tuple；`tests/dpi/run-corpus.sh --ipv6` 使用两个文档前缀 `/64`、nodad、ip6tables 和 IPv6 forwarding 复用现有 51 项 fixture，退出时恢复并核验对应 IPv6 状态。首次真机失败确认是测试机没有其他 IPv6 conntrack 使用者；runner 改为用 conntrack state match 自行激活所选 family 后，在 natflow path disabled 状态完成 DNS/SSH 20 项和 UDP protocol 31 项真机测试，51 项全部通过。维护者决定不支持 IPv6 extension header，精确 TCP segmentation、non-linear skb 专项验证和长时间 soak 暂缓。
- 2026-08-15 原生协议 corpus 框架：`tests/dpi/run-corpus.sh` 建立两个 network namespace，经 root namespace 的真实 FORWARD hook 注入每例独立的 TCP/UDP 连接；默认使用 IPv4，`--ipv6` 使用两个 IPv6 `/64`。`tools/natflow-dpi-traffic.c` 生成 original/reply payload，`tools/natflow-dpi-corpus.c` 先打开 queue，再按 original tuple 过滤并断言 v3 固定 catalog revision、app/category/rule/evidence。退出时恢复 enable 和对应 family forwarding，清理 iptables/ip6tables 与 namespace；最终 PASS 前核验状态均已恢复。它会清空事件统计，只用于隔离测试环境。
- 2026-07-19 DNS/SSH corpus：`tests/dpi/cases/dns-ssh.cases` 覆盖 DNS UDP/TCP query/response、首问 compression pointer、pointer loop/越界、截断、QR/opcode/qdcount 和错误端口，以及 SSH original/reply banner、1.99 版本、port-only、截断和错误版本格式。`tests/dpi/run-corpus.sh --check` 可在无 root、无模块环境静态校验 fixture 格式和 protocol/L4 约束。
- 2026-07-19 UDP protocol corpus：`tests/dpi/cases/udp-protocols.cases` 覆盖 WireGuard type 1-4 与 reserved/length/type negatives，STUN/TURN UDP/TCP original/reply 与 header length/cookie negatives，以及 BitTorrent TCP handshake、UDP uTP/DHT 和对应格式 negatives。corpus 审核发现 malformed WireGuard type 1 会落入弱 uTP 特征；uTP 已增加最多 4 段的有界 extension chain 校验，并拒绝 connection ID 为 0 的 DATA packet，避免与 WireGuard type 1 重叠。2026-07-26 维护者在真机完成 IPv4 和基础 IPv6 namespace/FORWARD/queue 全链执行，两种地址族的首批 51 项均全部通过。
- 2026-08-15 DPI M2/M5 B 级原生协议机器：FTP、SMTP、POP3、IMAP、SIP、RTSP、MQTT、RESP、MySQL、PostgreSQL、RDP、SMB 按文本、数据库、二进制三组占用剩余 3 个 discovery machine-class bit，不扩大 conntrack context；MySQL 只认 reply v10 greeting，MQTT/RESP/PostgreSQL 只认 original 结构首包，歧义 `USER`、端口和普通 banner 不分类。M5 后 RDP 不再由单个 TPKT/X.224 首包终态：16 位 automaton 用 `cmpxchg()` 单调 OR original Connection Request 与 reply Connection Confirm，两个事实任意顺序汇合才提交，claimed 后只运行 RDP machine。TCP sequence corpus 覆盖顺序、反序、同时发送、重复、双向预算、transport end 和 malformed confirm；自动 corpus 总数为 93，新增样本真机 IPv4/IPv6 尚待完成。
- 2026-08-15 DPI M6：使用 `/home/ptpt52/t-wrt/openwrt` 的 Linux 5.4.281、arm64、GCC 8.4 工具链完成七组合 clean build；`KCFLAGS=-Wno-unused-function` 用于兼容该内核头中的静态 helper 告警，其余 `-Werror` 保持生效。完整 `NO_DEBUG` 配置与 M4 `92e8e30` 同参数比较，`natflow_dpi_consume_packet_view()` 栈帧均为 240 字节，`natflow_dpi.o`/`natflow.ko` text 各增加 992 字节，data/bss 不变；92 项 fixture 静态检查、用户态工具 `-Werror` 编译和 shell 语法检查通过。维护者本轮要求编译验证即可，未在 x86 宿主加载 arm64 模块，运行态 corpus/queue 保留为目标机部署验证项。
- 2026-08-15 DPI 审查收口：同一 conntrack 的原生协议机器、automaton、双向预算、app/context 和 packet done 由 `ct->lock` 串行，app 或 packet terminal 在解锁前完成提交、清 owner 和写 done，事件分配/入队留在锁外；packet-only TCP 只 pull 最多 96 字节 parser 前缀，bridge/inet FORWARD 使用 `IPS_NATFLOW_SKIP_BRIDGE` 去重；`events_clear` 临时暂停 producer 并经 `synchronize_net()` 排空在途 hook 后复位；SMB1/2 的 NBSS 声明长度必须分别至少覆盖 32/64 字节 header，新增 zero-length 反例后 corpus 为 93 项。OpenWrt Linux 5.4.281 arm64/GCC 8.4 七组合构建已通过；并发双向 packet、bridge、non-linear skb 和并发 reset 仍需目标机压力验证。
- 2026-08-15 DPI M7 删除 `struct natflow_dpi_detector`、DNS/payload detector metadata 数组、metadata lookup/方向/预算遍历和通用 dispatcher。低 8 位继续作为 discovery machine-class mask，固定 native machine step 直接编码 parser 顺序、L4 和方向约束；M9 后 RDP、SOCKS 和 WhatsApp 是持久 claimed machine。每方向 4 包/384 字节预算、8 字节 context 和 v3 event/control ABI 不变。事件 reason 2 的 `NO_DETECTOR` 枚举名仅为未使用的历史 ABI 常量，不代表当前实现仍有 detector。
- 2026-08-16 DPI M9：NTP/SNMP/RADIUS/LDAP/CoAP 以任一端点端口加结构/长度证据单包终态，TFTP RRQ/WRQ 需要端点 69 且严格 OACK 支持动态 TID，NFS 按 RPC 结构且不限制端口；network parser 先于 STUN，NFS parser 先于 WireGuard/uTP，避免签名碰撞。SNMP/LDAP 复用拒绝 indefinite、超过 4 字节和非最短编码的 BER length helper；SOCKS 只接受 original negotiation + reply。WhatsApp 新前缀在首段至少匹配 2 字节后可跨同方向 payload 补全，Discord/Spotify/Zoom 使用直接 payload 特征；不扩大 `natflow_t`。corpus 共 196 项。
- 2026-08-17 DPI 本机 DNS 与端口语义：DPI 编译配置增加 IPv4/IPv6 `LOCAL_IN` DNS-only hook；original tuple TCP/UDP dport 53 是唯一入口候选，因此 direct、DNAT/REDIRECT 到本机非 53 监听端口都可解析。FORWARD DNS、QUIC 443 candidate 和所有依赖逻辑服务/应用端口的状态机统一改用 original client/server ports，当前 packet ports 只保留为 header evidence。本机入口只解析 original query、QNAME intent 和 DNS commit，不运行 URL/ACL、HTTP/TLS/QUIC、其他机器或 LOCAL_OUT；UDP 单报文与 TCP FIN/RST 有界收口，TCP 零 payload 不提前完成。`tests/dpi/run-local-dns.sh` 覆盖 IPv4 direct/REDIRECT original tuple 和 counters。
- `/dev/natflow_userinfo_queue`、`/dev/natflow_urllogger_queue` 和 `/dev/natflow_dpi_queue` 只允许一个 reader，默认 cache 为 0；三者都使用 reader count + cache limit 控制入队，reader 打开时清空残留队列并要求同一个 O_RDWR fd 写入正数 `cache=N` 才缓存新事件，最多缓存 N 条，队列满时丢弃新事件；写入 `cache=0` 或关闭 fd 会关闭缓存并清空未读事件；未知 queue 写命令返回 `-EINVAL`。三个队列 `read()` 空队列都返回 0，不挂起，不返回 partial record；用户 buffer 足够时单次 `read()` 可返回多条完整记录，`poll()` 在有可读事件时返回 readable。URL logger 的 `memsize_limit/memsize/count_limit` sysctl 已废弃，`count` 只观测当前待读 URL 记录数；DPI 不再有固定 1024 事件上限。DPI 事件 `timestamp` 是 uptime 秒数，与 URL logger 一致；事件 ABI 为 v3 固定头，original tuple 的 `family/l4proto/tuple_dir/sport/dport/sip/dip` 保持稳定连接身份，新增 `evidence_dir` 记录实际命中 packet 的 original/reply 方向。URL 输出 v2 `natflow_urllogger_event_hdr` 加不带结尾 NUL 的 `host + uri` payload；userinfo 输出 v3 固定头 `natflow_userinfo_event_hdr`，尾部 `ifname[IFNAMSIZ]` 记录 path 学习到的用户侧三层入口设备，字段语义与 `/dev/natflow_userinfo_ctl` 文本快照一致。
- 2026-08-17 DPI 增加流包数兜底：conntrack accounting 实现随 `NF_CONNTRACK` 内建，没有 `CONFIG_NF_CONNTRACK_ACCT` 符号；运行时 sysctl 决定新连接是否有 acct 扩展。acct 存在时双向总包数不超过 256 继续等待，第 257 包清除活跃 `NF_FF_DPI_USE` context、标记 DPI packet done 并增加 `context_cleared_acct_limit`；TCP 零 payload 包只运行该生命周期检查，不进入 payload parser。acct 缺失时仍可能等到 conntrack 销毁。`--packet-limit` 回归覆盖 UDP 256/257 边界、counter reset 和纯 TCP ACK。
- 慢路径依赖 Linux 原生 Netfilter、conntrack、NAT、路由和 bridge 行为，fast path 不能破坏慢路径回退。
- 旧内核兼容是项目价值的一部分，修改 API 适配时要确认版本分支。
- 非 seek 字符设备使用 `natflow_no_llseek()` 保持 `-ESPIPE`，不要直接依赖新旧内核是否暴露 `no_llseek`。
- 热路径要优先考虑性能、RCU/锁语义、skb 可写性、校验和、MTU、TTL/hop-limit、VLAN/PPPoE 和设备生命周期。
- QUIC crypto/HKDF/shash 临时缓冲放在 L7 per-CPU `natflow_l7_quic_crypto_ctx` 中，避免包处理路径栈膨胀和 `CONFIG_VMAP_STACK` scatterlist 风险；crypto 初始化失败只禁用 QUIC hostname parser，不导致 URL logger 或 L7 初始化失败。
- L7/DPI 数据面栈预算按入口到 consumer 的整条调用链评估，不按单个函数帧孤立评估；HTTP host view 可携带原始 Host 和 `host_flags`，URL/DPI consumer 在边界 normalize，已规范化的 URL/ACL/DNS host 走 DPI normalized classify，URL record 分配失败的 `urllogger_acl_lookup` 大对象只应出现在异常 fallback。
- 完整 L7 构建要求 `THREAD_SIZE >= 8192`；Kbuild 对 L7/DPI/URL consumer 数据面对象设置 512 字节单函数栈帧上限。2026-07-18 使用 x86_64 GCC 9.4、PATH+URLLOGGER+DPI 配置生成 `.su`：最大单帧 360 字节；显式传递 narrowed consumer mask、复用入口 packet view 后，模块内部最坏累计链由约 1936 字节降至约 1624 字节，不含 hook 上游和外部内核函数栈；8 KiB 目标仍需按实际工具链生成 `.su` 并做运行时栈余量验证。
- 2026-07-12 对 `11824c1..9dbcba7` 的 L7/DPI 收尾确认结论：代码审查未发现阻断问题，`git diff --check HEAD~2..HEAD` 和串行构建矩阵通过，维护者真机测试未发现问题。已覆盖 default、`CONFIG_NATFLOW_URLLOGGER`、`CONFIG_NATFLOW_DPI`、URLLOGGER+DPI、PATH+URLLOGGER+DPI 和 NO_DEBUG PATH+URLLOGGER+DPI 构建面。
- 2026-07 对 `e3c6601..5430b33` 的提交审核结论：本仓库风格是慢路径保持 Linux 原生语义、fast path 做机会性加速；新增能力后通常继续收紧边界、资源归属、RCU 和 ABI 文档。
- 包处理路径访问头部前必须先证明数据可读，写 skb 前必须确认可写；`pskb_may_pull()`、`skb_try_make_writable()`、`skb_cow_head()`、trim/csum 后要重新获取 `iph`/`l4`/payload 指针。
- 策略模块在等待认证、URL/SNI/QUIC 解析、L7 原生协议机器或 Host ACL 决策时必须设置对应 busy bit，完成后再清除，避免 fast path 提前接管。
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
