# Natflow 有界 L7 应用分类（DPI）设计

状态：Draft v4，待实现评审

更新时间：2026-07-10

实现状态：本文描述目标架构，不代表当前源码已经提供 DPI 接口或行为。

## 1. 结论与设计决策

Natflow 不应在内核中照搬 nDPI 或实现一个无边界通用应用识别引擎。适合本仓库的能力是一个**有界、机会性、面向连接首段的 L7 detector 框架**：复用并重构现有 HTTP Host/URI、TLS SNI 和 QUIC v1 Initial SNI 解析，同时允许为非 HTTP/TLS/QUIC 流量增加小型、确定性状态机 detector，得到可解释的协议与应用分类结果，然后尽快释放连接给软件或硬件 fast path。

本设计作出以下确定决策：

1. MVP 不再限制为 HTTP/TLS/QUIC 域名映射；MVP 必须先建立 detector 框架、fast-path gate、终态和事件 ABI。首批 detector 包含 HTTP/1 Host、TLS ClientHello SNI、QUIC v1 Initial SNI，以及少量非 HTTP/TLS/QUIC 的高确定性 detector。具体协议集按 7.4 节分级进入，初始支持清单见 7.5 节，不把 nDPI 全量协议一次搬入内核。
2. fast-path gate、终态和失败降级属于 MVP，不得放到后续阶段，否则首段流量可能在分类前被加速绕过。
3. HTTP/TLS/QUIC 只能有一套共享提取器。URL logger、Host ACL 和 DPI 都消费同一份规范化特征，不能并行重复解析。其他协议 detector 也必须复用同一 packet view、flow context、预算和终态框架。
4. 协议识别和应用识别分开。确认流量是 TLS/QUIC 不等于确认具体应用；`app_id=0` 始终表示应用未知。
5. `natflow_t` 尾部只追加长期需要的 `app_id`；DPI gate 沿用 `nf->status` 的现有非原子 owner bit 模型，预留独立 owner bit 并加入 `NF_FF_BUSY_USE`，不再设计 path 侧 gate repair。MVP 固定结果目标为逻辑 4 B/flow，实际 conntrack 扩展增量仍受 `__ALIGN_64BITS` 对齐影响。不使用 `skb->mark` 或 `ct->mark` 保存 DPI 结果。跨包字节只进入全局有硬上限的临时 cache。
6. 域名匹配固定为 hash + DNS label 边界 suffix probe，不保留“Trie 或 Hash”二选一，也不支持隐式 glob。非域名 detector 使用固定 magic、长度字段、方向阶段、命令字或有界 token parser；热路径不支持 PCRE、用户态字节码或任意 offset 正则。
7. 规则以不可变 snapshot 发布；控制面事务提交，数据面 RCU 读取，active context 绑定实际使用的 ruleset generation，并在 terminal event 中输出；flow 常驻结果只保留 `app_id`。协议 detector 可直接产生 `proto_id`，再由规则或内置映射生成用户定义 `app_id`。
8. `/dev/urllogger_queue`、`/dev/hostacl_ctl` 和现有 sysctl ABI 保持不变。DPI 使用独立控制设备和版本化二进制事件设备。
9. 所有解析失败、资源不足、加密不可见和不支持变体默认 fail-open，并输出可区分的 terminal reason 和计数器。
10. DNS snooping、JA3/JA4、任意 payload offset、User-Agent、HTTP path 组合规则、静态 IP fallback 和应用策略执行不进入 MVP。非 HTTP/TLS/QUIC 识别只通过显式列入的 detector 进入，且每个 detector 必须独立给出方向、包数、字节数、误判模型和资源预算。只有真实命中率和性能数据证明需要后，才扩大协议集或开放 enforce。

## 2. 现设计审计

当前源码提供的是 URL/SNI 元数据提取和 Host ACL，不是通用 DPI。现有 `DPI_DESIGN.md` 初稿可作为需求列表，但不能直接进入实现，主要原因如下：

- 文档先要求新流进入 inspecting，却把 busy bit 和 path 对接放到第二阶段；第一阶段自身无法保证观察到完整首段流量。
- `http_url_search()`、`tls_sni_search()` 和 QUIC parser 都是 `natflow_urllogger.c` 内部静态函数，并与 URL 记录分配、ACL 和动作混在同一 hook 中；“复用 urllogger”还没有共享 API。
- “写 conntrack 扩展或 mark”没有作出存储决策。mark 已有 QoS、tc 和硬件路径语义，不能再承担 DPI flow result。
- 原控制命令没有事务、generation、冲突规则、配额或严格错误语义；复杂规则也无法可靠放进 256 字节单行协议。
- 原事件结构只有 IPv4 五元组和 app/category，缺少 ABI version、record length、IPv6、字节序、证据、终态原因、规则 generation、队列溢出和 read/poll 语义。
- user QoS 在 `NF_IP_PRI_FILTER` 完成一次性匹配，URL hook 在 `NF_IP_PRI_FILTER + 5`；事后只写 `app_id` 不会自动触发 QoS 重评。
- DNS、JA3/JA4、任意 payload 签名、UA、path 和组合规则一次进入首期，会形成无边界的候选和缓存模型，与内核热路径目标冲突。非 HTTP/TLS/QUIC 支持必须表现为逐协议 detector，而不是一个全局正则/特征库扫描器。

源码审计还发现，重构时必须处理以下当前实现风险：

- HTTP 只检查当前 skb；首个 HTTP header 分段未包含 Host 时，连接仍会被标记 handled，Host ACL 存在机会性绕过。
- TLS/QUIC cache 按 CPU 保存。flow 在 RPS/RFS 或调度变化下跨 CPU 时，后续包无法稳定取得之前的重组状态。
- Host ACL 在 `urlinfo_alloc_record(GFP_ATOMIC)` 成功后才执行；日志对象分配失败会同时跳过 ACL。
- `nf->status` 的 `simple_set_bit()`/`simple_clear_bit()` 是非原子 read-modify-write，多 CPU 更新不同状态位时可能丢失更新。可能影响包括：user/URL/DPI busy 丢失而提前进入 fast path、QoS/token 位丢失而漏限速或漏 mark、route/check/OK 位丢失而重复学习或无法建表。维护者接受这一风险，允许新 DPI 继续沿用该状态字，本任务不迁移整字全部 writer，也不引入 path 侧 DPI gate repair；必须在文档、计数器和并发测试中保留这一已知限制。
- `urllogger_store_enable=0` 在 hook 入口直接返回；运行时关闭时，已有等待解析的 URL busy bit 没有统一清理路径。
- URL store 在全局 spinlock 内按时间窗口反向扫描去重，Host ACL 使用 `strstr()` 扫描追加 buffer；两者都不适合扩展为大规模 DPI 规则引擎。

这些问题不是扩大现有函数即可解决的局部细节，而是共享 parser、flow owner、终态和资源模型必须先建立的原因。

## 3. 目标、非目标与信任边界

### 3.1 目标

- 对 forwarded IPv4/IPv6 TCP/UDP 新连接做有界首段观察，包括可见域名类流量和明确纳入的非 HTTP/TLS/QUIC detector。
- 输出独立的 L7 protocol、应用分类、证据强度和终止原因。
- 在任何 terminal 结果后立即允许 fast path 继续学习或接管。
- 保持 URL logger、Host ACL、user/auth、现有 QoS 和 path 的既有 ABI 与默认行为。
- 数据面无阻塞、无正则、无无界循环、无无界候选链、无大栈对象，资源耗尽时确定性降级。
- 控制面规则原子更新，事件格式可版本化，所有资源和 owner 可追踪。

### 3.2 非目标

- 不做 WAF、IDS/IPS、反规避网关、完整 TCP 重组、全流 payload 扫描或 nDPI 全库内核移植。
- 不承诺穿透 TLS ECH、HTTP/3 加密头、VPN、代理、混淆或自定义加密协议。
- 不在内核保存应用名称、长签名描述、报表、机器学习模型、在线学习状态或用户可上传的程序化 detector。
- 不默认引入用户态 daemon。未来用户态工具可负责编译规则、批量下发和消费事件，但内核模块可以独立加载并保持 DPI 关闭。
- 不把域名、客户端指纹、DNS 关联或 IP/port 线索描述为不可绕过的身份事实。

### 3.3 安全定位

MVP 是审计和机会性分类能力。任何 `UNKNOWN`、`ERROR` 或资源降级默认放行，现有 Host ACL 行为除外。未来若加入应用级阻断，也只能对显式、高质量证据执行，并且不能让 `accept` 覆盖认证、Host ACL、conntrack drop 或其他既有拒绝结果。端口、IP/CIDR、DNS 关联和弱 payload 线索默认不能单独触发阻断。

## 4. 当前实现基线

新设计必须兼容以下源码事实：

- URL logger 默认挂在 IPv4、IPv6 和 bridge `FORWARD` 的 `NF_IP_PRI_FILTER + 5`；可选配置会改为 IPv4 `LOCAL_IN`。
- path 在最终建软件 fastnat 或硬件 offload 项前检查 `nf->status & NF_FF_BUSY_USE`。
- `NF_FF_BUSY_USE` 当前只包含 user 和 URL logger owner bit。
- `natflow_t` 当前包含 `magic`、`qos_id`、`status` 和双向 route；它位于 Natflow/NATCAP 共享的 conntrack 扩展尾部。
- `natflow_session_init()` 只能在 conntrack confirm 前扩展对象，并依赖当前 allocator/共享布局假设。
- URL logger 现有 TLS/QUIC cache 每 CPU 64 个节点，超时 4 秒，名义单流累计上限 32 KiB；首次 TCP `kmemdup()` 当前没有先执行该上限检查。QUIC crypto scratch 为 per-CPU 对象。
- user QoS 在 `NF_IP_PRI_FILTER` 首次匹配后设置 `NF_FF_QOS_TESTED`，后续不会自动重跑 tuple/ipset 规则。
- path、URL logger 和控制设备包含大量旧内核兼容分支；新实现不能只针对单一新内核 API。

## 5. 分类模型

### 5.1 三层结果

每条连接的结果分为三个独立维度：

| 维度 | 含义 | 示例 |
| --- | --- | --- |
| `proto_id` | 从报文格式或握手状态机确认的承载协议 | `HTTP1`、`TLS`、`QUIC_V1`、`DNS`、`STUN`、`SSH`、`BITTORRENT` |
| `app_id` | 由当前 ruleset、协议映射或 detector 结果得到的用户定义应用 | `app_id=1001` |
| `terminal reason` | 为什么停止观察 | `MATCHED`、`NO_RULE`、`ECH`、`BYTE_BUDGET` |

`proto_id` 已知而 `app_id=0` 是正常结果，不得折叠成解析错误。协议识别和应用识别仍然分开：识别出 `SSH`、`DNS` 或 `STUN` 可以产生 protocol-only event；是否映射成某个业务应用由规则或内置 app map 决定。

### 5.2 ID 约束

- `app_id` 是用户定义的 32 位无符号 ID；`0` 永久保留为 unknown。
- `category_id` 是用户定义的 16 位无符号 ID；`0` 表示未分类。
- `rule_id` 是 ruleset 内稳定的 32 位无符号 ID；`0` 表示没有命中规则。
- `proto_id` 是内核固定枚举，表示 detector 确认的协议。它不是 nDPI enum 的 ABI 拷贝；可以在实现中提供离线映射表，但 UAPI 数值由 Natflow 自己维护，只能追加。
- `detector_id` 是内核内部固定枚举，用于统计、调试和 event；一个 detector 可产生多个 `proto_id`，例如 BitTorrent detector 可区分 handshake、DHT 或 tracker 线索。
- 内核不保存 app/category 名称。名称和展示层映射属于用户态。
- 每个 terminal event 必须携带 `ruleset_generation`，使审计结果可以回溯到实际规则版本；该值不常驻 flow。

### 5.3 Evidence 与 confidence

confidence 是稳定的证据等级，不是概率：

| 等级 | 名称 | 含义 |
| --- | --- | --- |
| 0 | `NONE` | 没有应用证据 |
| 1 | `HINT` | 未来的 port 等弱提示，不能单独产生 app_id |
| 2 | `CORRELATED` | DNS/IP 等间接关联，默认只审计 |
| 3 | `DIRECT_SUFFIX` | 可见 Host/SNI/QNAME 命中 label-boundary suffix 规则 |
| 4 | `DIRECT_EXACT` | 可见 Host/SNI/QNAME 或固定字段命中 exact 规则 |
| 5 | `DIRECT_PROTOCOL` | detector 通过协议握手、magic、长度和方向阶段确认协议，但未确认具体应用 |
| 6 | `DIRECT_APP` | detector 通过高质量应用特征确认具体应用 |

MVP 可以提交 `DIRECT_SUFFIX`、`DIRECT_EXACT`、`DIRECT_PROTOCOL` 或少量 `DIRECT_APP` 结果。事件还必须携带 evidence 类型，例如 `HTTP_HOST`、`TLS_SNI`、`TLS_OUTER_SNI`、`QUIC_SNI`、`DNS_QNAME`、`BINARY_MAGIC`、`COMMAND_TOKEN`、`HANDSHAKE_STAGE` 或 `FLOW_PATTERN`，不能只看 confidence。

### 5.4 Terminal reason

至少区分以下终止原因，UAPI enum 只能追加，不能改变既有数值语义：

- 正常：`MATCHED`、`PROTO_ONLY`、`NO_RULE`、`NO_MATCH`、`NO_VISIBLE_METADATA`、`NO_DETECTOR`、`NOT_ELIGIBLE`、`REPLY_FIRST`、`FIN_RST`。
- 加密/协议：`ECH`、`UNSUPPORTED_VERSION`、`UNSUPPORTED_VARIANT`、`CRYPTO_UNAVAILABLE`。
- 报文：`FRAGMENT`、`IPV6_EXTENSION_LIMIT`、`TCP_GAP`、`PARSE_CONTENTION`、`MALFORMED`。
- 预算/资源：`PACKET_BUDGET`、`BYTE_BUDGET`、`TIME_BUDGET`、`CACHE_FULL`、`NO_MEMORY`、`RULE_LOOKUP_BUDGET`、`PARSER_BUDGET`。
- 管理：`DPI_DISABLED`、`MODULE_EXIT`。

reason 描述观察为什么结束，不代表连接必须丢弃。

## 6. 目标架构

### 6.1 组件划分

建议最终拆分为：

| 组件 | 职责 |
| --- | --- |
| `natflow_l7.c/.h` | read-only packet view、HTTP/TLS/QUIC parser、hostname normalize、bounded reassembly、QUIC crypto、常用有界解析 helper |
| `natflow_dpi.c/.h` | flow coordinator、detector dispatcher、状态机、rule snapshot、classifier、事件、控制 ABI、统计 |
| `natflow_urllogger.c` | legacy URL store、CSV ABI、Host ACL、302/RST 动作，改为消费共享 features |
| `natflow_path.c` | 在所有建表点检查包含 DPI bit 的 `NF_FF_BUSY_USE`；强制新 TCP SYN/TFO 和 UDP detector candidate 回慢路径 |
| `natflow_user.c` | 保持现有认证/QoS，只在未来提供明确的 app QoS adapter |

detector 是编译期静态实现，不提供运行时 plugin、用户字节码或函数指针注册 ABI。

### 6.2 数据流

```text
new forwarded flow
        |
        v
arm flow + set DPI owner bit
        |
        v
read-only packet view -> bounded detector/parser -> normalized features
        |                                      |
        | NEED_MORE                            | FEATURE / terminal
        v                                      v
bounded flow cache                     immutable rule lookup
        |                                      |
        +---------------------> flow result + legacy consumers
                                               |
                                               v
                                  policy snapshot -> event enqueue
                                               |
                                               v
                                       freeze result fields
                                               |
                                               v
                               publish terminal + clear DPI bit
                                               |
                                               v
                                      fast path may proceed
```

提取、分类、策略和输出是单向阶段。detector/parser 不直接执行 ACL、不写队列、不修改 skb；consumer 不得再次解析同一 payload。

## 7. Packet view 与 detector/parser contract

### 7.1 只读 packet view

core 先构造统一的 `dpi_packet_view`，再调用 detector/parser：

```c
struct dpi_packet_view {
	struct sk_buff *skb;
	u16 l3_offset;
	u16 l4_offset;
	u16 payload_offset;
	u16 payload_len;
	u8 family;
	u8 l4_proto;
	u8 direction;
	u8 flags;
};
```

具体实现字段可以调整，但必须满足：

- 统一处理 IPv4 IHL、IPv6 extension header 上限、TCP data offset、UDP length、PPPoE、bridge、VLAN 和 non-linear skb。
- 使用 `pskb_may_pull()`、`skb_header_pointer()` 或 `skb_copy_bits()` 证明数据可读；任何 pull/copy 后重新获取指针。
- 解析过程不得调用 `skb_try_make_writable()`，不得临时修改 `skb->protocol`、`network_header` 或 data。只有最终 reset/redirect 等动作可以进入独立的 writable 路径。
- IPv4/IPv6 fragment 在未确认已经完成 defrag 时终止为 `FRAGMENT`，不在 DPI 内做 IP 重组。
- IPv6 extension header 遍历必须有明确 header 数和字节上限。

### 7.2 Detector 与 parser API

```c
enum dpi_parse_rc {
	DPI_PARSE_SKIP,
	DPI_PARSE_FEATURE,
	DPI_PARSE_NEED_MORE,
	DPI_PARSE_UNSUPPORTED,
	DPI_PARSE_MALFORMED,
	DPI_PARSE_NO_RESOURCE,
};

struct dpi_parser_ops {
	u8 id;
	bool (*eligible)(const struct dpi_packet_view *view);
	enum dpi_parse_rc (*parse)(const struct dpi_packet_view *view,
	                          struct dpi_reassembly *reasm,
	                          struct dpi_features *features);
};

enum dpi_det_rc {
	DPI_DET_SKIP,
	DPI_DET_MATCH,
	DPI_DET_PROTO_ONLY,
	DPI_DET_NEED_MORE,
	DPI_DET_NO_MATCH,
	DPI_DET_MALFORMED,
	DPI_DET_NO_RESOURCE,
};

struct dpi_detector_ops {
	u16 detector_id;
	u16 default_proto_id;
	u8 l4_proto;
	u8 max_orig_pkts;
	u8 max_reply_pkts;
	u16 max_bytes;
	u32 flags;
	bool (*eligible)(const struct dpi_packet_view *view,
	                 const struct dpi_flow_ctx *ctx);
	enum dpi_det_rc (*match)(struct dpi_flow_ctx *ctx,
	                        const struct dpi_packet_view *view,
	                        struct dpi_features *features);
};
```

约束：

- `dpi_features` 中的 host/URI slice 只在当前调用有效；consumer 必须立即 match、copy 或 serialize，不能把 skb 指针存入 flow。
- reassembly 由 core 唯一拥有。attach 成功即完成 ownership transfer，parser 和调用方不得重复释放。
- 单包最多 dispatch 4 个 detector。dispatcher 先按 L4、端口、首字节、payload 长度、方向和 context stage 做常量时间候选裁剪，再调用 detector。
- HTTP/TLS/QUIC parser 是 detector 可复用的子解析器；TCP 按固定前缀区分 HTTP/TLS，UDP 只在配置端口（默认 443）尝试 QUIC Initial，其他协议按各自 detector 的 `eligible()` 进入。
- detector 不做动态规则查找，不分配日志对象，不执行 policy；它只产出 `proto_id`、evidence、confidence 和少量可序列化 feature。
- 每个 detector 必须声明正向/反向 payload packet 预算和 byte 预算；默认不得超过正反向各 4 个 payload 包。需要更多包的协议必须单独证明收益并在资源表中加上 hard limit。
- detector 只能使用固定字段、长度检查、magic、命令 token、方向阶段、有限状态和 bounded helper；热路径不得执行 PCRE、回溯正则、用户提供的 bytecode 或随规则数线性增长的 payload 扫描。
- 大 crypto/HKDF/shash scratch 继续使用受控的 per-CPU context；必须使用安全的 per-CPU 访问封装，不能把 VMAP stack 地址传给 scatterlist/crypto API。

### 7.3 MVP 支持矩阵

| 输入 | MVP 行为 |
| --- | --- |
| HTTP/1 GET/POST/HEAD | 提取并规范化 Host；URI 继续提供给 legacy URL logger，但不参与 MVP app rule |
| HTTP header 连续跨 TCP 包 | 在 flow budget 内拼接连续前缀 |
| HTTP keep-alive 后续 request | 不重新分类；MVP 是 per-connection 首段分类，不是 per-transaction ACL |
| TLS ClientHello | 确认 TLS，提取普通或 outer SNI |
| TLS 跨连续 TCP 包 | 在 flow budget 内拼接；不承诺完整多 TLS record handshake 重组 |
| QUIC v1 Initial/UDP 443 | 解密第一个受支持 Initial，提取 CRYPTO 中 ClientHello SNI |
| QUIC v2、Retry、复杂 coalesced、稀疏 CRYPTO | 协议可标记为 QUIC 变体，app unknown，给出精确 reason |
| ECH | 只能使用可见 outer SNI；无可见 SNI 时 app unknown |
| 其他 TCP/UDP | 仅交给显式启用的 detector；没有 detector 或预算耗尽时 `proto_id=UNKNOWN` 或 `proto-only`，不做任意 payload 扫描 |

### 7.4 非 HTTP/TLS/QUIC detector 分级

非 HTTP/TLS/QUIC 应用识别按协议族分级进入。每个 detector 合并前必须给出 nDPI 参考来源、最小确认条件、误判模型、方向/包数预算和 corpus。

| 等级 | 协议示例 | 进入条件 | 默认动作 |
| --- | --- | --- | --- |
| A | DNS、STUN/TURN、SSH、BitTorrent handshake/DHT、WireGuard | 有固定 magic、版本/长度字段或稳定握手，3-4 包内可高置信确认 | 可产生 `DIRECT_PROTOCOL`，少量可产生 `DIRECT_APP`；MVP 仅审计 |
| B | FTP、SMTP、POP3、IMAP、SIP、RTSP、MQTT、Redis、MySQL、PostgreSQL、RDP、SMB | 明文命令或二进制握手明确，但可能依赖 server-first 或 STARTTLS/升级路径 | 先 audit-only，覆盖率和误判稳定后再允许 policy |
| C | OpenVPN、SoftEther、Kerberos、RTP/RTCP、游戏/私有 UDP、代理/VPN 变体 | 需要多包方向模式、弱 magic、端口上下文或复杂状态；误判风险更高 | 默认只输出 protocol-only 或 hint，不用于阻断 |
| D | 仅端口/IP、DNS 关联、统计特征、加密不可见流量 | 证据弱或容易被共享基础设施污染 | 不单独产生可阻断 app，只能审计或辅助用户态分析 |

A/B/C/D 是准入等级，不是 ABI。实现时仍以固定 `detector_id`、`proto_id`、confidence 和 reason 输出。

典型 detector 形态：

- 明文命令型：在原始方向看命令 token，在反向看响应码或 banner；例如 FTP/SMTP/IMAP/SIP/RTSP。
- 二进制握手型：校验 magic、version、length、message type 和 reserved bits；例如 DNS/STUN/WireGuard/MySQL/PostgreSQL。
- 双向阶段型：保存 1-2 个小字段和方向阶段，等待反向确认；例如 SSH、BitTorrent、OpenVPN、RDP。
- 域名/名称型：复用 Host/SNI/QNAME normalize 和 suffix matcher；例如 DNS QNAME 或明文协议中的 server name。

禁止形态：

- 把正反向 payload 串接后跑一个大正则。
- 对所有规则做线性 payload contains 扫描。
- 因端口命中就输出可阻断 `app_id`。
- 在 flow context 中保存未上限的 payload、host 列表或候选链。

### 7.5 初始支持应用清单

本节定义 DPI 设计目标和分阶段支持范围，不表示当前源码已经实现。清单分成两类：

- **内置 detector app/proto**：内核 detector 可在连接首段通过握手、magic、长度、方向阶段或名称字段确认 `proto_id`，必要时由规则映射为 `app_id`。
- **域名规则 app**：内核只提供 HTTP Host、TLS/QUIC SNI、DNS QNAME 的规范化和后缀匹配；具体品牌、业务和域名后缀由用户态规则包下发，不硬编码进内核。

所有清单项默认先进入审计。进入阻断或 QoS 前，必须有 shadow 数据证明误判率、覆盖率和 CPU/内存成本符合目标。端口、共享 CDN/IP、DNS 关联和统计特征不能单独把未知加密流标记为可阻断应用。

#### 7.5.1 M1 内置 detector 清单

M1 只承诺审计输出和规则命中事件，不默认执行应用级阻断。

| 名称 | 默认输出 | 最小确认证据 | 备注 |
| --- | --- | --- | --- |
| HTTP/1 | `proto_id=HTTP`，Host 规则可映射 `app_id` | original 方向 request line + Host header | URI 继续服务 legacy URL logger；DPI app rule 不依赖 path |
| TLS over TCP | `proto_id=TLS`，SNI 规则可映射 `app_id` | ClientHello record、handshake length、SNI extension | ECH 只能使用可见 outer SNI；无可见 SNI 时 app unknown |
| QUIC v1 | `proto_id=QUIC`，SNI 规则可映射 `app_id` | UDP long header Initial v1、可解密 CRYPTO ClientHello、SNI | QUIC v2/Retry/复杂 coalesced 先输出 reason，不做强应用判断 |
| DNS | `proto_id=DNS` | DNS header、question count、name/length 边界、type/class | QNAME 只用于本 DNS flow 审计或规则命中，不给后续流做强关联阻断 |
| STUN/TURN | `proto_id=STUN` | message type、magic cookie、length、attribute 边界 | 可审计 WebRTC/VoIP 基础流量，但不能据此确认 Zoom/Teams 等品牌应用 |
| SSH | `proto_id=SSH` | 双向 SSH version exchange 或原向 banner + 合法格式 | 仅确认 SSH 协议；具体业务由外部规则或地址策略决定 |
| BitTorrent | `app_id=BITTORRENT` 或 `proto_id=BT_DHT` | TCP BitTorrent protocol handshake，或 UDP DHT magic/transaction 结构 | TCP/UDP 分 detector；命中后仍受 M1 audit-only 限制 |
| WireGuard | `app_id=WIREGUARD` | handshake initiation/response type、长度、reserved 字段和方向阶段 | 不因 UDP 端口单独命中；优先要求方向阶段确认 |

#### 7.5.2 M2 内置 detector 候选清单

M2 在 M1 事件格式和资源预算稳定后进入 shadow。以下协议仍需逐项提交 nDPI 参考、样本 corpus、误判模型和包数字节预算。

| 名称 | 默认输出 | 关键证据 | 风险 |
| --- | --- | --- | --- |
| FTP | `proto_id=FTP` | server banner、USER/PASS/response code 阶段 | 明文控制连接可识别；数据连接不在 MVP 自动关联 |
| SMTP | `proto_id=SMTP` | banner/EHLO/HELO/response code | STARTTLS 后只保留已确认协议，不继续解析加密内容 |
| POP3 | `proto_id=POP3` | `+OK` banner、USER/PASS/STAT 等命令 | server-first，需要反向首包预算 |
| IMAP | `proto_id=IMAP` | tagged command、`* OK` banner、CAPABILITY | 语法较松，必须避免弱 token 误判 |
| SIP | `proto_id=SIP` | request/status line、Via/Call-ID/CSeq 组合 | 与 HTTP-like 文本协议相似，必须多字段确认 |
| RTSP | `proto_id=RTSP` | RTSP request/status line、CSeq/header 组合 | 与 HTTP-like 文本协议相似，不能只看方法名 |
| MQTT | `proto_id=MQTT` | CONNECT packet type、remaining length、protocol name/version | TCP 粘包和短包要走 prefix budget |
| Redis | `proto_id=REDIS` | RESP frame、命令/响应阶段 | 明文管理流量，误判要靠 RESP 边界确认 |
| MySQL | `proto_id=MYSQL` | server handshake packet、protocol version、capability flags | server-first，需要反向首包预算 |
| PostgreSQL | `proto_id=POSTGRESQL` | startup/SSLRequest/cancel request 或 server response | SSLRequest 后不继续解析加密内容 |
| RDP | `proto_id=RDP` | TPKT/X.224 connection request/confirm | 可能与其他 TPKT 协议冲突，需严格版本/长度 |
| SMB | `proto_id=SMB` | SMB1/SMB2 magic、header length、command field | 只确认协议，不深入文件名/共享名策略 |

#### 7.5.3 M4/专项 detector 清单

这些协议默认不进入 M1/M2 阻断面。只有在目标部署有明确需求、样本充足且 shadow 证明稳定后，才单独设计 detector。

| 名称 | 默认输出 | 准入要求 |
| --- | --- | --- |
| OpenVPN | `proto_id=OPENVPN` 或 hint | 证明 magic/opcode/session id 组合在目标网络中低误判；不能只看 UDP 1194 |
| SoftEther | `proto_id=SOFTETHER` 或 hint | 明确握手阶段和与 TLS/HTTPS 的边界 |
| Kerberos | `proto_id=KERBEROS` | ASN.1/port/context 必须共同确认；不能只凭 88 端口 |
| RTP/RTCP | `proto_id=RTP`/`RTCP` 或 hint | 需要与 SIP/SDP、端口范围或方向阶段组合；默认不阻断 |
| Shadowsocks/V2Ray/Trojan/VLESS 等代理 | hint 或 domain app | 只有存在可解释握手或显式部署规则时进入；未知加密流不能靠端口/IP 标记 |
| 游戏/私有 UDP | app hint | 按 Steam Datagram Relay、Riot、Tencent Games、Battle.net 等逐个 detector 评审；共享 CDN/IP 不作为强证据 |

#### 7.5.4 首批域名规则应用清单

以下应用通过 HTTP Host、TLS SNI、QUIC SNI 或 DNS QNAME 的后缀规则识别。规则包由用户态下发，内核只保存编译后的 hash + DNS label 边界 suffix probe 所需数据和 `app_id`。同一 host 命中多个后缀时，必须选择最长后缀或显式优先级最高的规则。

| 类别 | 首批应用 |
| --- | --- |
| 搜索/平台 | Google、Baidu、Bing |
| 视频/短视频 | YouTube、Netflix、TikTok、Douyin、Kuaishou、Bilibili、Tencent Video、iQiyi、Youku |
| 社交/消息 | WeChat、QQ、WhatsApp、Telegram、Discord、Facebook、Instagram、X/Twitter |
| 办公/云协作 | Microsoft 365、Teams、OneDrive、Apple iCloud、Google Workspace |
| 电商/支付/生活服务 | Taobao、Tmall、Alipay、JD.com、Meituan、Amazon |
| 游戏/分发 | Steam、Epic Games、Battle.net、PlayStation Network、Xbox Live、Riot Games、Tencent Games |
| 云/基础设施 | AWS、Azure、Google Cloud、Cloudflare、Akamai、Fastly |

云、CDN、对象存储和公共加速域名属于共享基础设施。默认只能作为审计分类或 QoS 辅助，不建议作为阻断目标；如果用户强制配置阻断，事件必须保留 `confidence`、`rule_id` 和命中后缀，便于解释误伤。

## 8. Flow selector、hook 与 fast-path gate

### 8.1 Scope

MVP 只分类默认 FORWARD 路径中的新连接：

- IPv4、IPv6、bridge 上的 forwarded TCP/UDP。
- TCP 仅在看到 original SYN 或 TCP Fast Open 新流时 arm；中途启用 DPI 不追认既有 TCP 连接。
- UDP 仅在 conntrack original 方向的首个 NEW 包 arm；非目标 UDP 可立即 terminal/bypass。arm 后可按 detector 预算观察正反向 payload，但默认正反向各不超过 4 个 payload 包。
- LOCAL_IN、LOCAL_OUT 和没有 conntrack 的 skb 明确 bypass。`CONFIG_NATFLOW_URLLOGGER_LOCAL_IN` 的 legacy 行为不自动扩展成 DPI 行为。
- bridge 与 inet hook 对同一 conntrack 的重复观察通过原子 state claim 去重。

### 8.2 Arm 时点

统一 L7 `FORWARD` hook 负责正常 arm，但不能只依赖这个 hook：当前 fast path 在 conntrack/DPI hook 之前先查旧 fastnat node，tuple 复用可能让新流直接命中残留 node。

因此 M1 必须同时实现两层保护：

1. fast path 在命中并发送前识别 TCP SYN/TFO；这类包必须使匹配的旧 node 失效并回 slow path。
2. UDP fast path 只做常量时间 candidate probe：QUIC/443 long-header Initial v1、以及显式启用的少量 UDP detector 端口/magic 组合。candidate 必须回 slow path，不能在 ingress 做 crypto、状态机或完整 DPI parse。没有 candidate 规则的 UDP 继续走现有 fast path。

进入 slow path 后，统一 L7 `FORWARD` hook 在 path POST route 学习前调用 `natflow_dpi_arm()`，并在正常 arm 后设置 `NF_FF_DPI_USE`。path POST/HWNAT 编程点只检查扩展后的 `NF_FF_BUSY_USE`，不额外调用 DPI gate repair helper。若并发非原子 writer 覆盖了 DPI bit，可能提前进入 fast path，这是本设计接受并要求计数/压测说明的限制。

如果厂商硬件会在 CPU 观察新 SYN 或 UDP detector candidate 前按残留 tuple 转发，DPI 模式下必须为目标协议禁用该硬件 offload，直到厂商路径能保证 new-flow control packet 回 CPU。不能在无法证明这一点的平台宣称 DPI 覆盖。

### 8.3 `nf->status` owner bit

DPI 沿用现有 owner 模型，建议预留：

```c
#define NF_FF_DPI_USE_BIT 21
#define NF_FF_DPI_USE (1U << NF_FF_DPI_USE_BIT)
#define NF_FF_BUSY_USE (NF_FF_USER_USE | NF_FF_URLLOGGER_USE | NF_FF_DPI_USE)
```

实现约束：

- 进入 `ARMING` 前设置 `NF_FF_DPI_USE`；`ARMING`、`ARMED`、`PARSING` 和 `WAIT_MORE` 正常情况下都持有该 bit。
- terminal writer 按程序顺序先写 result/policy 和 `DONE_*`，再清 `NF_FF_DPI_USE`；不要求 path 侧通过 acquire/release handshake 重新确认 DPI state。
- `UNSEEN`、`BYPASS` 和全部 `DONE_*` 正常情况下不持有 DPI bit。
- IPv4、IPv6、软件 fastnat、HWNAT/WED 的每个 entry programming 点都只检查扩展后的 `NF_FF_BUSY_USE`；DPI 不再增加 path-side ensure/repair API。
- URL 和 DPI 使用不同 owner bit，一个 consumer 正常完成时只清自己的 bit。

bit 21 在当前仓库未使用，但实现前仍需确认 NATCAP、厂商补丁和部署分支没有私占。

已接受限制：`nf->status` 是普通 `unsigned int`，现有 `simple_*` helper 不是原子操作。任一并发 writer 都可能覆盖 DPI bit，DPI 不尝试在 path 建表前修复该状态；因此仍可能出现提前 fast path、漏审计或漏策略。该风险必须有计数/并发压测和部署说明，但不作为 M0/M1 阻塞项。

### 8.4 Gate 不变量

- active state 正常情况下必须持有 DPI bit；terminal state 正常情况下必须清除 DPI bit。
- detector、cache、policy、event 任一错误都必须走唯一 `dpi_finish()`，禁止散落发布 terminal。
- terminal 前不得为本连接建立软件 fastnat 或硬件 offload 项。
- queue full、没有 reader 或审计分配失败不得延长 gate。
- app drop/reset terminal 必须先设置永久 drop/stop 状态，再发布 terminal 并清 DPI bit。
- 新 TCP SYN/TFO 和 UDP detector candidate 必须能够穿透残留 fast node 到达 arm；不满足的平台只能关闭对应 offload 或禁用对应 detector。

## 9. Flow 状态、结果与并发

### 9.1 状态机

```text
UNSEEN --not selected--> BYPASS
   |
   +--selected--> ARMING
                    |
                    +--register context + bind ruleset--> ARMED
                              |
                              v
                           PARSING <----+
                              |         |
                              +--> WAIT_MORE
                              |
                              +--> DONE_APP
                              +--> DONE_PROTO
                              +--> DONE_UNKNOWN
                              +--> DONE_ERROR
```

- 设置 DPI owner bit 后由 cmpxchg claim `ARMING`。arm 必须为每个 selected flow 登记 context、持有 ct 引用并绑定 ruleset；任一步失败都直接 `DONE_ERROR` 并清 DPI bit。
- `ARMING` 只允许存在于当前 netfilter 临界期内。disable/exit 先阻止新 arm 并 `synchronize_net()`，所以 drain 开始时不会遗留未登记的 `ARMING`。
- `PARSING` 由 cmpxchg claim，保证同一 conntrack 同时只有一个 detector owner，但其他 CPU 的 payload 不能被忽略。
- 每个 payload packet 先在 context 短锁内做有界 sequence merge，再竞争 detector owner。loser 已把连续字节并入 prefix；若遇到无法表达的 gap/overlap 或 merge 预算耗尽，则确定性 terminal 为 `TCP_GAP`/`PARSE_CONTENTION`，不能静默等待超时。
- detector owner 对稳定的 prefix length 做解析；解析期间新 append 只发生在已发布长度之后。owner 返回 `NEED_MORE` 前若发现 prefix generation 已变化，可在固定次数上限内重试，否则由下一包继续。
- `DONE_*` 都是 terminal；terminal 后不重新分类，即使规则已更新。
- FIN/RST、deadline、packet/byte budget、TCP gap、cache attach 失败和 module disable 都必须终止。

### 9.2 `natflow_t` 尾部结果

MVP 只在 `natflow_t` 尾部追加一个 32 位应用结果，所有既有字段偏移保持不变：

```c
struct natflow_dpi_flow {
	u32 app_id;
};
```

这是内核私有布局示意，不可直接作为 UAPI copy 给用户态。要求：

- `app_id` 是唯一常驻 flow 结果。`0` 表示 unknown 或尚无应用命中；非 0 表示当前连接已经由 DPI 规则识别出应用。
- DPI 状态机、`rule_id`、`ruleset_generation`、`category_id`、`proto_id`、`detector_id`、`evidence`、`confidence`、`reason`、`inspected_bytes`、payload packet 计数和 policy action 都属于 active context 或 terminal event 数据，不常驻 conntrack。需要审计时在 terminal 当场序列化到 `/dev/natflow_dpi_queue`；event ring 满时这些诊断信息可以丢失，只保留 flow 上的 `app_id`。
- 不在 flow 中保存 host、path、payload 或任意指针。
- 不使用 skb/ct mark 保存结果，避免覆盖 QoS、tc、路由和用户态已有语义。
- writer 在 matched 结果时先写 `app_id`，再写 terminal state，最后清 DPI owner bit；unknown/error/disabled 等未命中场景保持 `app_id=0`。由于沿用非原子 `nf->status`，这是正常路径顺序约束，不提供跨 CPU 完整同步保证。
- M3 若实现 App QoS，优先复用常驻 `app_id` 重新查当前 policy；只有实测证明必须缓存更多状态时，才在独立设计中扩大该结构或提出等价持久存储。
- 扩大 `natflow_t` 是 M0/M1 的设计前置门槛，必须先在真实 NATCAP 组合上验证 `nat_key_t.len`、`natflow_off`、`NATCAP_MAX_OFF` 和现有脆弱 krealloc 假设。v4 不提供长期 result side-table fallback；验证不通过的 build 必须拒绝 `CONFIG_NATFLOW_DPI`，不能在实现后期静默换存储模型。

### 9.3 跨包 context

每个 selected flow 都使用全局分片 hash 中的固定预算 `natflow_l7_flow_ctx`；只有跨包字节不放进 `natflow_t`：

- key 使用持有引用的 `struct nf_conn *`，避免地址复用；context terminal/过期时 `nf_ct_put()`。
- context 在进入 `ARMED` 前保存 deadline、双向连续 TCP sequence、detector bitset/stage、正反向 packet/byte counter、arm-time ruleset 引用、consumer mask 和受限 prefix buffer。
- flow 可跨 CPU 查找同一 context，替代当前 per-CPU flow cache。
- bucket 使用细粒度 spinlock；同一 flow context 再做单 owner claim。
- context registry 覆盖 `ARMED`、`PARSING` 和 `WAIT_MORE`，因此单个 delayed work 可以批量过期，disable/exit 可以枚举并完成全部 active DPI owner；不为每个 flow 建 timer。
- module exit 顺序必须先停止新 hook，再 drain context、写入 terminal 并清各 consumer owner bit，最后释放 cache 和 ruleset。

### 9.4 多 consumer 生命周期

共享 L7 detector/parser cache 不等于共享 terminal。每个 `natflow_l7_flow_ctx` 必须包含 `consumer_mask` 和每个 consumer 的 done/reason：

- 当前 consumer 至少为 `URLLOGGER` 和 `DPI`。flow arm 时在控制 mutex/RCU 保护下捕获 active consumer mask；运行时新 enable 默认只加入之后 arm 的 flow。
- packet view、sequence merge、prefix 和 detector/parser invocation 只有一份。detector/parser 产出 feature 后，在同一调用内 fan-out 给 mask 中尚未 done 的 consumer。
- DPI 达到正反向 packet/byte 预算、规则 terminal 或 disable 时，只发布 DPI result/state 并清 DPI owner bit；如果 URL consumer 仍在等待，shared prefix/context 和 URL owner 继续存在。
- URL consumer 按 legacy byte/time/parser 语义完成并只清 URL owner。M0/M1 若改变 HTTP 跨包识别或 enable 只影响新流的行为，必须作为明确行为变化进入 README/SYSTEM_DESIGN_SPEC，而不能伪装成纯重构。
- 关闭任一 consumer 只从所有 context 中完成该 consumer。最后一个 consumer done 后，才能释放 prefix、ruleset/ct 引用和 context slot。
- consumer 的 telemetry 分配失败只影响该 consumer 的事件；Host ACL/policy 决策不得依赖 URL record 或 DPI event 对象。
- shared L7 context pool/crypto/cache 由 core 按 active consumer refcount 管理。legacy `urllogger_store/enable` 必须换成保持同路径、数值和 Host ACL 联动语义的 custom sysctl handler，在 consumer control mutex 下完成资源准备/回滚；不能继续只改一个裸变量。

这样 DPI disable 不会释放仍被 URL logger 使用的 reassembly，URL logger 完成也不会提前发布 DPI terminal。

## 10. 规则模型与查找

### 10.1 MVP 规则

MVP 有三类配置对象：

```text
app:    app_id -> category_id
domain: rule_id, app_id, kind(exact|suffix), source_mask, normalized_host
proto:  rule_id, app_id, proto_id, min_confidence, optional detector_mask
```

- `source_mask` 可限制 `HTTP_HOST`、`TLS_SNI`、`TLS_OUTER_SNI` 和 `QUIC_SNI`。
- `exact example.com` 只匹配 `example.com`。
- `suffix example.com` 匹配 apex `example.com` 及 label 边界子域，如 `a.example.com`；不得匹配 `badexample.com`。
- 不接受 `*.example.com`、正则、contains 或非 DNS label glob，避免通配语义歧义。
- hostname 使用与 URL logger 相同的严格 normalize/validate：ASCII 小写、去 root dot、总长和 label 长度限制、拒绝控制字符和空 label。
- `proto` 规则把 detector 确认的 `proto_id` 映射到用户定义 `app_id`，例如 `proto=ssh app=2001`。它不能由端口猜测单独触发，至少需要 `DIRECT_PROTOCOL` confidence。
- `rule_id` 在整个 snapshot 内唯一。相同 kind/host 的任意两条规则只要 `source_mask` 有交集就必须在 commit 时拒绝；数据面不处理同等 specificity 的二义性，也不保留无界候选链。

HTTP path、UA、任意 payload contains 和组合条件不进入 MVP。现有 URI 仍可由 legacy URL logger 输出，但 DPI classifier 不复制 query/path 到 flow result。

### 10.2 数据结构

规则 snapshot 在进程上下文构造为不可变对象：

- app 表按 `app_id` hash。
- domain 表使用 snapshot-local 随机 seed 的 hash bucket。
- proto 表按 `proto_id` 索引或 hash，commit 时拒绝同一 `proto_id` 下相同或重叠 `detector_mask/min_confidence` 的二义性规则。
- domain lookup 先查 exact，再从最长到最短枚举 DNS label suffix。
- proto lookup 只在 detector 输出 `proto_id` 和满足 `min_confidence` 时执行，不做 payload 扫描。
- suffix probe 次数有硬上限；超过上限保留 protocol result，并以 `RULE_LOOKUP_BUDGET` 结束应用匹配。
- hash 冲突链长度在 commit 时检查；超过 hard cap 拒绝整个 snapshot。
- 所有 rule 字符串和 bucket storage 计入 snapshot memory limit。

这使热路径复杂度受 host 长度、suffix probe 上限和 collision cap 共同约束，而不是规则总数。

### 10.3 Snapshot 生命周期

1. 每个控制 fd 在 private staging 中构造完整候选 ruleset。
2. `commit` 在 mutex 下校验 base generation、引用、冲突和所有 hard limit。
3. 构造完成后一次 `rcu_assign_pointer()` 发布，不在 live snapshot 上原地修改。
4. 每个 selected flow 在 arm 时绑定 snapshot。immediate parse 和 `WAIT_MORE` 都通过 context 使用该引用，不在实际 lookup 时重新选择 current snapshot。
5. 替换后的 global 引用在 grace period 后释放；只有 global 和 active context 引用都归零时才能 free。
6. 因此规则 commit 只影响 commit 后 arm 的连接；等待中的旧连接仍使用原 generation。
7. accounting 同时覆盖 current、retired 和 staging snapshot；不能用单 snapshot limit 代替全局总上限。

## 11. 用户态 ABI

### 11.1 编译与默认开关

- 新增独立 `CONFIG_NATFLOW_DPI`，默认未定义。
- shared L7 core 在 `CONFIG_NATFLOW_URLLOGGER` 或 `CONFIG_NATFLOW_DPI` 任一启用时编译。
- `CONFIG_NATFLOW_DPI` 不强制依赖 `CONFIG_NATFLOW_PATH`；没有 path 时仍可审计，但 gate 不产生加速协作效果。
- `natflow_probe_ct_ext()` 必须从 path 私有初始化移到 common/main 的 exactly-once 初始化，并在 user/path/URL/DPI 注册任何 hook 前完成。probe 改为可返回错误；失败时 DPI 保持 `DISABLED` 且模块不得注册 DPI hook。DPI-only build 不能使用未经 probe 的默认 fixed offset。
- DPI 运行时默认 `enable=0`。DPI enable 不改变 legacy `/proc/sys/urllogger_store/enable` 语义：该 sysctl 仍同时控制 URL CSV 记录和 Host ACL 处理；`enable=0` 时不执行 Host ACL，即使 DPI 已启用。L7 activation 是 DPI consumer 与 legacy URL/HostACL consumer 的 OR。
- 实现新增宏、设备和行为后，再同步 README、SYSTEM_DESIGN_SPEC、Makefile.dkms 和 agent memory；设计阶段不把未实现接口写成现状。

### 11.2 `/dev/natflow_dpi_ctl`

新设备使用严格的文本控制协议，但不复用 legacy `MAX_IOCTL_LEN=256`。定义 `DPI_CTL_MAX_LINE=512`，以容纳最长合法 hostname 和全部固定字段。

MVP 使用**完整替换事务**，不直接对 live ruleset add/delete：

```text
begin abi=1 base_gen=12
app id=1001 category=10
app id=2001 category=20
domain id=1 app=1001 kind=exact source=http,tls,tls_outer,quic host=video.example.com
domain id=2 app=1001 kind=suffix source=tls,tls_outer,quic host=cdn.example.com
proto id=3 app=2001 proto=ssh min_confidence=direct_protocol
commit
```

另有：

```text
abort
enable=0|1
event_mode=matched|evidence|all
```

ABI 规则：

- 每个 open fd 有独立 staging 和半行 buffer；close 自动 abort，多个 writer 不共享静态缓存。
- 每行必须以 `\n` 结束；超长、重复 key、非法 ID、未知 key/value 或 generation 冲突返回明确负 errno，不打印后假装成功。
- `begin` 创建空 staging，后续 app/domain/proto 构成完整新配置；`commit` 全成或全败。
- `proto=` 使用 Natflow 固定 protocol name 或十进制 `proto_id`；未知 protocol、低于 detector 准入等级的 protocol 或不满足 confidence 约束的配置返回 `-EINVAL`。
- write/control 需要 `CAP_NET_ADMIN`；设备权限仍需部署侧限制。
- read 使用 seq_file，支持 partial read，输出 ABI、enable、generation、hard/active limits、usage、各 terminal reason counter、event lost count 和可重放配置。
- 同时最多 2 个 staging fd，单 staging 最多 2 MiB，全局 staging bytes 最多 4 MiB；超限的 open/write 返回 `-ENOSPC`，close/abort 必须归还 accounting。
- 本仓库不要求提供 daemon；后续可增加小型 loader 工具，但不是内核热路径的一部分。

### 11.3 `/dev/natflow_dpi_queue`

新队列输出版本化二进制 frame。不得直接 `copy_to_user()` 本机 C struct；实现必须在独立 UAPI header 中定义固定 offset，并显式 serialize。

v1 固定 header 为 104 字节，按以下 offset 显式编码：

| Offset | Size | 字段 | 编码 |
| --- | --- | --- | --- |
| 0 | 4 | `magic` | `__le32`，常量 `NATFLOW_DPI_EVENT_MAGIC=0x3144464e`，wire bytes 为 `NFD1` |
| 4 | 2 | `abi_version` | `__le16`，v1 为 1 |
| 6 | 2 | `header_len` | `__le16`，v1 为 104 |
| 8 | 2 | `record_len` | `__le16`，104..512 |
| 10 | 1 | `record_type` | v1 terminal event 为 1 |
| 11 | 1 | `flags` | bit 0=`DPI_EVENT_F_TLV_OMITTED`；其余 v1 必须写 0，reader 忽略未知位 |
| 12 | 4 | `reserved0` | 必须写 0 |
| 16 | 8 | `sequence` | `__le64` |
| 24 | 8 | `monotonic_boot_ms` | `__le64`，非 Unix epoch |
| 32 | 4 | `ruleset_generation` | `__le32` |
| 36 | 4 | `rule_id` | `__le32` |
| 40 | 4 | `app_id` | `__le32` |
| 44 | 2 | `category_id` | `__le16` |
| 46 | 1 | `family` | 4=`DPI_AF_INET`，6=`DPI_AF_INET6` |
| 47 | 1 | `l4_proto` | IANA IP protocol number |
| 48 | 2 | `proto_id` | `__le16`，Natflow 固定协议枚举，0=unknown |
| 50 | 2 | `detector_id` | `__le16`，Natflow 固定 detector 枚举，0=none |
| 52 | 1 | `confidence` | 取 5.3 节固定值 |
| 53 | 1 | `evidence` | 0=none, 1=HTTP_HOST, 2=TLS_SNI, 3=TLS_OUTER_SNI, 4=QUIC_SNI, 5=DNS_QNAME, 6=BINARY_MAGIC, 7=COMMAND_TOKEN, 8=HANDSHAKE_STAGE, 9=FLOW_PATTERN |
| 54 | 1 | `reason` | 取下方 v1 reason enum |
| 55 | 1 | `policy_action` | 0=none/audit；其他值 v1 保留 |
| 56 | 1 | `direction` | 0=original, 1=reply, 2=bidirectional |
| 57 | 1 | `address_len` | IPv4=4，IPv6=16 |
| 58 | 2 | `reserved1` | 必须写 0 |
| 60 | 2 | `source_port` | network byte order |
| 62 | 2 | `destination_port` | network byte order |
| 64 | 16 | `source_address` | network-order bytes；IPv4 只用前 4 字节，其余清 0 |
| 80 | 16 | `destination_address` | 同上 |
| 96 | 2 | `tlv_count` | `__le16` |
| 98 | 2 | `reserved2` | 必须写 0 |
| 100 | 4 | `reserved3` | 必须写 0 |

tuple 固定使用 conntrack original tuple，不随 legacy `tuple_type` 改变。

v1 reason 数值固定为：

| 值 | Reason | 值 | Reason |
| --- | --- | --- | --- |
| 0 | `NONE` | 1 | `MATCHED` |
| 2 | `NO_RULE` | 3 | `NO_VISIBLE_METADATA` |
| 4 | `NOT_ELIGIBLE` | 5 | `REPLY_FIRST` |
| 6 | `FIN_RST` | 7 | `ECH` |
| 8 | `UNSUPPORTED_VERSION` | 9 | `UNSUPPORTED_VARIANT` |
| 10 | `CRYPTO_UNAVAILABLE` | 11 | `FRAGMENT` |
| 12 | `IPV6_EXTENSION_LIMIT` | 13 | `TCP_GAP` |
| 14 | `PARSE_CONTENTION` | 15 | `MALFORMED` |
| 16 | `PACKET_BUDGET` | 17 | `BYTE_BUDGET` |
| 18 | `TIME_BUDGET` | 19 | `CACHE_FULL` |
| 20 | `NO_MEMORY` | 21 | `RULE_LOOKUP_BUDGET` |
| 22 | `PARSER_BUDGET` | 23 | `DPI_DISABLED` |
| 24 | `MODULE_EXIT` | 25 | `PROTO_ONLY` |
| 26 | `NO_MATCH` | 27 | `NO_DETECTOR` |

header 后是 `tlv_count` 个 TLV。每个 TLV header 固定为 `type:__le16, len:__le16`，随后为 `len` 字节 value，再补 0 到 4 字节对齐；padding 计入 `record_len`，reader 用 `ALIGN(4 + len, 4)` 跳过未知 type。

- type 1=`HOST`：规范化 host，不带 NUL，最大 253 字节，因此 v1 总 record 可以稳定放入 512 字节 slot。
- type 2=`EVIDENCE_BYTES`：用于少量固定证据字节或命令 token，最大 64 字节；只在 `event_mode=evidence|all` 输出，不能保存任意 payload。
- MVP 不输出 HTTP query/path；完整 URL 继续由 legacy queue 负责。
- `record_len` 必须不大于 512。未来可选 TLV 放不下时省略该 TLV、设置 `DPI_EVENT_F_TLV_OMITTED` 并增加 counter；不得截断 HOST 后伪装成完整值，也不得丢掉固定 header event。

除 IP/port 外的多字节整数都使用 little-endian。实现必须提供独立 UAPI header、size/offset static assertion、reserved-zero test 和 userspace golden decode test。

队列语义：

- 固定容量 ring，packet path 只做一次有界 copy；满时 drop-new 并增加 `event_lost`，不阻塞、不影响 policy、不延迟 terminal publication。
- 单一破坏性 consumer；open 需要 `CAP_NET_ADMIN`，第二个 reader 返回 `-EBUSY`，避免两个 reader 随机分流事件。
- 一次成功 read 恰好返回一条完整 record，不打包多条也不做 partial record。blocking read 等待；`O_NONBLOCK` 无数据返回 `-EAGAIN`；支持 `poll()`。
- 用户 buffer 小于下一个 `record_len` 时返回 `-EMSGSIZE` 且不消费记录。
- 每 flow 最多输出一个 terminal event。默认 `event_mode=matched`；诊断模式可输出有 evidence 的未匹配或全部 terminal。
- `sequence` 在满足 event_mode、准备尝试入队时先递增；ring full 的丢失 attempt 因而在成功事件中形成 sequence gap，并同时增加 `event_lost`。被 event_mode 主动抑制的事件不占 sequence。
- 只有模块退出/设备失效产生 EOF；普通暂时无数据不是 EOF。

### 11.4 Runtime control 状态机

DPI enable/disable、legacy consumer enable/disable、ruleset commit 和 event mode 更新由同一个 L7 control mutex 串行化。DPI 全局状态固定为：

```text
DISABLED -> ENABLING -> ENABLED -> DISABLING -> DISABLED
```

- `enable=1` 先进入 `ENABLING`，完成 conntrack ext probe 状态确认、context/ring/crypto capability 和初始 ruleset 引用准备；只有全部成功后才以 release 语义发布 `ENABLED`。
- ENABLING 任一步失败都按逆序释放本次资源、恢复 `DISABLED` 并返回原始 errno，不能留下部分 parser/queue 可用的半启用状态。
- `enable=0` 先以 release 语义发布 `DISABLING`，arm 只在 acquire-load 到 `ENABLED` 时允许；随后 `synchronize_net()`，完成所有 context 中的 DPI consumer，最后发布 `DISABLED`。
- shared L7 资源仍被 URL consumer 使用时不能释放，只移除 DPI consumer；DPI-only 资源在 drain 后释放。
- 同值 enable 写是幂等成功；ENABLING/DISABLING 期间的冲突控制操作返回 `-EBUSY`。commit 和 event_mode 不得与状态迁移交错。
- module exit 复用 DISABLING 路径，但 terminal reason 使用 `MODULE_EXIT` 并唤醒 queue reader。

## 12. Legacy URL logger 与 Host ACL 兼容

- `/dev/urllogger_queue` 的 CSV 字段、escaping、老化/合并、tuple_type 和 read 行为保持原样，除非另立兼容变更任务。
- `/dev/hostacl_ctl` 命令、32 个槽位、ipset 命名和四种 action 保持原样。
- `/proc/sys/urllogger_store/enable` 的 legacy 语义保持原样：`0` 表示不记录 URL 且不执行 Host ACL，`1` 表示 legacy URL/HostACL consumer 参与共享 parser。DPI enable 不能让 Host ACL 在该 sysctl 为 `0` 时生效；若未来要拆分 Host ACL 独立开关，必须作为单独 ABI 变更设计。
- `IPS_NATFLOW_URLLOGGER_HANDLED` 只表示 legacy consumer 已处理，不代表 DPI terminal。
- shared parser 先产出规范化 features；Host ACL 不再依赖 URL 日志对象分配成功才执行。ACL/policy 所需最小对象必须独立、受控。
- URL store 的 O(N) 合并逻辑不得被 DPI event 复用。DPI 每流事件使用独立 ring。
- runtime 关闭 URL logger 只能完成 legacy URL/HostACL consumer/owner；不能改变 DPI state/owner。runtime 关闭 DPI 只完成每个 shared context 中的 DPI consumer，发布 DPI terminal 并清 DPI owner bit；legacy consumer 未完成时 context/prefix 继续保留。
- parser 重构必须保留 PPPoE/bridge skb 状态；目标 read-only packet view 应消除临时 pull/restore 依赖。

## 13. 策略集成（MVP 之后）

MVP 只做分类和审计。应用级 ACL/QoS 必须等 shadow 数据验证误判和覆盖率后分阶段加入。

### 13.1 App policy

未来 policy 与 classification rule 分离，selector 至少包括 app/category/proto_id/detector_id/min confidence，action 只考虑：

- `audit`
- `drop`
- `reset`（仅 TCP）
- `qos=<existing group id>`

应用 policy 不提供 redirect。HTTP redirect 继续由现有 Host ACL 实现；TLS/QUIC 不承诺 redirect。

策略顺序固定为：

1. 既有 user/auth/conntrack drop 先执行，DPI `accept` 永远不能推翻。
2. legacy Host ACL 非 record 动作优先，app policy 只能追加限制。
3. app drop 设置 `IPS_NATFLOW_CT_DROP` 和 `IPS_NATFLOW_FF_STOP`，然后才写入 DPI terminal 并清 DPI owner bit。
4. unknown/error 默认 accept；MVP 不提供 `unknown=drop`。

### 13.2 App QoS

现有 tuple/ipset QoS 在 `NF_IP_PRI_FILTER` 先完成，因此未来 app QoS 必须采用明确 adapter：

- 若 `nf->qos_id != 0`，保留既有 QoS，DPI 不覆盖。
- 若 `nf->qos_id == 0` 且 app policy 指向有效现有 QoS group，DPI 在 `FILTER + 5`、user POST 前写入 `qos_id` 并设置 `NF_FF_TOKEN_CTRL`。
- 不清除 `NF_FF_QOS_TESTED`，不在 DPI hook 中重新跑现有 tuple/ipset 规则。
- policy 所需状态必须在写入 DPI terminal 和清 DPI owner bit 前完成；由于 `nf->status` 非原子，软件/hardware path 看到该状态是正常路径契约，不是严格同步保证。
- DPI 写入的 QoS 必须设置 `DPI_FLOW_F_QOS_OWNED` 并处理 policy/QoS generation。MVP 的 flow 结果只常驻 `app_id`，不预留 generation 字段；M3 必须优先用已缓存 `app_id` 重新查当前 policy，若必须缓存 generation 再提出独立持久存储设计。clear/reload 后不能让旧数组位置静默指向另一规则。
- `NF_FF_TOKEN_CTRL` 置位后，当前 path 不建立 fastnat/HWNAT，而是保持 slow path 执行 token/tc 语义；M3 测试必须固定这一契约。

任何新的优先级需求都要先形成单独决策，不能通过最后写入者覆盖 `qos_id`。

## 14. 资源预算与热路径约束

下表是 MVP 初始 hard limit，合并实现前可根据目标设备基准下调，但不得取消上限：

| 资源 | 初始 hard limit | 耗尽行为 |
| --- | --- | --- |
| `natflow_t` DPI 固定结果 | 4 B logical/flow | session 初始化失败则不分类；实际扩展增量受 `__ALIGN_64BITS` 对齐影响 |
| active flow context | 256 个 | `CACHE_FULL`，fail-open |
| 单流连续 prefix | 32 KiB | `BYTE_BUDGET`，fail-open |
| 全局 reassembly bytes | 2 MiB | `CACHE_FULL`，fail-open |
| original/reply payload packet | 4 + 4 个 | `PACKET_BUDGET`，fail-open |
| wall-clock inspect | 4 秒 | `TIME_BUDGET`，fail-open |
| detector dispatch | 4 个/packet | 不再尝试其他 detector |
| domain rules | 4096 条 | commit 返回 `-E2BIG` |
| proto rules | 512 条 | commit 返回 `-E2BIG` |
| app entries | 1024 条 | commit 返回 `-E2BIG` |
| 单 snapshot memory | 2 MiB | commit 返回 `-E2BIG` |
| current + retired ruleset bytes | 8 MiB | commit 返回 `-EBUSY` |
| retired generations | 4 代 | commit 返回 `-EBUSY` |
| staging fd/bytes | 2 个 / 4 MiB | open/write 返回 `-ENOSPC` |
| suffix probes | 16 次/flow | `RULE_LOOKUP_BUDGET` |
| hash collision candidates | 8 个/bucket | commit 拒绝 snapshot |
| IPv6 extension walk | 8 headers / 256 B | `IPV6_EXTENSION_LIMIT` |
| HTTP header lines | 64 | `PARSER_BUDGET` |
| TLS records/extensions | 4 / 128 | `PARSER_BUDGET` 或 `UNSUPPORTED_VARIANT` |
| QUIC frames/ACK ranges | 64 / 32 | `PARSER_BUDGET` |
| prefix-change parser retry | 2 次/packet | 留给下一包或 `PARSER_BUDGET` |
| event ring | 256 x 512 B | drop-new + lost counter |

实现要求：

- active context 和 event ring 在 enable/init 时建立可核算预算；数据面不得按攻击者声明长度做任意 `kmalloc/krealloc`。
- prefix storage 使用固定 size class/mempool 或等价的全局原子 accounting，不能突破 per-flow/global 两层上限。
- `live_ruleset_bytes` 包含 current 和所有被 flow context pin 的 retired snapshot；新 commit 在发布前预留 accounting，超限时不得替换 current。retired generation/bytes 释放后，控制面可重试。
- SYN/纯 ACK 不计 payload packet；FIN/RST 会终止。
- QUIC 每 datagram 只尝试当前支持的第一个 Initial，维持现有机会性边界。
- 所有 loop 都必须能从上述 packet、byte、label、candidate、frame 或 header 数上限推导出终止条件。
- 日志只用 ratelimited 聚合计数，不能对每个 malformed packet 打印。

## 15. 降级语义

| 场景 | protocol 结果 | app 结果 | 默认动作 |
| --- | --- | --- | --- |
| Host/SNI exact 命中 | 已知 | matched | audit/allow |
| Host/SNI suffix 命中 | 已知 | matched | audit/allow |
| DNS/STUN/SSH 等 detector 确认协议但无 app 规则 | 已知 | unknown + `PROTO_ONLY` | allow |
| detector 已启用但未满足确认条件 | unknown 或 partial | unknown + `NO_MATCH` | allow |
| 没有适用 detector | unknown | unknown + `NO_DETECTOR` | allow |
| 可见 Host/SNI 无规则 | 已知 | unknown + `NO_RULE` | allow |
| TLS/QUIC 无 SNI | TLS/QUIC | unknown + `NO_VISIBLE_METADATA` | allow |
| 检测到 ECH 且有 outer SNI | TLS | 可按 outer SNI 匹配，evidence 明示 outer | allow |
| 检测到 ECH 且无可见 SNI | TLS | unknown + `ECH` | allow |
| QUIC crypto 不可用 | QUIC candidate | unknown + `CRYPTO_UNAVAILABLE` | allow |
| TCP gap/乱序 | 可保留已确认 protocol | unknown + `TCP_GAP` | allow |
| fragment/IPv6 header 超限 | unknown | unknown + 精确 reason | allow |
| cache/rule/event 资源耗尽 | 尽可能保留已知 protocol | unknown/error | allow；event 满只计数 |
| malformed | unknown 或已确认外层 protocol | unknown + `MALFORMED` | allow |

DNS/IP correlation 不是 ECH 的自动解决方案。共享 CDN、多客户端、CNAME/TTL、DNS 污染和 DoH/DoT 都会造成歧义；未来若需要，只能做 client/zone scoped 的低 confidence 关联，优先放到用户态，默认不得用于阻断。

## 16. 配置变化、既有连接与卸载

- `enable=1` 只 arm 启用后看到新建信号的连接。已建立或已 offload 的连接不会重新出现 ClientHello、协议 banner 或首段握手，不得伪装成可重分类。
- ruleset commit 只影响 commit 后 arm 的 flow；terminal flow 保留旧 generation 和结果，`WAIT_MORE` flow 持有旧 snapshot。
- `enable=0` 先阻止新 arm，再 `synchronize_net()`，随后完成所有 active context 中的 DPI consumer，以 `DPI_DISABLED` 写入 terminal 并清 DPI owner bit；其他 consumer 可继续持有 context。
- module exit 先注销/停用 hook，再完成全部 consumer、唤醒 event waiter，最后释放 ruleset、crypto、cache 和设备。
- `update_magic` 只能使部分 path 状态重学，不能恢复已经错过的 L7 元数据，也不能被描述为 DPI 重分类。
- 已安装硬件 offload 的撤销语义因厂商分支而异。MVP 不自动在 rule commit 时失效软件/硬件 flow。
- 若未来只更新 policy 而希望复用已缓存 app result，需要把 classifier generation 和 policy generation 分离，并单独设计 path/HWNAT 失效；不属于 MVP。

## 17. 分阶段实施

### M0：Parser 解耦与回归基线

- 先完成 NATCAP/shared conntrack extension 的 `app_id` 尾增验证；失败的 build 明确不支持 `CONFIG_NATFLOW_DPI`。
- 建立 parser corpus 和当前 URL/Host ACL 行为测试。
- 抽出 read-only packet view、hostname normalize、HTTP/TLS/QUIC parser API 和通用 detector dispatcher。
- legacy URL logger 改为消费共享 features，保持现有设备/CSV/sysctl ABI。
- 把 ACL 与 URL 日志对象分配解耦并统一 owner/错误出口；新增 DPI state transition 使用 cmpxchg owner claim，DPI gate 则按已接受风险沿用 `nf->status` helper，不迁移整字全部 writer，也不增加 path 侧 repair。
- 此阶段不新增 DPI 对外 ABI，不宣称已经实现应用分类。

### M1：Audit-only detector MVP

- 增加 `CONFIG_NATFLOW_DPI`、`app_id` flow result、`NF_FF_DPI_USE` owner bit 和扩展后的 `NF_FF_BUSY_USE` path 检查。
- 增加跨 CPU 的全局有界 flow context/reassembly 和过期 drain。
- 实现 detector dispatcher、HTTP/TLS/QUIC 共享 detector，以及首批 A 级非 HTTP/TLS/QUIC detector。首批建议从 DNS、STUN、SSH、BitTorrent handshake/DHT、WireGuard 中选择；OpenVPN 只有在目标样本能证明低误判时进入 M1，否则留到 M2/M4。
- 实现 app/domain/proto snapshot、exact/suffix/proto matcher、transactional ctl。
- 实现版本化 event queue、`proto_id`/`detector_id`、计数器和 reason。
- 在 M1 退出前删除所有临时重复 coordinator/cache/parse adapter，URL logger、Host ACL 和 DPI 必须已经消费同一次 parser 结果。
- 默认关闭、unknown/error fail-open；此阶段不执行 app ACL/QoS。
- gate、terminal 和 path/HWNAT 不变量必须在本阶段一次完成。

### M2：生产 shadow 与兼容收尾

- 持续断言运行时只有一个 L7 coordinator、flow cache 和 parser 调用点，不再把架构清理留到本阶段。
- 对比新旧 URL 记录、Host ACL 决策和 CPU/memory 指标。
- 生产环境先运行 audit shadow，统计 detector coverage、protocol-only rate、app hit、unknown reason、false positive sample、cache/ring loss 和 p99 hook latency。
- 按数据逐步加入 B 级 detector，例如 FTP/SMTP/POP3/IMAP/SIP/RTSP/MQTT/Redis/MySQL/PostgreSQL/RDP/SMB。每个新 detector 必须带 corpus 和可关闭开关。

### M3：可选 App policy

- 先加入 audit-only policy decision，再按明确优先级开放 drop/reset。
- 最后接入“仅填空”的 app QoS adapter。
- 每种 enforce action 都要有单独回滚开关和 fast/HWNAT 验证。

### M4：数据驱动的扩展评审

只有 M2/M3 数据证明收益后，才分别评审：

- HTTP path prefix 或少量固定 header 特征。
- 有界 payload exact signature。
- JA4 等客户端指纹。
- 用户态 DNS correlation。
- QUIC v2 或更多 frame/record 变体。
- C 级复杂 detector，例如 OpenVPN/SoftEther/Kerberos/RTP/游戏私有协议。

每项必须单独给出证据等级、false-positive 模型、规则/候选上限、cache owner、ABI 变化和性能预算。它们不是当前路线的既定承诺。

## 18. 验证矩阵

### 18.1 构建与兼容

- base、URLLOGGER、PATH、DPI、PATH+DPI、URLLOGGER+DPI、PATH+URLLOGGER+DPI。
- 上述关键组合追加 `NO_DEBUG=1`。
- 代表性旧/新内核；有/无所需 QUIC crypto；NATCAP 共享扩展组合。
- 编译期检查 result size、UAPI offset、conntrack extension 容量和 `NF_FF_DPI_USE_BIT` 冲突。

### 18.2 Parser corpus

- HTTP 单包、Host/URI 跨包、非法 method/header/Host、最大 hostname、non-linear skb。
- TLS 单包、连续跨包、重传、gap/乱序、多 record、无 SNI、ECH、非法长度。
- QUIC v1 正常、CRYPTO 连续/缺口、coalesced、Retry、v2、密钥/AEAD 不可用、畸形 varint。
- DNS/STUN/SSH/BitTorrent/WireGuard 首批 detector 的正向、反向、server-first、畸形长度、重传、gap、端口伪装和相似协议负样本。
- B/C 级 detector 合并前必须追加专属 corpus，不允许只用线上抓包手工验证。
- 对每个输入断言 parse rc、protocol、evidence、reason、owner 和 buffer release。

### 18.3 网络路径

- IPv4/IPv6、route/bridge、PPPoE、VLAN、SNAT/DNAT。
- IPv6 extension headers、IPv4/IPv6 fragment、GSO/GRO、non-linear skb。
- original/reply、跨 CPU/RPS、TCP Fast Open、FIN/RST、server-first flow。
- `CONFIG_NATFLOW_URLLOGGER_LOCAL_IN` 回归和 DPI local bypass。

### 18.4 Gate 与策略

- 预置同 tuple 的旧 fastnat node，验证新 TCP SYN/TFO 和已启用 UDP detector candidate 必定回 slow path 并 arm；覆盖 IPv4/IPv6 和 collision slot。
- terminal 前软件 fastnat 和所有 HWNAT/WED 分支都不能建项。
- 每个 normal/error/timeout/disable/exit 分支最终都写入 terminal 并清 DPI owner bit。
- app drop 后不能因清 DPI owner bit 而建立 fast entry。
- URL owner bit 和 DPI owner bit 独立，任一 consumer 完成不得结束另一 consumer；最后 consumer 才释放 shared context。
- 既有 QoS 优先；未来 app QoS 只填 `qos_id==0`。

### 18.5 资源与并发

- context、prefix bytes、rule memory、collision、suffix probe 和 event ring 全部打满。
- fault injection 覆盖 context/buffer/event/ruleset allocation 失败。
- 同一 conntrack 多 CPU 并发、ruleset commit 与 parse 并发、enable/disable 与 parse 并发、module exit drain。
- 可用时运行 KASAN、KCSAN、lockdep、SLUB debug；特别验证当前 conntrack ext realloc 风险。

### 18.6 ABI

- transaction commit/abort、close abort、base generation 冲突、重复/非法规则、超长行。
- IPv4/IPv6 event encode/decode、version/length/endian/TLV skip。
- blocking/nonblocking/poll、第二 reader、short buffer 不消费、overflow/lost counter、退出 EOF。
- legacy `/dev/urllogger_queue` 字节级格式和 Host ACL 四种 action 回归。

### 18.7 性能门槛

至少比较 DPI off、protocol-only、domain rules 满载、proto rules 满载、首批 detector 全开五组：

- 单核和多核 pps/吞吐。
- hook 平均、p95、p99 latency。
- 每 flow allocation、cache hit/loss、rule probe 和 event drop。
- SYN flood、无 SNI TLS、畸形 QUIC、UDP candidate flood、端口伪装二进制负样本等最坏输入下 CPU/memory 上界。
- fast path 建项时间和 HWNAT/WED 成功率。

具体允许回归百分比必须在目标硬件基线完成后由维护者确认，不能在没有测量时宣称“无性能影响”。

## 19. 实施前确认项

以下问题不影响本文的总体架构，但会阻止代码合并，必须在实现任务中逐项确认：

1. `nf->status` bit 21 在 NATCAP/厂商分支中确实空闲，且 `natflow_t` 追加 `app_id` 后满足所有共享 conntrack 扩展布局；这是 M0 前置门槛，不满足的 build 不支持 DPI。
2. 下游硬件 offload 是否存在早于当前 FORWARD arm、绕过扩展后的 `NF_FF_BUSY_USE`，或按残留 tuple 吞掉新 SYN/UDP detector candidate 的 entry programming 点。
3. DPI 必须支持的最低内核/API 集，以及 RCU ref、poll、IPv6 extension helper 和 per-CPU crypto 的兼容封装。
4. 目标设备可接受的 active context、prefix、snapshot 和 ring 内存预算。
5. app/category/rule/proto/detector ID 的管理 owner，以及生产需要的最大 app/domain/proto 规模。
6. 是否存在仓库外的 URL queue/Host ACL consumer，以及它们的严格兼容要求。
7. 应用 policy 和现有 tuple QoS 的业务优先级是否接受“existing QoS wins”。
8. 当前模块是 init_net/global 配置模型；若要求 per-netns，必须另立架构任务，不能只给 DPI 局部加 namespace。

## 20. MVP 验收标准

只有同时满足以下条件，M1 才算完成：

- 共享 L7 detector/parser 只解析一次，URL logger、Host ACL 和 DPI 无重复解析路径。
- 所有 active state 正常持有 `NF_FF_DPI_USE`，所有 terminal/error/disable/exit 路径可证明写入 terminal 并清 owner bit；并发丢 bit 作为已接受风险单独计数和压测。
- terminal event 可区分 `app_id=0`、protocol-only、matched 和 error，并带 generation/reason/`proto_id`/`detector_id`；flow 常驻结果只保留 `app_id`。
- rule commit 原子，domain/proto 查找有界，事件有版本/长度，资源有 hard limit 和可观测 lost/reason/detector counter。
- 现有 URL logger/Host ACL/user/auth/QoS/path ABI 和默认关闭行为通过回归。
- 构建矩阵、parser/network/gate/concurrency/ABI 测试完成，目标硬件性能数据可接受。
- README、SYSTEM_DESIGN_SPEC、docs/agent/MEMORY/ROADMAP 与最终源码同步；任何无法验证的旧内核、NATCAP 或 HWNAT 组合被明确记录。
