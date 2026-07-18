# Natflow 统一 L7 与 DPI 设计

状态：Draft v7，实施中

更新时间：2026-07-18

实现状态：本文描述目标架构。当前源码使用 `NF_FF_L7_USE` 和 `NF_FF_DPI_USE` 协调 shared L7 与 `natflow_t` 尾部的有界 DPI 瞬态上下文；`app_id` 仍是唯一分类结果。packet view 携带 conntrack direction、当前 packet `sport/dport` 和方向感知的 client/server port。reply 包只准入 DPI packet consumer，URL、Host ACL、HTTP/TLS/QUIC host 和 DNS QNAME domain 保持 original-only；DNS response 与 payload detector 可作为 reply 协议证据。

## 1. 总体结论

Natflow 不应该把现有 `urllogger` 简单扩大成一个大而全的 DPI 引擎，也不应该把所有已有 URL/Host ACL 接口直接改名为 DPI。更合适的统一模型是：

```text
natflow_l7 core
    |
    +-- legacy URL/HostACL consumer
    |       exposes /dev/natflow_urllogger_queue
    |       keeps /dev/hostacl_ctl
    |       keeps /proc/sys/urllogger_store/*
    |
    +-- DPI classifier consumer
            adds /dev/natflow_dpi_ctl
            adds /dev/natflow_dpi_queue
            writes only app_id as resident flow result
```

内部统一命名为 `L7`，不是 `urllogger` 或 `dpi`。理由：

1. 现有能力不只是日志，还包括 HTTP/TLS/QUIC 元数据提取、Host ACL、reset/redirect/drop 动作和 URL store。
2. 新 DPI 不只是域名匹配，还要支持少量有界 protocol detector。
3. `hostacl` 和 `urllogger_store` 已经是用户可见 ABI，URL queue 当前已显式统一到 `natflow_urllogger_queue` 命名。
4. 共享部分是 L7 packet view、bounded prefix、parser、feature fan-out 和 owner 生命周期；URL logger 和 DPI 只是 consumer。

因此，本设计保留 `DPI_DESIGN.md` 文件名作为历史任务入口，但实现时目标文件应逐步拆成：

| 文件 | 角色 |
| --- | --- |
| `natflow_l7.c/.h` | 共享 packet view、bounded prefix、HTTP/TLS/QUIC parser、hostname normalize、QUIC crypto/cache、consumer fan-out。 |
| `natflow_l7_url.c/.h` 或保留拆薄后的 `natflow_urllogger.c/.h` | legacy URL consumer，消费 L7 packet view，保留 URL store、二进制 URL event 输出、Host ACL、302/RST 动作和 `urllogger_store` sysctl 资源。 |
| `natflow_dpi.c/.h` | DPI enable/disable、rule snapshot、classifier、event ring、`app_id` 发布和 `/dev/natflow_dpi_*` ABI。 |
| `natflow_l7_det_*.c` | 编译期内置的小型 detector，按协议逐个引入。 |

## 2. 当前源码事实

统一设计必须从当前源码出发，而不是从目标接口假设出发：

- 当前 `NF_FF_BUSY_USE` 已包含 `NF_FF_USER_USE | NF_FF_L7_USE | NF_FF_DPI_USE`。DPI packet context 有效时设置 `NF_FF_DPI_USE`，终态时先清 DPI owner，再由 L7 写 packet done。
- 当前 `natflow_t` 尾部包含常驻分类结果 `app_id`，以及仅在 `NF_FF_DPI_USE` 有效的 8 字节瞬态 context：双向 packet/byte counter、detector mask 和保留字节。
- 当前 fast path 在建软件 fastnat 或硬件 offload 前检查 `nf->status & NF_FF_BUSY_USE`；DPI 必须沿用这个 mask 阻止首段流量被提前接管。
- 当前 shared L7 hook 的生命周期由 `natflow_l7_init()/exit()` 触发，URL/DPI hook ops、内核 hook 签名兼容包装、PPPoE normalize/restore、基础 conntrack 过滤、packet view 构造、`NATFLOW_L7_CONSUMER_URL/DPI_DOMAIN/DPI_PACKET` mask 和 packet dispatcher 已由 `natflow_l7.c` 持有：统一注册 IPv4、IPv6 和 bridge `FORWARD` hook，优先级 `NF_IP_PRI_FILTER + 5`。当前 active mask 按 `urllogger_store/enable` 发布 URL consumer，按 DPI domain/proto 规则分别发布 DPI domain 与 DPI packet consumer；入口先用 `natflow_session_in()` 统一确保 URL/DPI 共享同一个 `natflow_t.status`，再扣除对应 done bit 并分发。底层数据面中，L7 dispatcher 已直接处理 TCP HTTP/TLS producer、UDP/443 QUIC producer 和 DPI packet-view consumer，并通过 `natflow_urllogger_consume_host_view()` 或 DPI-only host classifier fan-out。HTTP/TLS/QUIC host fan-out 已通过 `natflow_l7_host_view` 固化 source、host、URI 和 HTTP method 输入 contract，legacy URL consumer 只在本地映射 URL flags、DPI event source 和 ACL 回复策略。DPI packet-view consumer 的 L4/payload 输入由 L7 producer 统一填充，包含 payload 总长度和已线性化的有界前缀长度。
- 当前 `urllogger_store_enable=0` 时 URL consumer 不加入 active mask，因此 URL event 和 Host ACL 不会执行；若 DPI enabled 且存在 domain rule，DPI host consumer 仍可复用同一 L7 hook 解析 HTTP/TLS/QUIC host。
- 当前 HTTP Host/URI、TLS SNI、QUIC v1 Initial SNI parser API、TCP HTTP/TLS packet producer、TCP TLS SNI cache、QUIC cache、QUIC crypto ctx 和 QUIC UDP packet producer 已迁移到 `natflow_l7` 生命周期；legacy URL consumer 仍持有 URL record 分配、Host ACL、队列输出和 ACL 回复策略。
- 当前 TCP TLS cache 和 QUIC cache 都按 CPU 存储。RPS/RFS 或调度变化导致同一 flow 后续包落到其他 CPU 时，可能找不到之前 prefix。
- 当前 Host ACL 已不依赖 URL record 分配成功；URL 日志对象分配失败时不会生成 URL event，但会尽量基于同一 host normalize 规则执行 ACL。
- 当前 `nf->status` 的 `simple_set_bit()` 和 `simple_clear_bit()` 是非原子 read-modify-write。维护者接受这个已知风险，DPI 不引入 path 侧 repair，也不在本设计中迁移整个状态字。
- 当前 `natflow_session_init()` 使用共享 conntrack extension 尾部布局，并依赖脆弱的 `krealloc()`/offset 假设；源码已增加 layout guard，但后续 DPI/L7 hook 注册仍必须在 guard 成功后执行。

## 3. 目标与非目标

### 3.1 目标

- 把 URL logger、Host ACL 和 DPI 统一到一套 L7 packet view、bounded prefix、parser 和 consumer 生命周期上。
- 保持当前 URL logger、Host ACL、sysctl、二进制事件输出和默认行为兼容。
- 为 DPI 增加独立控制面、事件面和 `app_id` flow result。
- 对 forwarded IPv4/IPv6 TCP/UDP 新连接做有界首段观察。
- 复用 HTTP Host、TLS SNI、QUIC v1 Initial SNI，并允许逐步加入少量高确定性非 HTTP/TLS/QUIC detector。
- 在任何 terminal 结果后尽快释放 flow 给软件或硬件 fast path。
- 所有解析、规则查找、缓存和事件都有硬上限，资源不足时 fail-open 并计数。

### 3.2 非目标

- 不做 nDPI 全量内核移植。
- 不做 WAF、IDS/IPS、反规避网关、完整 TCP 重组、全流 payload 扫描或大签名库。
- 不支持 PCRE、用户态字节码、任意 offset payload contains 或线性扫描全规则。
- 不承诺穿透 TLS ECH、HTTP/3 加密头、VPN、代理或自定义加密协议。
- 不在内核保存应用名称、长描述、报表、机器学习模型或在线学习状态。
- 不默认引入用户态 daemon。未来用户态工具可以负责编译规则、下发事务和消费事件，但内核模块必须能独立加载并默认关闭 DPI。

### 3.3 安全定位

MVP 是审计和机会性分类能力。`UNKNOWN`、`ERROR`、预算耗尽、不可见加密元数据和 unsupported variant 默认放行。现有 Host ACL 行为保持原样。未来应用级阻断必须等 shadow 数据证明误判可控后单独开放，且不能让 DPI 的 accept 覆盖认证、Host ACL、conntrack drop 或其他既有拒绝结果。

## 4. 命名与兼容策略

### 4.1 内部命名

- 共享代码使用 `natflow_l7_*` 前缀。
- 共享 flow context 使用 `natflow_l7_flow_ctx`。
- URL/Host ACL consumer 使用 `NATFLOW_L7_CONSUMER_URL`。
- DPI domain consumer 使用 `NATFLOW_L7_CONSUMER_DPI_DOMAIN`；DPI packet consumer 使用 `NATFLOW_L7_CONSUMER_DPI_PACKET`；`NATFLOW_L7_CONSUMER_DPI` 是二者组合。
- HTTP/TLS/QUIC parser 输出统一 `natflow_l7_features`。

### 4.2 外部兼容

必须保留以下外部接口，除非另立兼容破坏决策：

| ABI | 兼容要求 |
| --- | --- |
| `/dev/natflow_urllogger_queue` | 保持版本化二进制事件头、payload、老化/合并、小 buffer 行为和 `clear` 命令。 |
| `/dev/hostacl_ctl` | 保持命令、32 个 ACL 槽位、ipset 命名和四种 action。 |
| `/proc/sys/urllogger_store/*` | 保持路径、字段名和语义。尤其 `enable=0` 表示 URL event 和 Host ACL 都不执行。 |
| `CONFIG_NATFLOW_URLLOGGER` | 继续表示启用 legacy URL logger、Host ACL 和 sysctl。 |
| `NF_FF_L7_URL_DONE` / `NF_FF_L7_DPI_DOMAIN_DONE` / `NF_FF_L7_DPI_PACKET_DONE` | URL、DPI domain、DPI packet 独立终态标记，保存在 `natflow_t.status`；任一终态不关闭其他仍 pending 的 consumer。 |

共享 hook、parser 和 dispatcher 必须使用 `natflow_l7_*` 命名；只有 URL event、Host ACL 和兼容资源 consumer 使用 `natflow_urllogger_*` 命名。用户可见 ABI 以当前 `/dev/natflow_urllogger_queue`、`/dev/hostacl_ctl` 和 `urllogger_store` 为准。

## 5. 统一架构

### 5.1 组件

```text
netfilter hook
    |
    v
natflow_l7_core
    - build read-only packet view
    - select active consumers
    - arm owner bits
    - merge bounded prefix if needed
    - run parser/detector once
    - fan-out features to consumers
    |
    +--> URL consumer
    |       - legacy URL record
    |       - Host ACL match/action
    |       - /dev/natflow_urllogger_queue
    |
    +--> DPI consumer
            - rule snapshot lookup
            - app_id write
            - /dev/natflow_dpi_queue
```

parser/detector 只产出 feature 和 terminal reason，不直接写 URL queue、不执行 ACL、不写 `app_id`、不修改 skb。consumer 再根据 feature 执行自己的输出或策略。

### 5.2 数据流

```text
new selected flow
        |
        v
active consumer mask = URL? | DPI?
        |
        v
set required owner bits in nf->status
        |
        v
read-only packet view
        |
        v
bounded parser/detector
        |
        +-- NEED_MORE -> context registry + bounded prefix
        |
        +-- FEATURE / TERMINAL
                    |
                    +-- URL consumer: URL event + Host ACL
                    |
                    +-- DPI consumer: ruleset -> app_id/event
                    |
                    v
             clear completed owner bits
                    |
                    v
             fast path may proceed
```

共享跨包 prefix/cache 的 lifetime 由解析自然终态和其自身资源上限决定。URL 完成不能提前释放 DPI 仍在等待的 prefix。运行时配置变化只控制后续数据包看到的 active consumer，不枚举、不强制终止、也不清理已经设置 `NF_FF_L7_USE` 的连接状态。

## 6. 编译与初始化

### 6.1 编译宏

- `CONFIG_NATFLOW_URLLOGGER`：启用 legacy URL consumer、Host ACL、`/dev/natflow_urllogger_queue`、`/dev/hostacl_ctl` 和 `urllogger_store` sysctl。
- `CONFIG_NATFLOW_DPI`：启用 DPI consumer、`/dev/natflow_dpi_ctl`、`/dev/natflow_dpi_queue`、DPI owner bit 和 `app_id` result。
- L7 core 在 `CONFIG_NATFLOW_URLLOGGER` 或 `CONFIG_NATFLOW_DPI` 任一启用时编译。
- `CONFIG_NATFLOW_DPI` 不强制依赖 `CONFIG_NATFLOW_PATH`。没有 path 时仍可审计，但 fast-path gate 不产生加速协作效果。

### 6.2 初始化顺序

实现 DPI 前必须调整初始化前置条件：

1. `natflow_probe_ct_ext()` 已从 path 私有初始化移动到 common/main 初始化。
2. probe 已改为可返回错误，供 DPI 判断共享 conntrack extension 是否可用。
3. layout guard 已在注册 path 或 shared L7 hook 前完成；后续 L7/DPI hook 必须继续遵守该顺序。
4. `natflow_l7` 是 shared L7 hook lifecycle owner，并持有 hook ops、签名兼容包装、PPPoE normalize/restore、packet view 构造和 QUIC crypto capability；内部入口统一使用 `natflow_l7_hook*` 命名。
5. URL consumer 初始化 legacy 设备和 sysctl，再由 L7 core 注册 hook，避免 hook 进入未初始化的 URL 资源。
6. DPI consumer 默认 `enable=0`，只初始化控制设备、规则和事件状态；数据面由 L7 shared hook 在存在 domain/proto 规则时分别调度 DPI domain/packet consumer，`natflow_dpi_consume_packet_view()` 返回本次可终态的子 mask。

退出顺序反向执行：先注销 hook，阻止新包进入 L7，再释放模块持有的规则、cache、crypto 和设备资源。模块退出不枚举 conntrack，也不要求为已经标记的连接补写 terminal 或清 owner bit。

## 7. Flow 结果与 fast-path gate

### 7.1 Owner bit

shared L7 与 DPI busy bits：

```c
#define NF_FF_L7_USE_BIT 19
#define NF_FF_L7_USE (1 << NF_FF_L7_USE_BIT)
#define NF_FF_DPI_USE_BIT 21
#define NF_FF_DPI_USE (1 << NF_FF_DPI_USE_BIT)
#define NF_FF_L7_URL_DONE_BIT 22
#define NF_FF_L7_URL_DONE (1 << NF_FF_L7_URL_DONE_BIT)
#define NF_FF_L7_DPI_DOMAIN_DONE_BIT 23
#define NF_FF_L7_DPI_DOMAIN_DONE (1 << NF_FF_L7_DPI_DOMAIN_DONE_BIT)
#define NF_FF_L7_DPI_PACKET_DONE_BIT 24
#define NF_FF_L7_DPI_PACKET_DONE (1 << NF_FF_L7_DPI_PACKET_DONE_BIT)
#define NF_FF_BUSY_USE (NF_FF_USER_USE | NF_FF_L7_USE | NF_FF_DPI_USE)
```

要求：

- `NF_FF_L7_USE_BIT` 复用原 URL logger fast-path pause 位，语义改为 shared HTTP/TLS/QUIC L7 parser 正在等待 terminal。
- `NF_FF_DPI_USE_BIT` 必须在当前 `nf->status` bit map 中空闲。
- 编译期和 init 时都要检查该 bit 未与既有 bit 冲突。
- 所有 fast path 建表和硬件 offload 入口必须继续用 `NF_FF_BUSY_USE` 判断。
- shared L7 parser 在 selected flow arm 成功后设置 `NF_FF_L7_USE`；DPI packet 需要等待方向或后续 packet 时初始化 `natflow_t` 瞬态字段并设置 `NF_FF_DPI_USE`，terminal 时先清 DPI owner，再写 packet done。
- 继续接受 `nf->status` 非原子 writer 风险，不增加 path 侧 repair，但必须保留 lost-owner/early-fastpath 计数和并发压测。

### 7.2 `natflow_t` 尾部结果

MVP 只在 `natflow_t` 尾部追加 32 位应用结果：

```c
struct natflow_dpi_flow {
	u32 app_id;
};
```

约束：

- `app_id=0` 永久表示 unknown、未命中、未分类或尚无结果。
- 非 0 表示当前连接由 DPI ruleset 识别出应用。
- `app_id` 是唯一常驻分类结果。
- packet/byte counter 和 detector mask 作为 8 字节瞬态 context 保存在 `natflow_t`；`rule_id`、generation、proto、evidence、confidence、reason 和 policy action 不进入常驻分类结果。
- 不在 flow 中保存 host、URI、payload、证书、名称字符串或指针。
- 不使用 `skb->mark` 或 `ct->mark` 保存 DPI 结果，避免覆盖 QoS、tc 和用户态既有语义。
- writer 在 matched 结果时先写 `app_id`，DPI packet terminal 先清 `NF_FF_DPI_USE` 和瞬态字段，再由 L7 写 packet done；active consumer 全部 done 后清 `NF_FF_L7_USE` 并设置 L7_SKIP hint。

追加字段前必须验证 `nat_key_t.len`、`natflow_off`、`NATCAP_MAX_OFF`、`__ALIGN_64BITS` 和 NATCAP 组合布局。验证不通过时，`CONFIG_NATFLOW_DPI` build 必须拒绝启用，不能静默切换到长期 side-table 模型。

## 8. Packet view 与 parser contract

### 8.1 Read-only packet view

L7 core 先构造统一 packet view：

```c
struct natflow_l7_packet_view {
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

实现必须满足：

- 统一处理 IPv4 IHL、IPv6 extension header、TCP data offset、UDP length、PPPoE、bridge、VLAN 和 non-linear skb。
- 使用 `pskb_may_pull()`、`skb_header_pointer()` 或 `skb_copy_bits()` 证明数据可读。
- 任何 pull/copy 后重新获取 `iph`、`ip6h`、`l4` 和 payload 指针。
- parser 不调用 `skb_try_make_writable()`，不临时修改 `skb->protocol`、`network_header` 或 data。
- reset/redirect/drop 需要修改 skb 时，由 URL consumer 的 action path 独立处理。
- IPv4/IPv6 fragment 在未确认 defrag 完成时终止为 `FRAGMENT`。
- IPv6 extension walk 必须有 header 数和字节数上限。

### 8.2 Feature model

parser/detector 输出统一 feature：

| feature | 来源 | 说明 |
| --- | --- | --- |
| `HTTP_HOST` | HTTP/1 request | host normalize 后用于 URL、Host ACL、domain rules。 |
| `HTTP_URI` | HTTP/1 request | 只给 legacy URL logger；MVP DPI 不按 path 分类。 |
| `TLS_SNI` | TLS ClientHello | 普通可见 SNI。 |
| `TLS_OUTER_SNI` | TLS ClientHello + ECH | 只表示 outer SNI，event 必须保留 evidence。 |
| `QUIC_SNI` | QUIC v1 Initial | 从 CRYPTO 中 ClientHello 提取。 |
| `DNS_QNAME` | DNS detector | original direction TCP/UDP 53 query 第一问 QNAME，normalize 后进入 domain rules。 |
| `PROTO` | protocol detector | 输出 `proto_id`、`detector_id`、confidence。 |

hostname normalize 复用现有严格规则：ASCII 小写、去 root dot、总长 1..253、单 label 1..63、拒绝空 label、控制字符、空白、逗号、非 DNS 字节、label 首尾 `-`。HTTP Host 可允许并剥离合法十进制 `:port`；TLS/QUIC SNI 不接受端口。

### 8.3 Parser/detector API

```c
enum natflow_l7_parse_rc {
	NATFLOW_L7_SKIP,
	NATFLOW_L7_FEATURE,
	NATFLOW_L7_NEED_MORE,
	NATFLOW_L7_UNSUPPORTED,
	NATFLOW_L7_MALFORMED,
	NATFLOW_L7_NO_RESOURCE,
};

struct natflow_l7_parser_ops {
	u16 parser_id;
	u8 direction_mode;
	u8 packet_budget[2];
	u16 byte_budget[2];
	bool (*eligible)(const struct natflow_l7_packet_view *view);
	enum natflow_l7_parse_rc (*parse)(struct natflow_l7_flow_ctx *ctx,
	                                  const struct natflow_l7_packet_view *view,
	                                  struct natflow_l7_features *features);
};
```

约束：

- 每个 parser/detector 声明方向、最大 payload packet、最大 bytes、最大循环次数和最大状态大小。
- 不支持运行时 plugin、用户态 bytecode 或任意函数指针注册 ABI。
- detector 是编译期静态实现，由 ruleset 或 enable mask 控制是否参与。
- parser/detector 不能直接执行 policy，只返回 feature、reason 和 confidence。

### 8.4 Direction contract

方向准入和 detector 终态是两个独立概念。packet view 必须携带 conntrack direction；original/reply 都使用 original tuple 作为连接身份，但 detector 通过方向感知的 client/server port helper 解释服务端口，不能把当前 packet 的 `dport` 永久等同于服务端口。

```c
enum natflow_dpi_direction_mode {
	NATFLOW_DPI_DIR_ORIGINAL_ONLY,
	NATFLOW_DPI_DIR_REPLY_ONLY,
	NATFLOW_DPI_DIR_EITHER,
	NATFLOW_DPI_DIR_BOTH,
};
```

| mode | 准入与终态语义 | context 要求 |
| --- | --- | --- |
| `ORIGINAL_ONLY` | 只消费 original；该方向确认、明确不匹配或预算耗尽后 detector 终态，不等待 reply。 | 单包可无 context；跨包时按需分配。 |
| `REPLY_ONLY` | original 不消耗 detector 预算；等待 reply，直到确认或资源/时间预算耗尽。 | 必须有最小等待状态。 |
| `EITHER` | 两个方向都可提供充分证据；任一方向确认即成功终态，一个方向未命中不能关闭另一个方向。 | 首个方向未确认后需要最小方向/预算状态。 |
| `BOTH` | 必须满足 detector 定义的双向关联条件；不能把两个方向字节简单拼接后匹配。 | 必须保存两个方向的有界状态和关联阶段。 |

首批方向合同：

| detector/feature | mode | 证据 |
| --- | --- | --- |
| DNS QNAME domain | `ORIGINAL_ONLY` | TCP/UDP 53 标准 query 第一问 QNAME。 |
| DNS protocol | `EITHER` | original query 或 reply response 的合法 DNS header/question 结构。 |
| SSH | `EITHER` | 任一方向 `SSH-<version>-` identification string。 |
| WireGuard | `EITHER` | 任一方向合法 message type、reserved bytes 和对应长度。 |
| STUN/TURN | `EITHER` | 任一方向合法 header、length、magic cookie 和 method。 |
| BitTorrent | `EITHER` | 任一方向 TCP handshake 或 UDP uTP/DHT 子集证据。 |
| 后续 server-first detector | `REPLY_ONLY` | 仅服务端应答具有稳定证据。 |
| 后续挑战应答 detector | `BOTH` | request/response 阶段和字段能够有界关联。 |

方向模式是编译期 detector 正确性元数据，不作为首期规则参数开放。ruleset 只决定启用哪些 detector 以及命中后映射的 `app_id`，不能覆盖 detector 的方向语义。URL logger、Host ACL、HTTP request Host、TLS ClientHello SNI、QUIC client Initial SNI 和 DNS QNAME domain 继续保持 original-only；reply 首期只准入 DPI packet consumer。

## 9. Context 与多 consumer 生命周期

### 9.1 Context key

方向预算状态直接使用 `natflow_t` 尾部的 8 字节有界 context，不分配 parser cache，也不引入全局 conntrack registry。纯单包 `ORIGINAL_ONLY` detector 可以不置 `NF_FF_DPI_USE`；需要等待后续方向或 packet 的 detector 才发布 context owner。

若后续确实引入 context，其可保存：

- active consumer mask。
- owner state。
- original/reply packet 与 byte counter。
- TCP 连续 prefix 和 sequence。
- UDP/QUIC CRYPTO 连续 prefix。
- 观察到的 DPI ruleset generation，仅用于审计，不 pin retired ruleset。
- 已确认的 proto/features。
- 每个 consumer 的 done/reason。
- 每个 active detector 的 direction mode、seen/done direction、parse stage 和 terminal reason。

### 9.2 状态机

```text
NEW
 |
 v
ARMING -> ARMED -> PARSING -> WAIT_MORE
                       |          |
                       +----------+
                       |
                       +--> DONE_URL
                       +--> DONE_DPI
                       +--> DONE_ALL
```

要求：

- `ARMING` 只允许存在于当前 netfilter 临界期。
- context 字段初始化完成并保持 `NF_FF_L7_USE` 后，最后设置 `NF_FF_DPI_USE` 发布 owner。
- `PARSING` 使用单 flow owner claim，避免同一 conntrack 同时跑多个 parser owner。
- loser CPU 可以在短锁内合并连续 prefix；无法表达 gap/overlap 或预算耗尽时 deterministic terminal。
- 每个 consumer 独立 terminal。最后一个 consumer done 后释放 context。
- DPI packet consumer 在任一 detector 命中并写入 `app_id`，或全部 active detector 都终态后，才设置连接级 `NF_FF_L7_DPI_PACKET_DONE`。不能把“观察到一个方向”直接解释为整个 packet consumer 已完成。
- 若 URL/domain consumer 已写入非 0 `app_id`，DPI packet consumer 以 `APP_EXISTS` 终态，不再分配或保留方向 context；MVP 不为同一连接覆盖既有应用结果或继续输出第二分类。
- 仍有 `REPLY_ONLY`、`EITHER`、`BOTH` 或跨包 detector 等待数据时设置 `NF_FF_DPI_USE`。context 存续期间允许 `NF_FF_L7_USE | NF_FF_DPI_USE` 同时存在。
- FIN/RST、packet budget 和 byte budget 按 parser 自身状态机自然终止。初始 hard limit 是 original/reply 各 4 个 payload 包；不设置 wall-clock deadline。运行时 disable、rules commit、rules clear 和 module exit 不枚举或强制终止已经标记的连接。
- `ORIGINAL_ONLY` 不等待 reply；`EITHER`、`REPLY_ONLY` 和 `BOTH` 若所需方向始终没有 payload，可以保持 `NF_FF_DPI_USE` 到 conntrack 生命周期结束。这是取消时间约束后的明确取舍。

### 9.3 Enable/disable

控制面 mutex 串行化以下操作：

- legacy `urllogger_store/enable` 写入。
- DPI `enable=0|1`。
- DPI ruleset commit。
- event mode 更新。

DPI 状态保持为：

```text
DISABLED <-> ENABLED
```

- `enable=1` 发布 `ENABLED`，仅使后续尚未 L7 terminal 的候选连接可以进入 DPI consumer。
- `enable=0` 发布 `DISABLED`，使后续数据包不再把 DPI 纳入 active consumer；不扫描 conntrack，不完成既有 consumer，不补写 `DPI_DISABLED` terminal，也不清理已经设置的 L7 owner/done 状态。
- shared L7 资源仍可被 URL consumer 或已经进入解析流程的连接使用，不能因 DPI enable 变化而释放共享资源。
- 同值 enable 写幂等成功。

legacy `urllogger_store/enable` 必须从裸 `proc_douintvec` 迁移到 custom sysctl handler，保持路径和值不变，但在 L7 control mutex 下完成资源准备、发布和回滚。

## 10. 分类模型

### 10.1 三层结果

| 维度 | 含义 |
| --- | --- |
| `proto_id` | 由 parser/detector 确认的承载协议，例如 HTTP、TLS、QUIC、DNS、SSH。 |
| `app_id` | 用户定义应用 ID，由 domain/proto rule 映射得出；0 表示 unknown。 |
| `terminal reason` | 停止观察的原因，例如 `MATCHED`、`NO_RULE`、`ECH`、`BYTE_BUDGET`。 |

协议识别和应用识别分开。`proto_id=TLS, app_id=0` 是正常结果，不是解析错误。

### 10.2 Evidence 与 confidence

confidence 是稳定证据等级，不是概率：

| 等级 | 名称 | 含义 |
| --- | --- | --- |
| 0 | `NONE` | 没有应用证据。 |
| 1 | `HINT` | 端口等弱提示，不能单独产生可阻断 app。 |
| 2 | `CORRELATED` | DNS/IP 等间接关联，默认只审计。 |
| 3 | `DIRECT_SUFFIX` | Host/SNI/QNAME 命中 label-boundary suffix。 |
| 4 | `DIRECT_EXACT` | Host/SNI/QNAME 或固定字段 exact 命中。 |
| 5 | `DIRECT_PROTOCOL` | detector 通过握手、magic、长度和方向阶段确认协议。 |
| 6 | `DIRECT_APP` | detector 通过高质量应用特征确认具体应用。 |

事件必须带 evidence 类型，例如 `HTTP_HOST`、`TLS_SNI`、`TLS_OUTER_SNI`、`QUIC_SNI`、`DNS_QNAME`、`BINARY_MAGIC`、`COMMAND_TOKEN` 或 `HANDSHAKE_STAGE`。

### 10.3 Terminal reason

至少区分：

- 正常：`MATCHED`、`PROTO_ONLY`、`NO_RULE`、`NO_MATCH`、`NO_VISIBLE_METADATA`、`NO_DETECTOR`、`NOT_ELIGIBLE`、`REPLY_FIRST`、`FIN_RST`。
- 加密/协议：`ECH`、`UNSUPPORTED_VERSION`、`UNSUPPORTED_VARIANT`、`CRYPTO_UNAVAILABLE`。
- 报文：`FRAGMENT`、`IPV6_EXTENSION_LIMIT`、`TCP_GAP`、`PARSE_CONTENTION`、`MALFORMED`。
- 预算/资源：`PACKET_BUDGET`、`BYTE_BUDGET`、`TIME_BUDGET`、`CACHE_FULL`、`NO_MEMORY`、`RULE_LOOKUP_BUDGET`、`PARSER_BUDGET`。
- 管理：`DPI_DISABLED`、`MODULE_EXIT`。

reason 描述观察为什么结束，不直接表示连接动作。

## 11. DPI ruleset

### 11.1 MVP 规则

MVP 支持三类对象：

```text
app:    app_id -> category_id
domain: rule_id, app_id, kind(exact|suffix), source_mask, normalized_host
proto:  rule_id, app_id, proto_id, min_confidence, optional detector_mask
```

约束：

- `source_mask` 可限制 `HTTP_HOST`、`TLS_SNI`、`TLS_OUTER_SNI`、`QUIC_SNI`、后续 `DNS_QNAME`。
- `exact example.com` 只匹配 `example.com`。
- `suffix example.com` 匹配 apex 和 label 边界子域，例如 `a.example.com`，不得匹配 `badexample.com`。
- 不接受隐式 glob、contains、正则或 path/query 规则。
- `proto` 规则只在 detector 输出满足 `min_confidence` 时触发，不能由端口猜测单独触发。
- 相同 kind/host/source 产生二义性的规则在 commit 时拒绝。

HTTP URI 继续由 legacy URL logger 输出，但不进入 MVP DPI classifier。

### 11.2 Snapshot 生命周期

规则 snapshot 在进程上下文构造为不可变对象：

1. 每个控制 fd 在 private staging 中构造完整候选 ruleset。
2. `commit` 在 mutex 下校验 base generation、引用、冲突和 hard limit。
3. 构造完成后 `rcu_assign_pointer()` 一次发布。
4. classifier 在实际匹配时读取 active ruleset，并把该次匹配使用的 generation 写入 event。
5. 替换后的 global 引用在 grace period 后释放；MVP 不为已标记连接 pin retired ruleset。
6. 已设置 L7_SKIP 的终态连接不会因 commit 重新武装；仍在自然解析路径中的连接若再次分类，读取当时发布的 active ruleset，不保证继续使用 arm 时 generation。
7. accounting 覆盖 current、retired 和 staging snapshot。

## 12. 用户态 ABI

### 12.1 `/dev/natflow_dpi_ctl`

DPI 新增独立控制设备，不复用 legacy `MAX_IOCTL_LEN=256`。定义 `DPI_CTL_MAX_LINE=512`。

MVP 命令：

```text
enable=0
enable=1
status
stats
clear_stats
begin abi=1 base_gen=<gen>
app id=<app_id> category=<category_id>
domain id=<rule_id> app=<app_id> kind=exact|suffix source=http,tls,tls_outer,quic,dns host=<host>
proto id=<rule_id> app=<app_id> proto=<proto_name> min_confidence=direct_protocol
commit
abort
```

要求：

- 单行必须以 `\n` 结束。
- 所有字段必须有宽度限制和数值范围校验。
- 未知命令返回 `-EINVAL`，不能 silent success。
- `commit` 原子替换完整 ruleset，不对 live snapshot 原地 add/delete。
- read 输出必须包含 abi version、state、generation、ruleset bytes、event lost、reason counters 和 enable 状态；当前 context 内嵌于 conntrack，不做全局枚举或 active context 计数。

### 12.2 `/dev/natflow_dpi_queue`

DPI event 使用版本化二进制记录，不复用 `/dev/natflow_urllogger_queue` 的 URL event。

固定 header 必须包含：

| 字段 | 说明 |
| --- | --- |
| magic/version/header_len/record_len | ABI 识别和跳过能力。 |
| flags | 至少包含 TLV omitted 标志。 |
| timestamp | 事件时间。 |
| ruleset_generation | 命中时使用的规则版本。 |
| app_id/category_id/rule_id | 分类结果。 |
| proto_id/detector_id/evidence/confidence/reason | 解释字段。 |
| family/l4_proto/dir | 协议和方向。 |
| tuple | IPv4/IPv6 五元组。 |
| inspected_packets/bytes | 有界观察量。 |

record_len 初始上限 512。TLV 放不下时省略 TLV 并设置 omitted flag，不得截断 host 后伪装成完整值，也不得丢弃固定 header event。

小 buffer read 行为必须在 v1 就定义清楚。建议支持 per-open partial read 或返回 `-EINVAL` 并在 README/SYSTEM_DESIGN_SPEC 明确；不能沿用不明行为。

## 13. Legacy URL logger 与 Host ACL

legacy consumer 的目标是保持当前 URL/Host ACL 行为，不是顺手修语义：

- `/dev/natflow_urllogger_queue` 版本化二进制 URL event 格式保持不变。
- URL store 的 O(N) 合并逻辑只服务 legacy URL event，不被 DPI event 复用。
- `/dev/hostacl_ctl` 命令和读回格式保持不变。
- `host_acl_rule<id>_ipv4`、`host_acl_rule<id>_ipv6`、`host_acl_rule<id>_mac` ipset 命名保持不变。
- `/proc/sys/urllogger_store/enable=0` 时 URL event 和 Host ACL 都不执行，即使 DPI 已启用。
- `/proc/sys/urllogger_store/enable=1` 时 URL/HostACL consumer 加入 L7 active consumer mask。
- DPI `enable=1` 且存在 domain rule 时，DPI host consumer 加入 L7 active consumer mask，不要求 `urllogger_store/enable=1`。
- 已完成：Host ACL 决策不再依赖 URL record 分配成功；当前使用 `urllogger_acl_lookup` 最小 host 视图，HTTP/TLS/QUIC host fan-out 已通过 legacy URL consumer 公共 helper 统一处理 URL record、Host ACL、DPI classify 和现有 ACL 回复策略。
- reset/redirect/drop 动作仍由 legacy URL consumer 执行。DPI MVP 不提供 redirect。
- PPPoE/bridge 场景下必须保留 skb 状态恢复；目标 read-only packet view 应减少临时 pull/restore。

M0 若改变 HTTP 跨包识别、TLS cache 跨 CPU 行为或 enable 只影响新流等行为，必须明确标为行为变化并同步 README/SYSTEM_DESIGN_SPEC。

## 14. Detector 支持范围

### 14.1 MVP 输入矩阵

| 输入 | 行为 |
| --- | --- |
| HTTP/1 GET/POST/HEAD | 提取 Host；URI 仅给 legacy URL logger。 |
| HTTP header 跨连续 TCP 包 | 在 prefix budget 内拼接。 |
| HTTP keep-alive 后续 request | 不重新分类；MVP 是 per-connection 首段分类。 |
| TLS ClientHello | 确认 TLS，提取普通 SNI 或 ECH outer SNI。 |
| QUIC v1 Initial/UDP 443 | 解密第一个受支持 Initial，提取 CRYPTO 中 ClientHello SNI。 |
| ECH | 只使用可见 outer SNI；无可见 SNI 时 app unknown。 |
| 其他 TCP/UDP | 只交给显式启用 detector；没有 detector 时 `NO_DETECTOR`。 |

### 14.2 分级

| 等级 | 协议示例 | 进入条件 | 默认动作 |
| --- | --- | --- | --- |
| A | DNS query、SSH banner、WireGuard、STUN/TURN、BitTorrent TCP handshake 与 UDP uTP/DHT | 有固定 magic、版本/长度字段或稳定握手，少量包内可高置信确认。 | audit-only，可产生 `DIRECT_PROTOCOL`。 |
| B | FTP、SMTP、POP3、IMAP、SIP、RTSP、MQTT、RESP、MySQL、PostgreSQL、RDP、SMB | 明文命令或二进制握手明确，但可能依赖 server-first 或升级路径。 | shadow 后再考虑 policy。 |
| C | OpenVPN、SoftEther、Kerberos、RTP/RTCP、游戏/私有 TCP/UDP、代理/VPN 变体 | 需要多包方向模式、弱 magic、端口上下文或复杂状态。 | 默认 protocol-only 或 hint。 |
| D | 仅端口/IP、DNS 关联、统计特征、加密不可见流量 | 证据弱或容易受共享基础设施污染。 | 不单独产生可阻断 app。 |

禁止把 nDPI enum 直接复制为 Natflow UAPI。nDPI 只作为 detector 设计、域名规则包和 corpus 的参考来源。

### 14.3 阶段清单

| stage | 内容 |
| --- | --- |
| M1b | HTTP、TLS、QUIC parser 统一和 domain exact/suffix rules。 |
| M1c | DNS 标准 query、SSH banner、WireGuard 结构校验 protocol-only detector；端口只选择解析候选，不单独产生分类。 |
| M1d | STUN/TURN protocol-only、BitTorrent TCP handshake 与 UDP uTP/DHT 子集。 |
| M2 | MQTT、MySQL、PostgreSQL、SMB、FTP、SMTP、POP3、IMAP、SIP、RTSP、RESP、RDP 等 shadow 评估。 |
| M4 | OpenVPN、SoftEther、Kerberos、RTP/RTCP、私有游戏/聊天、代理/VPN、IP/证书/cache/JA4 等专项评审。 |

默认域名规则包由用户态从 nDPI `host_match[]`、生成域名表和维护者样本整理后事务提交。内核不内置品牌名称、长域名列表或中文展示名。IP-only/CDN/证书/cache 类证据默认只作为审计或 QoS hint，不能单独触发可阻断 `app_id`。

## 15. 资源预算

初始 hard limit：

| 资源 | 初始上限 | 耗尽行为 |
| --- | --- | --- |
| `natflow_t` DPI 分类结果 | 4 B logical/flow | session 初始化失败则不分类。 |
| `natflow_t` DPI 瞬态 context | 8 B/flow | 仅在 `NF_FF_DPI_USE` 时有效。 |
| 单流连续 prefix | 32 KiB | `BYTE_BUDGET`，fail-open。 |
| 全局 prefix bytes | 2 MiB | `CACHE_FULL`，fail-open。 |
| original/reply payload packets | 4 + 4 | `PACKET_BUDGET`。 |
| inspect wall clock | 不限制 | 不使用时间预算或定时扫描。 |
| detector dispatch | 4 个/packet | 不再尝试其他 detector。 |
| domain rules | 4096 条 | commit 返回 `-E2BIG`。 |
| proto rules | 512 条 | commit 返回 `-E2BIG`。 |
| app entries | 1024 条 | commit 返回 `-E2BIG`。 |
| 单 snapshot memory | 2 MiB | commit 返回 `-E2BIG`。 |
| current + retired ruleset bytes | 8 MiB | commit 返回 `-EBUSY`。 |
| retired generations | 4 代 | commit 返回 `-EBUSY`。 |
| suffix probes | 16 次/flow | `RULE_LOOKUP_BUDGET`。 |
| hash collision candidates | 8 个/bucket | commit 拒绝 snapshot。 |
| IPv6 extension walk | 8 headers / 256 B | `IPV6_EXTENSION_LIMIT`。 |
| HTTP header lines | 64 | `PARSER_BUDGET`。 |
| TLS records/extensions | 4 / 128 | `PARSER_BUDGET`。 |
| QUIC frames/ACK ranges | 64 / 32 | `PARSER_BUDGET`。 |
| event ring | 256 x 512 B | drop-new + lost counter。 |

数据面不得按攻击者声明长度做任意 `kmalloc()`/`krealloc()`。所有循环都必须能从上述 packet、byte、label、candidate、frame 或 header 上限推导出终止条件。malformed packet 只增加计数，日志必须 ratelimited。

## 16. 策略集成

MVP 只分类和审计，不执行 app policy。未来 policy 与 classification rule 分离：

- action 初始只考虑 `audit`、`drop`、`reset`、`qos=<existing group id>`。
- 不提供 app redirect，HTTP redirect 继续由 Host ACL 实现。
- 既有 user/auth/conntrack drop 优先，DPI accept 不能推翻。
- legacy Host ACL 非 record 动作优先，app policy 只能追加限制。
- app drop 必须设置 `IPS_NATFLOW_CT_DROP` 和 `IPS_NATFLOW_FF_STOP`，再写 terminal 并清 DPI bit。
- unknown/error 默认 accept，MVP 不提供 `unknown=drop`。
- app QoS 只能“填空”：若 `nf->qos_id != 0`，不覆盖既有 QoS；若为 0 且 policy 指向有效 QoS group，才写入 `qos_id` 并设置 `NF_FF_TOKEN_CTRL`。

M3 若需要缓存 policy generation，必须另立持久状态设计；MVP flow result 不预留 generation 字段。

## 17. 配置变化和既有连接

- DPI `enable=1` 只影响启用后看到的、尚未进入 L7 terminal 的候选连接。
- 已建立或已 offload 的连接不会重新出现 ClientHello、banner 或首段握手，不得宣称可重分类。
- 已设置 `IPS_NATFLOW_L7_HANDLED` 的连接不会因 ruleset commit 重新武装。
- WAIT_MORE flow 不 pin ruleset snapshot；若后续包仍进入分类路径，使用当时的 active ruleset。
- `update_magic` 只能使部分 path 状态重学，不能恢复已经错过的 L7 元数据。
- MVP 不在 rule commit 时自动失效软件 fastnat 或硬件 offload flow。
- runtime 关闭 URL consumer、关闭 DPI、rules clear 或 rules commit 都只改变后续 active consumer mask，不枚举、不退出、不清理已经标记的连接。
- 已标记连接可以继续自然终态，也可以一直保留原 owner/done 状态直到 conntrack 生命周期结束；这是接受的配置语义，不要求控制面主动回收。

## 18. 分阶段实施

### M0：统一 L7 core 与 legacy 回归

- 建立 parser corpus 和现有 URL/Host ACL 行为测试。
- 抽出 read-only packet view、hostname normalize、HTTP/TLS/QUIC parser API 和 bounded prefix helper。
- legacy URL logger 改为消费 shared features，保持当前设备、二进制事件、sysctl 和 Host ACL ABI。
- 已完成：Host ACL 与 URL record 分配解耦。
- 建立 L7 control mutex、consumer mask 和 custom `urllogger_store/enable` handler。
- 不新增 DPI 对外 ABI，不宣称应用分类。

### M1a：DPI gate、状态和 ABI 骨架

- 已完成：增加 `CONFIG_NATFLOW_DPI`。
- 已完成：增加 `NF_FF_L7_USE`、`NF_FF_DPI_USE`、`NF_FF_L7_URL_DONE`、`NF_FF_L7_DPI_DOMAIN_DONE`、`NF_FF_L7_DPI_PACKET_DONE` 和扩展后的 `NF_FF_BUSY_USE`。
- 已完成：在 `natflow_t` 尾部追加 `app_id`，并完成 shared conntrack extension layout guard。
- 后续仅在 parser/detector 确需更强跨包状态时增加最小 context；不为运行时配置变更实现 conntrack drain。
- 已完成骨架：实现 `/dev/natflow_dpi_ctl` 的 status、enable/disable、空 ruleset 事务。
- 已完成骨架：实现 `/dev/natflow_dpi_queue` 固定 header ABI；后续 M1b/M1c 已增加 match event producer。
- M1a 当时不宣称应用识别；后续 M1b/M1c 已加入 audit-only 的 domain/proto match。

### M1b：HTTP/TLS/QUIC 和 domain rules

- 已完成 MVP：DPI 复用 legacy URL logger 已解析出的 HTTP Host、TLS SNI、QUIC v1 Initial SNI，不重复解析包。
- 已完成 MVP：实现 RCU 发布的 domain exact/suffix ruleset，命中时写 `natflow_t.app_id` 并输出固定头 match event。
- 已完成 MVP：URL record 分配失败时，DPI 与 Host ACL 一样消费 `urllogger_acl_lookup` 的最小 host 视图。
- 已完成阶段性迁移：HTTP Host、TLS SNI、QUIC Initial/CRYPTO/SNI 解析和 TCP/QUIC packet producer 进入 `natflow_l7` feature core，TCP TLS SNI cache、QUIC cache 和 QUIC crypto ctx 迁入 `natflow_l7` 生命周期，legacy URL、Host ACL 和 DPI 继续保持原有外部 ABI；HTTP/TLS/QUIC consumer fan-out 已改为消费 `natflow_l7_host_view`，调用点不再分别散落 URL flags、DPI source 和 ACL 回复策略常量。
- 当前只输出 match event；未命中不输出 `NO_RULE`，也不执行 app ACL/QoS。

### M1c：首批 protocol-only detector

- 已完成 MVP：增加 DNS、SSH、WireGuard protocol-only 规则，并通过 L7 shared hook 的 DPI packet-view consumer 运行。
- 已完成 MVP：DNS 需要解析 TCP/UDP 53 标准 query，SSH 需要匹配 TCP original-direction `SSH-<version>-` banner，WireGuard 需要校验 UDP message type、reserved bytes 和长度；端口只选择解析候选，不直接写入 `app_id`。命中 proto rule 后写 `app_id` 并输出 match event。
- 已完成 MVP：DNS query 第一问 QNAME 由 `natflow_l7_dns_parse()` 解析并进入 domain exact/suffix ruleset，命中事件 source 为 DNS。
- 已完成阶段性迁移：DPI packet consumer 不再自行按 IPv4/IPv6 重解析 skb，而是消费 L7 packet view 的 L4/payload 指针、payload 长度和有界 `payload_linear_len`。
- 全部 audit-only，不执行 app ACL/QoS。

### M1d：第二批 A 级 detector

- 已完成 MVP：增加 STUN/TURN 子集，识别 STUN header、length、magic cookie，并按 TURN 方法区分 TURN。
- 已完成 MVP：增加 BitTorrent TCP handshake，以及 UDP uTP v1 header 和 DHT bencode token 前缀窗口子集；uTP 会校验版本、类型和扩展号。
- 已完成 MVP：`/dev/natflow_dpi_ctl` status 输出 HTTP/TLS/QUIC/DNS/SSH/WireGuard/STUN/TURN/BitTorrent source counters、protocol-only reason counters 和 `events_lost`。
- 已完成 MVP：增加 `events_clear` 测试辅助命令，用于清空已排队 match event 并重置 `events*` shadow 统计和 `proto_*` reason 统计，不改变 ruleset、enable 状态或 generation。
- 已完成基础设施：packet view 增加 direction、当前 packet `sport/dport` 和 client/server port helper；reply 只准入 DPI packet consumer。
- 已完成基础设施：DNS 与 payload detector 使用静态 metadata 声明 L4、方向模式和双向预算；DNS query/response 第一问共享有界 compression pointer walker，最多跳转 16 次并拒绝环和越界。
- 已完成基础设施：`natflow_t` 内置 8 字节 bounded context，使用 `NF_FF_DPI_USE`、双向 packet/byte counter 和 detector mask 保持 packet consumer pending。
- 已完成基础设施：放开 reply packet consumer，保持所有 URL/domain host consumer original-only。
- 仍未完成：更完整的 reason counters、payload TLV、IPv6 extension header 解析、误判 corpus 和生产 shadow 数据采集。

### M2：生产 shadow

- 生产 shadow 对比 legacy 行为，统计 coverage、unknown reason、资源丢失、CPU cost、event lost、early-fastpath/lost-owner。
- 基于数据评审 B 级 detector。
- 不改变默认阻断行为。

### M3：可选 app policy

- 在明确 Host ACL/QoS 优先级后，分步开放 app drop/reset 和 app QoS。
- 每个 action 单独验证误判、回退和 fast path 协作。

### M4：数据驱动扩展

- 逐项评审 HTTP path/UA、payload signature、JA4、DNS correlation、更多 QUIC 变体、nDPI IP/证书/cache 特征和复杂 detector。
- 不允许把 M4 能力回填成 M1 默认承诺。

## 19. 验证矩阵

### 19.1 构建

- base。
- `CONFIG_NATFLOW_URLLOGGER`。
- `CONFIG_NATFLOW_DPI`。
- `CONFIG_NATFLOW_PATH + CONFIG_NATFLOW_DPI`。
- `CONFIG_NATFLOW_URLLOGGER + CONFIG_NATFLOW_DPI`。
- `CONFIG_NATFLOW_PATH + CONFIG_NATFLOW_URLLOGGER + CONFIG_NATFLOW_DPI`。
- `NO_DEBUG=1` 组合。

### 19.2 Parser corpus

- HTTP GET/POST/HEAD、Host 大小写、port、非法 host、超长 URI、跨包 header。
- TLS 普通 SNI、无 SNI、ECH outer SNI、malformed extension、跨连续 TCP 包、gap/retransmit。
- QUIC v1 Initial、无 crypto、crypto split、coalesced、Retry、v2/unsupported、crypto 不可用。
- IPv4/IPv6、VLAN、PPPoE、bridge、non-linear skb。

### 19.3 URL/Host ACL ABI

- `/dev/natflow_urllogger_queue` 二进制事件头、payload 和单 reader 语义回归。
- `/dev/hostacl_ctl` 配置、读回、32 槽位、ipset 源过滤。
- Host ACL accept/drop/reset/redirect。
- `/proc/sys/urllogger_store/enable=0` 时 URL 和 Host ACL 都不执行。

### 19.4 Gate 与并发

- waiting flow 不建 fastnat/HWNAT。
- URL 和 DPI owner 独立完成。
- 正常 parser terminal、明确 timeout、cache full 和 NO_MEMORY 路径按各自状态机清 bit；disable、ruleset 变化和 module exit 不要求清理已标记连接。
- `nf->status` lost-owner/early-fastpath 计数。
- RPS/RFS 跨 CPU prefix 不丢。

### 19.5 ABI 与资源

- DPI ctl line 长度、未知命令、事务冲突、generation 回放、`events_clear` 后队列和统计归零。
- DPI queue 小 buffer、poll、event lost、record_len 跳过。
- ruleset memory、retired generation、hash collision、suffix probes。
- malformed packet 不刷日志。

### 19.6 性能

至少比较：

1. DPI off。
2. URL only。
3. DPI empty ruleset。
4. domain rules 满载。
5. protocol detector 全开。
6. URL + DPI 全开。

指标包括 PPS、CPU、首包延迟、context occupancy、prefix bytes、event lost、URL queue 延迟和 fast path 命中率。

## 20. 实施前确认项

1. `NF_FF_DPI_USE_BIT=21` 在 NATCAP/厂商分支中空闲。
2. `natflow_t` 追加 `app_id` 后不破坏共享 conntrack extension 布局。
3. `natflow_probe_ct_ext()` 可以 exactly-once 前置并返回错误。
4. fast path 和硬件 offload 所有建表点都受扩展后的 `NF_FF_BUSY_USE` 保护。
5. URL/Host ACL legacy 行为有 corpus 和字节级回归。
6. 运行时 disable/规则变化不依赖全局 conntrack registry，且不会重新武装或主动清理既有连接。
7. DPI queue ABI 在 v1 就定义 partial-read/poll/overflow。
8. 最低内核版本所需 RCU、poll、sysctl、crypto、IPv6 extension helper 兼容封装明确。
9. 默认规则包生成方式和 app_id 重映射责任归用户态。

## 21. MVP 验收标准

- 内部实现统一为 L7 core，URL 和 DPI 不重复解析 HTTP/TLS/QUIC。
- legacy URL logger、Host ACL、sysctl 和二进制事件行为不回退。
- `NF_FF_L7_USE` 正常阻止 fast path 提前接管 shared L7 selected flow，URL/DPI-domain/DPI-packet done bit 保证任一 consumer 失败或完成不会提前关闭另一个 consumer；DPI 瞬态 context 使用 `NF_FF_DPI_USE`。
- 正常 terminal/error 路径按状态机写 reason 并清 owner bit；运行时 disable、规则变化和 module exit 不负责清理已标记连接。
- flow 分类结果只有 `app_id`；`natflow_t` 内另有 8 字节瞬态预算上下文，其他分类细节在 event 中输出。
- unknown/error/resource exhaustion 默认 fail-open。
- 新增 DPI ABI 有版本、长度、generation、IPv6、reason、overflow 和 read/poll 语义。
- 构建矩阵和 parser/legacy/gate 回归通过，或明确记录当前环境缺失的验证项。
