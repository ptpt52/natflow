# Natflow 系统设计与规格限制文档

生成日期：2026-07-10
扫描范围：当前仓库的源码、头文件、Makefile、DKMS 配置、现有 Markdown 文档（含 DPI 设计）和仓库实际文件清单。
目标读者：内核开发者、运维集成者、代码审查者，以及需要依据本规格重建实现的 AI/自动化工具。

本文是根据仓库当前实现反向整理的系统规格。若本文和代码冲突，以当前源码为准；若要用 AI 生成对应实现，必须同时满足本文的接口、状态位、数据流和限制条件。

## 1. 项目定位

Natflow 是一个 Linux 内核模块，模块名为 `natflow`。它围绕 Netfilter、conntrack、NAT、ipset、网络设备 notifier 和字符设备控制接口实现以下能力：

- 软件快速转发：在慢路径完成路由、NAT、桥转发和 conntrack 学习后，将可加速流写入 fastnat 哈希表，后续包可在 ingress/pre-routing 中直接改写二三层头并发往出口设备。
- 可选硬件 NAT/WED 卸载：在 MTK/Ralink 相关内核配置存在时，将 fastnat 流继续下发到硬件 offload。
- 用户识别和认证控制：用“fakeuser conntrack”表示用户，跟踪 IP/MAC、认证状态、认证规则、流量统计和事件。
- QoS/限速：按用户、端口、远端地址、协议匹配 QoS 规则，并基于 token bucket 或 `skb->mark` 输出 classid。
- URL/SNI 记录和主机访问控制：解析 HTTP Host/URI、TCP TLS SNI 和 QUIC Initial SNI，记录访问日志，按 host 规则和 ipset 执行动作。
- Zone 标记：按接口名或接口名前缀把设备标记为 LAN/WAN zone，供认证和策略判断使用。
- vline/relay：在 `CONFIG_NETFILTER_INGRESS` 场景下，把指定设备之间建立 L2/L3 直通或 relay 关系。
- 观测接口：输出 conntrack、用户、URL、host ACL、zone、核心配置等状态。

模块不是一个用户态守护进程。当前仓库没有完整的 authd/web server 实现；内核模块只提供底层用户态接口、事件和网络策略执行点。

## 2. 仓库结构

| 路径 | 类型 | 角色 |
| --- | --- | --- |
| `natflow_main.c` | 编译源码 | 模块入口、`/dev/natflow_ctl`、子模块初始化和退出顺序。 |
| `natflow_common.c/.h` | 编译源码/公共头 | 日志、兼容封装、conntrack 扩展探测、natflow 会话扩展、ipset/NAT 封装。 |
| `natflow.h` | 公共头 | 核心数据结构、fastnat 节点、状态位、哈希算法、表大小和超时常量。 |
| `natflow_l7.c/.h` | 编译源码/头 | L7 hook 生命周期和共享 feature core；当前持有 URL hook ops、内核 hook 签名兼容包装、PPPoE normalize/restore、基础 conntrack 过滤和注册/注销流程，并提供 packet view、host/URI normalize、HTTP Host、TLS SNI、QUIC Initial/CRYPTO/SNI 和 DNS QNAME parser。 |
| `natflow_dpi.c/.h` | 编译源码/头 | DPI 控制/事件接口，提供默认关闭的 `/dev/natflow_dpi_ctl`、domain exact/suffix ruleset、DNS QNAME domain 分类、DNS/SSH/WireGuard/STUN/TURN/BitTorrent protocol-only ruleset、`app_id` 写入、source counters 和 `/dev/natflow_dpi_queue` match 事件。 |
| `natflow_path.c/.h` | 编译源码/头 | fast path、route 学习、fastnat 表、vline/relay、设备 notifier、硬件 offload。 |
| `natflow_user.c/.h` | 编译源码/头 | 用户 fakeuser、认证、QoS、用户事件、用户信息控制设备。 |
| `natflow_urllogger.c/.h` | 编译源码/头 | Legacy URL consumer；通过 `natflow_urllogger_consume_url_view()` 消费 L7 packet view，保留 URL/SNI 记录、URL store、Host ACL、302/RST 动作、sysctl 和 QUIC/SNI cache/crypto 资源。 |
| `natflow_zone.c/.h` | 编译源码/头 | LAN/WAN zone 控制、设备 zone 标记、zone notifier。 |
| `natflow_conntrack.c/.h` | 编译源码/头 | `/dev/conntrackinfo_ctl` conntrack dump。 |
| `natflow_compat.h` | 公共头 | 大量内核版本和 API 兼容宏。 |
| `Makefile` | 构建入口 | 编译 `natflow.o`，对象始终包含所有 `.o`，功能由 C 宏决定。 |
| `Makefile.dkms`、`dkms.conf` | DKMS 入口 | 安装到 `/usr/src/natflow-<version>` 并通过 DKMS build/install。 |
| `README.md` | 文档 | 面向人类的使用手册和对外接口说明。 |
| `SYSTEM_DESIGN_SPEC.md` | 文档 | 面向开发、审查和自动化重建的系统设计规格。 |
| `DPI_DESIGN.md` | 文档 | 统一 L7 core 与 DPI 目标设计，覆盖 legacy URL/HostACL consumer、DPI classifier consumer、HTTP/TLS/QUIC/DNS QNAME 共享解析、`app_id` flow result、独立 DPI ABI、分级 detector 和 M0-M4 实施路径；当前源码已预留 DPI busy bit、`app_id`、layout guard，实现 L7 feature core、DPI domain exact/suffix ruleset、DNS QNAME domain 分类、DNS/SSH/WireGuard/STUN/TURN/BitTorrent protocol-only ruleset、match event producer、source counters 和 `app_id` 写入。 |

### 2.1 当前扫描基线

本次重新扫描基于当前工作区实际文件和 Git 跟踪文件：

- 仓库包含 C 源码 9 个、头文件 10 个，以及多个 Markdown 文档（包括系统规格、DPI 设计和智能体记忆）、Makefile、DKMS 配置和 `.gitignore`。
- 当前实际目录中没有 `natflow_path.c.orig`、`cscope.files`、`cscope.out`、`natflow.mod.c` 等历史备份、索引或构建生成文件；`.gitignore` 仍会忽略 `*.orig`、`cscope.*` 和 `*.mod.c`，因此未来若这些文件重新出现，应先判断是否为生成物或临时备份，不能加入 DKMS 源码复制清单。
- `SYSTEM_DESIGN_SPEC.md` 本身是规格产物，参与 Git 跟踪，但不是内核模块构建输入。
- 仓库中不再保留 `portal/` 设计草案文档；当前源码仍只提供内核模块接口，没有 authd/web server 实现。

## 3. 构建规格

### 3.1 Makefile 行为

主 Makefile：

- 生成内核模块 `natflow.o`。
- `natflow-y` 包含 `natflow_main.o natflow_common.o natflow_l7.o natflow_dpi.o natflow_path.o natflow_user.o natflow_zone.o natflow_urllogger.o natflow_conntrack.o`。
- 默认 `EXTRA_CFLAGS += -Wall -Werror -Wno-stringop-overread`。
- 定义 `NO_DEBUG` 时追加 `-Wno-unused -Os -DNO_DEBUG`，并关闭 `NATFLOW_DEBUG/INFO/WARN/ERROR/FIXME` 宏输出。
- 运行时全局日志级别可通过 `debug=<u>` 掩码控制（包含 `debug_ratelimited` 等位）。
- `KERNELDIR` 默认 `/lib/modules/$(uname -r)/build`，通过 `make -C $(KERNELDIR) M=$(PWD)` 编译。

DKMS Makefile：

- 版本来自 `natflow_common.h` 的 `NATFLOW_VERSION`，当前为 `1.0.1`。
- 拷贝源码和头文件到 `/usr/src/natflow-<version>`；复制清单不包含 `natflow.mod.c` 等 Kbuild 生成物。
- 生成的 DKMS Makefile 会把 `#EXTRA_CFLAGS` 行替换为 `EXTRA_CFLAGS = -DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER`。
- DKMS 安装位置为 `/kernel/drivers/net`，`AUTOINSTALL="yes"`。

运行时日志参数：

| bit | 十进制 | 宏 | 行为 |
| --- | --- | --- | --- |
| 0 | 1 | `NATFLOW_LOG_ERROR` | 输出 error 日志。 |
| 1 | 2 | `NATFLOW_LOG_WARN` | 输出 warning 日志。 |
| 2 | 4 | `NATFLOW_LOG_INFO` | 输出 info 日志。 |
| 3 | 8 | `NATFLOW_LOG_DEBUG` | 输出完整 debug 日志。 |
| 4 | 16 | `NATFLOW_LOG_FIXME` | 输出 fixme 日志。 |
| 5 | 32 | `NATFLOW_LOG_DEBUG_LIMITED` | 当 bit 3 未置位时输出 ratelimited debug。 |

`debug` 同时是 `module_param(debug, int, 0)` 和 `/dev/natflow_ctl` 命令；module param 权限为 0，不提供 sysfs 运行时写入口，常规运行期应通过控制设备设置。

### 3.2 关键编译宏

| 宏 | 影响 |
| --- | --- |
| `CONFIG_NATFLOW_PATH` | 编译并初始化 fast path、vline/relay、`natflow_ctl` 中 path 相关命令。未定义时 path 能力不生效。 |
| `CONFIG_NATFLOW_URLLOGGER` | 编译并初始化 URL logger、host ACL、sysctl。 |
| `CONFIG_NATFLOW_DPI` | 编译并初始化 DPI 控制/事件接口，提供 `/dev/natflow_dpi_ctl`、domain exact/suffix ruleset、DNS QNAME domain 分类、DNS/SSH/WireGuard/STUN/TURN/BitTorrent protocol-only ruleset 和 `/dev/natflow_dpi_queue`；默认关闭。当前 HTTP/TLS/QUIC host 分类复用 `CONFIG_NATFLOW_URLLOGGER` parser，并在 DPI enabled 且存在 domain rule 时独立激活 L7 DPI consumer；DNS QNAME 分类由 DPI hook 自己解析。 |
| `CONFIG_NETFILTER_INGRESS` | 使用 per-netdev ingress hook；当前源码也只在该模式下分配 `natflow_fast_nat_table` 并编译主要软件 fastnat 命中/建表路径；vline/relay 只在该模式下有实际转发路径。 |
| `CONFIG_NET_RALINK_OFFLOAD` | 启用 Ralink/MTK 硬件 offload 相关代码。 |
| `NATFLOW_OFFLOAD_HWNAT_FAKE` + `CONFIG_NET_MEDIATEK_SOC` | 启用 fake HWNAT/MTK offload 分支。 |
| `CONFIG_NET_MEDIATEK_SOC_WED` | 允许配置 `hwnat_wed_disabled`。 |
| `CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH` | 硬件外部设备 offload 以 VLAN hash 辅助索引。 |
| `CONFIG_HWNAT_EXTDEV_DISABLED` | 禁用部分外部设备硬件 offload 分支。 |
| `CONFIG_NATFLOW_URLLOGGER_LOCAL_IN` | URL logger 改用 IPv4 `LOCAL_IN` hook，而不是默认 FORWARD/bridge hook 组合。 |
| `CONFIG_NF_CONNTRACK_MARK` | 认证流程可写 `ct->mark`。 |
| `CONFIG_BRIDGE_NETFILTER` | 用户统计/桥路径有额外物理入出设备判断。 |
| `CONFIG_NF_NAT` 或 `CONFIG_NF_NAT_MODULE` | 必需；缺失会在 `natflow_common.h` 编译期报错。 |
| `NATFLOW_NAT66_AVAILABLE` | 决定是否定义 `NATFLOW_HAVE_NAT66` 并启用 IPv6 NAT66 DNAT 封装。 |

### 3.3 内核兼容

`natflow_compat.h` 和 `natflow_common.h` 封装了跨内核版本差异，包括：

- Netfilter hook 函数签名、`nf_hook_state`、owner 字段、netdev ingress 注册方式。
- `nf_register_net_hooks`/旧接口差异。
- conntrack 全局 hash、conntrack 扩展 replace/assign 的 RCU 语义。
- `nf_conntrack_find_get` zone 参数差异。
- `nf_nat_setup_info`、NAT66、`nf_nat_range` API 差异。
- ipset state API、新旧 `ip_set_test/add/del` 调用形式。
- `skb_try_make_writable`、`skb_make_writable`、`nf_reset_ct`、`get_random_u32`、`class_create`、sysctl 注册 API 差异。
- 非 seek 字符设备使用 `natflow_no_llseek()` 保持 `-ESPIPE` 语义，避免依赖不同内核是否暴露 `no_llseek` 符号。

内核版本适配是模块设计的一部分。重建实现时不能只面向单一新内核 API，除非明确放弃旧内核支持。

## 4. 运行时架构

Natflow 分为控制面、策略面、数据面和观测面。

控制面：

- 字符设备：`/dev/natflow_ctl`、`/dev/natflow_zone_ctl`、`/dev/natflow_user_ctl`、`/dev/qos_ctl`、`/dev/userinfo_ctl`、`/dev/userinfo_event_ctl`、`/dev/conntrackinfo_ctl`、`/dev/hostacl_ctl`、`/dev/urllogger_queue`、`/dev/natflow_dpi_ctl`、`/dev/natflow_dpi_queue`。
- sysctl：`/proc/sys/urllogger_store/*`。
- ipset：认证白名单、旁路名单、QoS 集合、vline 过滤集合、host ACL 过滤集合。

策略面：

- zone 匹配决定 LAN/WAN 方向和认证规则适用性。
- user/auth 模块决定用户状态、HTTP/HTTPS 重定向、认证阻断/放行。
- QoS 模块决定限速或 tc classid 标记。
- urllogger/hostacl 模块决定 URL 记录、drop/reset/redirect 标记。
- vline 模块决定指定设备之间的 L2/L3 直通或 relay。

数据面：

- 慢路径仍然依赖 Linux 原生 Netfilter、conntrack、NAT、路由、桥。
- `natflow_path_post_ct_out_hook()` 在 POST_ROUTING 学习正反向出口路由、L2 头、MTU、TTL/hop-limit、VLAN、PPPoE 等信息。
- `natflow_path_pre_ct_in_hook()` 在 ingress/PRE_ROUTING 尝试 fastnat 命中；命中时直接更新 L3/L4 校验、MAC/VLAN/PPPoE/TTL 并 `dev_queue_xmit()`。
- 未命中、条件不满足或需采样/保活时回退慢路径。

观测面：

- `conntrackinfo_ctl` 输出非 fakeuser/non-NATCAP-peer 的 conntrack 文本。
- `userinfo_ctl` 输出 fakeuser 用户状态和计数。
- `userinfo_event_ctl` 阻塞输出认证事件。
- `urllogger_queue` 输出 URL/SNI 记录。
- 各控制设备读接口可输出可重放配置。

## 5. 初始化和退出顺序

`natflow_init()` 顺序：

1. 注册 `/dev/natflow_ctl` 的主设备号。
2. 前置执行 `natflow_probe_ct_ext()`，探测并验证 shared conntrack extension 布局。
3. 初始化 `/dev/natflow_ctl` 的 cdev/class/device。
4. 初始化 zone：`natflow_zone_init()`。
5. 初始化 user/auth/QoS/userinfo：`natflow_user_init()`。
6. 初始化 conntrackinfo：`conntrackinfo_init()`。
7. 若 `CONFIG_NATFLOW_PATH`，初始化 path：`natflow_path_init()`。
8. 若 `CONFIG_NATFLOW_URLLOGGER`，初始化 urllogger 设备、Host ACL 和 sysctl：`natflow_urllogger_init()`。
9. 若 `CONFIG_NATFLOW_DPI`，初始化 DPI 控制/事件和规则接口：`natflow_dpi_init()`。
10. 若 `CONFIG_NATFLOW_URLLOGGER || CONFIG_NATFLOW_DPI`，初始化 L7 hook 生命周期：`natflow_l7_init()`。

退出顺序反向执行：

1. L7 hook lifecycle 退出。
2. DPI 控制/事件和规则接口退出。
3. URL logger 退出。
4. path 退出。
5. conntrackinfo 退出。
6. user 退出。
7. zone 退出。
8. 注销 `/dev/natflow_ctl`。

设计含义：

- zone 和 user 在 path 前初始化，因此 fast path 可依赖 zone/user 状态位。
- user 子系统初始化时，`userinfo_event_store_init()` 在 `/dev/userinfo_event_ctl` 的 `cdev_add()` 之前执行；设备节点一旦可打开，事件队列的 spinlock、list 和 waitqueue 已经有效。
- URL logger 在 path 后初始化，但通过 `NF_FF_URLLOGGER_USE` 与 path 协调，避免未完成 URL 处理的流被快速转发。
- L7 hook lifecycle 在 URL logger 资源初始化之后注册 URL hook ops；hook 签名兼容包装由 L7 持有，数据面通过 `natflow_urllogger_consume_url_view()` 委托 legacy URL consumer。退出时先注销 hook 再释放 URL logger 资源。
- 退出 path 时先 `disabled=1`，再注销 hooks/notifier、同步 RCU、停止硬件 offload、释放表。

## 6. 公共控制协议

除 `conntrackinfo_ctl` 的长读逻辑和 `userinfo_event_ctl` 的阻塞读外，大多数字符设备写入均采用同一协议：

- 单条命令最长 `MAX_IOCTL_LEN = 256` 字节。
- 命令必须以换行 `\n` 结束，否则会暂存在静态 `data[MAX_IOCTL_LEN]` 中等待后续写入。
- 行过长返回 `-EINVAL` 并丢弃当前缓冲。
- 开头空格、制表符、换行会被跳过，且会清空未完成行。
- 解析成功时返回本次消费字节数。
- 未识别命令打印 `ignoring line`，多数情况下仍返回已消费长度；若解析过程中设置了错误码，则返回对应错误。
- 每个设备写缓冲是文件作用域 `static` 变量，不是每个 fd 独立状态；多进程并发写同一设备可能互相污染半行命令。

AI 重建时必须保留“换行结束、256 字节上限、静态半行缓存、未识别命令只记录日志”的行为，除非明确作为兼容性破坏项修改。

常见错误返回：

| 返回值 | 场景 |
| --- | --- |
| `-EACCES` | `copy_from_user()` 失败。 |
| `-EFAULT` | `copy_to_user()` 失败。 |
| `-EINVAL` | 控制行超过 256 字节、命令字段格式非法、部分 read buffer 过小。 |
| `-ENOMEM` | 规则、per-open 缓冲、skb 或工作队列分配失败。 |
| `-ENOENT` | 用户控制命令找不到指定 fakeuser。 |
| `-ENODEV` | vline/relay 应用时找不到配置的 endpoint 设备。 |
| `-EAGAIN` | 分批扫描尚未完成、暂时无可读数据、互斥锁被信号中断等。 |
| `-EBUSY` | `/dev/userinfo_event_ctl` 已有 reader。 |
| `-ENOSYS` | `/dev/userinfo_event_ctl` 写接口未实现。 |
| `-EBADF` | 读接口缺少 per-open 私有数据。 |

读接口分为三类：

- `seq_file` 配置接口：`natflow_ctl`、`natflow_zone_ctl`、`natflow_user_ctl`、`qos_ctl`、`hostacl_ctl`。
- 支持 partial read 的流接口：`conntrackinfo_ctl`，可把一条长记录分多次 copy 到用户 buffer。
- 不支持 partial read 的队列接口：`userinfo_ctl`、`userinfo_event_ctl`、`urllogger_queue`；一行大于用户 buffer 时返回 `-EINVAL`。

## 7. 字符设备规格

### 7.1 `/dev/natflow_ctl`

读接口输出：

- `Version: <NATFLOW_VERSION>`。
- 使用说明。
- `debug=<value>`。
- 若启用 path：`disabled`、`hwnat`、`hwnat_wed_disabled`、`delay_pkts`、`go_slowpath_if_no_qos`、`ifname_group_type`。
- 当前 ifname group 和 vline/relay 配置的可重放命令。

默认值：

- path `disabled=1`，模块加载后 fast path 默认关闭。
- `delay_pkts=0`，`go_slowpath_if_no_qos=0`。
- HWNAT 分支中 `hwnat=1`；`hwnat_wed_disabled` 在 `CONFIG_NET_MEDIATEK_SOC_WED` 下默认 0，否则默认 1。

写命令：

| 命令 | 条件 | 行为 |
| --- | --- | --- |
| `debug=<u>` | 总是可用 | 设置全局日志 bitmask（1=error, 2=warn, 4=info, 8=debug, 16=fixme, 32=debug_ratelimited）。 |
| `disabled=<u>` | `CONFIG_NATFLOW_PATH` | 设置 path `disabled`，布尔化。 |
| `hwnat=<u>` | HWNAT 分支 | 设置硬件 offload 开关。 |
| `hwnat_wed_disabled=<u>` | `CONFIG_NET_MEDIATEK_SOC_WED` | 设置 WED 禁用标志。 |
| `delay_pkts=<u>` | path | fastnat 建立前延迟包数阈值。 |
| `go_slowpath_if_no_qos=<u>` | path | 无 QoS 命中时是否停止 fast path。 |
| `ifname_group_type=<u>` | path | 接口组过滤模式：0 全部；1 仅 group 双向；2 group 双向走慢路径。 |
| `ifname_group_clear` | path | 清除所有设备 `IFF_IFNAME_GROUP`。 |
| `ifname_group_add=<ifname>` | path | 在 `init_net` 中找到设备并设置 `IFF_IFNAME_GROUP`。 |
| `vline_clear` | path | 清空 vline 配置和运行映射。 |
| `vline_add=<src>,<dst>,<family>` | path | 追加 vline 配置，family 为 `ipv4`/`ipv6`/`all`。 |
| `relay_add=<src>,<dst>,<family>` | path | 追加 relay 配置，family 同上。 |
| `vline_apply` | path | 清除运行状态并应用所有 vline/relay 配置。 |
| `list_net_device` | path | 打印设备、ifindex、flags 到内核日志。 |
| `update_magic` | path | 递增 path magic，使现有 fastnat 条目失效/重新学习。 |

`vline_add`/`relay_add` 解析使用 `%15[^,],%15[^,],%7s%c`，必须正好解析 3 个字段；接口名可见部分最多 15 字节，family 最多 7 字节，行尾不能带额外非空字符。

### 7.2 `/dev/natflow_zone_ctl`

读接口输出 usage、当前 zone 规则和可重放命令。

写命令：

| 命令 | 行为 |
| --- | --- |
| `clean` | 清空 zone 规则；当前实现不会自动刷新已有设备缓存标记，调用者应继续执行 `update_match`。 |
| `lan_zone <id>=<if_name>` | 追加 LAN zone 规则。 |
| `wan_zone <id>=<if_name>` | 追加 WAN zone 规则。 |
| `update_match` | 重新扫描 `init_net` 设备并应用匹配。 |
| `print_zone` | 输出设备 zone 信息到内核日志。 |

规则匹配：

- `<if_name>` 最大解析 14 字符。
- `+` 表示前缀通配终止，例如 `eth+` 匹配所有以 `eth` 开头的设备；无 `+` 时要求完整匹配。
- 写解析会拒绝 `id > MAX_ZONE_ID` 并返回 `-EINVAL`；`natflow_zone_id_set()` 内部仍以 `ZONE_ID_MASK` 做防御性裁剪。
- 同一个 zone id 只能属于一种类型；如果某个 id 已经被 `lan_zone` 使用，再添加同 id 的 `wan_zone` 必须返回 `-EINVAL`，反之亦然。同 id 同类型的多条接口匹配规则允许存在。

### 7.3 `/dev/natflow_user_ctl`

读接口输出：

- `disabled`、`auth_conf_magic`、`redirect_ip`、`redirect_ip6`、`no_flow_timeout`。
- `auth_open_weixin_reply`、`https_redirect_en`、`https_redirect_port`。
- 规则数量、`dst_bypasslist_name`、`src_bypasslist_name`。
- 每条 auth 规则的可重放命令。

写命令：

| 命令 | 行为 |
| --- | --- |
| `clean` | 清空所有认证规则，同时清空 `dst_bypasslist_name` 和 `src_bypasslist_name`。 |
| `disabled=<u>` | 布尔化设置用户认证模块开关。默认 `1`。 |
| `update_magic` | 更新认证配置 magic。 |
| `dst_bypasslist_name=<name>` | 设置目标 IP 旁路 ipset 名称，空值清除。 |
| `src_bypasslist_name=<name>` | 设置源 IP 旁路 ipset 名称，空值清除。 |
| `auth id=<id>,szone=<idx>,type=web/auto,sipgrp=<name>[,ipwhite=<name>][,macwhite=<name>]` | 追加认证规则。 |
| `redirect_ip=a.b.c.d` | 设置 HTTP 302/认证跳转目标 IPv4。 |
| `redirect_ip6=<ipv6>` | 设置 HTTP 302/认证跳转目标 IPv6。默认为 `::`，当请求为 IPv6 且此项未配置时，默认 Fallback 倒退使用 IPv4 `redirect_ip` 作为 HTTP 302 Location URL 目标。 |
| `no_flow_timeout=<u>` | 设置 fakeuser 无流超时秒数，默认 1800。 |
| `https_redirect_en=<u>` | 开启/关闭 HTTPS DNAT 重定向。 |
| `auth_open_weixin_reply=<u>` | 开启/关闭 WeChat 自动 portal 响应。 |
| `https_redirect_port=<u>` | 设置 HTTPS DNAT 端口，内部保存为网络字节序。 |

默认值：

- `disabled=1`。
- `redirect_ip=10.10.10.10`。
- `redirect_ip6=::`。
- `no_flow_timeout=1800` 秒。
- `auth_open_weixin_reply=0`。
- `https_redirect_en=0`。
- `https_redirect_port=443`。
- `auth_conf_magic` 初始化时由 `jiffies` 赋值到 `uint16_t`，高位会按 C 整数转换语义截断；`update_magic` 后自增。

限制：

- 最多 `MAX_AUTH = 16` 条 auth 规则。
- ipset 名称字段类型为 `IPSET_MAXNAMELEN`。当前 `auth` 命令中 `sipgrp/ipwhite/macwhite` 拷贝循环最多写入 `IPSET_MAXNAMELEN - 1` 字节并补 NUL，避免越界写；但过长名称会被静默截断而不是返回 `-EINVAL`，集成层仍应主动限制长度。
- 认证类型仅 `web` 和 `auto`；非法 type 会返回 `-EINVAL`。当前解析没有强制要求提供 `type=`，缺失时规则内 `auth_type` 保持 0；匹配阶段只有 `AUTH_TYPE_AUTO` 走自动认证，其余值按 web 认证处理。
- `sipgrp` 必填；`ipwhite` 和 `macwhite` 可选。

### 7.4 `/dev/qos_ctl`

读接口输出：

- usage。
- `tc_classid_mode=<0|1>`。
- `clear` 和所有 QoS 规则的可重放命令。

写命令：

| 命令 | 行为 |
| --- | --- |
| `clear` | 清空 QoS 规则和 token 组。 |
| `tc_classid_mode=<u>` | 布尔化设置 classid 模式。 |
| `add user=<addr/set>,user_port=<port/set>,remote=<addr/set>,remote_port=<port/set>,proto=<tcp/udp/>,rxbytes=<u>,txbytes=<u>` | 追加规则。 |

字段规格：

- `user`、`remote` 支持 IPv4、IPv4 CIDR、IPv6、IPv6 CIDR、ipset 名称或空字符串通配。
- CIDR 输入必须是网络地址形式，不能包含 host bits。
- `user_port`、`remote_port` 支持 `0..65535` 数字端口、ipset 名称或空字符串通配。
- `proto` 支持 `tcp`、`udp` 或空字符串通配。实现要求字段后面有逗号；读接口输出 `proto=,` 表示通配。
- set 名称数组为 16 字节，因此最多 15 字节。
- 最多 `QOS_TOKEN_CTRL_GROUP_MAX = 64` 条规则。
- token 速率保存为 `bytes / HZ`；若 `rxbytes` 或 `txbytes` 小于 `HZ`，`tokens_per_jiffy` 会变成 0，实际限速行为可能不符合预期。
- `rxbytes/txbytes` 字段未提供时规则仍可能被加入，速率默认为 0；匹配后 token 控制函数会因 `tokens_per_jiffy == 0` 放行。

`tc_classid_mode=1` 时不消耗 token，而是对 rx/tx 分别设置 `skb->mark = qos_id * 2 - 1` 和 `qos_id * 2`。`tc_classid_mode=0` 时使用 token bucket 丢弃/放行。

### 7.5 `/dev/userinfo_ctl`

读接口输出 fakeuser 列表，每行：

```text
ip_or_ipv6,mac,auth_type_hex,auth_status_hex,rule_id,idle_time,rx_pkts:rx_bytes,tx_pkts:tx_bytes,rx_speed_pkts:rx_speed_bytes,tx_speed_pkts:tx_speed_bytes
```

写命令：

| 命令 | 行为 |
| --- | --- |
| `kickall` | 分批重置所有 fakeuser 的认证状态和计数；扫描超过时间片会返回 `-EAGAIN`，调用方应重试。 |
| `kick <ip>` | 重置指定 IPv4/IPv6 用户。 |
| `set-status <ip> <status>` | 设置用户认证状态。 |
| `set-token-ctrl <ip> <rx> <tx>` | 设置用户级 token ctrl；`rx/tx` 为字节每秒，内部转为 `bytes/HZ`。 |

限制：

- 单次 read 如果生成行长度大于用户提供 buffer，会返回 `-EINVAL`，这会破坏 shell 中按 1 字节读的用法。代码中已有 FIXME，重建实现若追求兼容应保留，若修复需在变更记录说明。
- fakeuser 是特殊 conntrack，不是独立用户态表。
- `idle_time` 复用 fakeuser 内部 `timestamp` 计算，输出值为经过秒数，不再从当前 `no_flow_timeout` 反推；该 timestamp 在 fakeuser 创建/获取时写入，user pre hook 中普通活动最多每 32 秒刷新一次，`IP_CT_NEW` 新连接包距离上次刷新超过 2 秒也会刷新。
- 每个打开实例缓存最多 4096 条用户快照；扫描 conntrack hash 超过时间片或缓存上限时会保存 `next_bucket` 并返回 `-EAGAIN`。
- 速度字段来自 4 个 2 秒窗口；如果超过 8 秒无更新，速度输出为 0。

### 7.6 `/dev/userinfo_event_ctl`

行为：

- `open` 时通过 `cmpxchg()` 把全局 `stage` 从 STOPPED 切到 RUNNING，只允许一个 reader；已有 reader 时返回 `-EBUSY`。
- 事件只在 reader 已打开且 `stage == RUNNING` 时入队；入队前和持有队列锁后都会检查 `stage`，避免 close 竞态后继续挂入全局队列。
- `read` 阻塞等待用户事件，输出格式与 `userinfo_ctl` 行接近；`read` 不再负责启动或停止全局事件流。
- `release` 会把 `stage` 置回 STOPPED，唤醒等待中的 reader，并清空全局待消费事件队列。
- `write` 返回 `-ENOSYS`。
- 单次 read 同样存在行长度大于 buffer 时返回 `-EINVAL` 的限制。

### 7.7 `/dev/conntrackinfo_ctl`

读接口：

- 扫描 conntrack hash。
- 跳过 reply 方向、已过期 conntrack、fakeuser (`IPS_NATFLOW_USER`) 和 NATCAP peer (`IPS_NATCAP_PEER`)。
- 输出类似 `/proc/net/nf_conntrack` 的文本，包括 l3/l4、超时、tuple、协议私有状态、acct、`[UNREPLIED]`、`[ASSURED]`、mark、use 等。

写命令：

- 当前只识别 `kickall`，但没有实际清理行为，主要用于占位/兼容。

性能限制：

- 每次扫描时间片约 100ms。
- 每个打开实例最多缓存 256 个 4096 对齐 chunk，约 1MB。
- 未完成扫描时 read 返回 `-EAGAIN`，调用方应继续读。
- 输出行长大于用户 buffer 时会 partial copy 并保留剩余数据，这是该仓库中唯一实现 partial read 的长文本接口。

### 7.8 `/dev/urllogger_queue`

条件：`CONFIG_NATFLOW_URLLOGGER`。

写命令：

- `clear`：清空 URL store。

读接口：

- 每次取出并删除一个超过 `timestamp_freq` 老化阈值的 URL 记录。
- 输出格式：

```text
timestamp,mac,sip,sport,dip,dport,hits,method,type,acl_idx,acl_action,url
```

字段说明：

- `method` 为 `NONE`、`GET`、`POST`、`HEAD`。
- `type` 为 hostname 来源协议：`HTTP`、`HTTPS` 或 `QUIC`。
- `acl_action` 数值：0 accept/record，1 drop，2 reset，3 redirect。
- IPv6 地址使用 `%pI6` 输出。

限制：

- 如果没有满足老化条件的记录，read 返回 0。
- 如果输出行大于用户 buffer，返回 `-EINVAL`。
- 如果编码后的 URL 记录超过内部 `URLLOGGER_DATALEN`，该记录会被取出并释放，但本次 read 返回 0；这会造成超长 URL 日志静默丢失。
- 内部输出缓存大小约 `ALIGN(sizeof(struct urllogger_user), 2048) - sizeof(struct urllogger_user)`。
- `url` 字段按 CSV 字段输出；若字段内出现逗号、双引号、CR 或 LF，会用双引号包裹并把内部双引号写成两个双引号。当前 hostname/URI 入口拒绝 NUL 和控制字符，CR/LF escaping 主要作为输出边界防御。
- HTTP 记录的 `url` 字段是 `host + uri` 拼接结果，中间没有额外分隔符；HTTPS/QUIC 记录只保存 SNI hostname。

### 7.9 `/dev/hostacl_ctl`

条件：`CONFIG_NATFLOW_URLLOGGER`。

读接口输出默认 action、usage，以及 `ACL0..ACL31` 的规则内容。

写命令：

| 命令 | 行为 |
| --- | --- |
| `clear` | 清空所有 ACL 规则。 |
| `acl_action_default=accept/drop/reset/redirect` | 设置默认动作。 |
| `redirect_url=<http_url>` | 设置 Host ACL redirect 动作使用的 HTTP 302 Location URL。 |
| `add acl=<id>,<act>,<host>` | 添加 host ACL。 |

限制：

- `ACL_RULE_MAX = 32`。
- `<act>` 必须是 `0..3`，含义同 URL logger。
- `<id>` 必须是 `0..31`。
- host 原样追加进规则 buffer，匹配时会按 host 和域名后缀查找。
- 规则 buffer 容量按 `ACL_RULE_ALLOC_SIZE = 256` 对齐；每次追加规则都会构造新的完整 buffer，并通过 RCU 指针发布，旧 buffer 在 RCU grace period 后释放。
- host ACL 控制面读写由 `acl_rule_lock` 串行化；URL hook 数据面匹配在 RCU 读侧保护下读取当前规则 buffer。
- 规则内部用 host 前一个 marker 字节保存 high-bit、action 和 rule id；读 `/dev/hostacl_ctl` 时会把 marker 内容直接夹在规则 buffer 输出中，不是结构化 JSON/CSV。

关联 ipset：

- `host_acl_rule<id>_ipv4`
- `host_acl_rule<id>_ipv6`
- `host_acl_rule<id>_mac`

如果某条 host 规则的 IP 和 MAC ipset 都不存在，host 命中即可应用；如果对应 set 存在，则必须 set 测试命中才应用。

## 8. Sysctl 规格

条件：`CONFIG_NATFLOW_URLLOGGER`。

路径：`/proc/sys/urllogger_store/`

| 名称 | 默认值 | 权限/行为 |
| --- | --- | --- |
| `enable` | 0 | 开关 URL store 和 hook 处理。 |
| `memsize_limit` | 10MB | URL store 内存上限；超过后驱逐最老记录。 |
| `memsize` | 0 | 当前内存使用，只读语义。 |
| `count_limit` | 10000 | URL store 记录数上限；超过后驱逐最老记录。 |
| `count` | 0 | 当前记录数，只读语义。 |
| `timestamp_freq` | 10 | 相同 URL 合并时间窗口，也是读出前的最小老化秒数。 |
| `tuple_type` | 0 | URL 记录使用的 conntrack tuple 方向。0=dir0 src/dst；1=dir0 src/dir1 src；2=dir1 dst/dir1 src。 |

`enable=0` 时 URL hook 直接 accept，不记录、不执行 host ACL。

## 9. ipset 契约

Natflow 不创建 ipset，只按名称查找和测试/添加/删除。用户态负责创建合适 family/type 的 set。

公共封装：

| wrapper | dim/flags | set 不存在时返回 |
| --- | --- | --- |
| `ip_set_test_src_ip()` | `IPSET_DIM_ONE` + `IPSET_DIM_ONE_SRC` | `-EINVAL` |
| `ip_set_test_dst_ip()` | `IPSET_DIM_ONE` + dst 语义 | 0 |
| `ip_set_test_dst_netport()` | `IPSET_DIM_TWO` + dst 语义 | 0 |
| `ip_set_add_src_ip()` | `IPSET_DIM_ONE` + `IPSET_DIM_ONE_SRC` | 0 |
| `ip_set_add_dst_ip()` | `IPSET_DIM_ONE` + dst 语义 | 0 |
| `ip_set_del_src_ip()` | `IPSET_DIM_ONE` + `IPSET_DIM_ONE_SRC` | 0 |
| `ip_set_del_dst_ip()` | `IPSET_DIM_ONE` + dst 语义 | 0 |
| `ip_set_test_src_mac()` | `NFPROTO_UNSPEC` + `IPSET_DIM_ONE_SRC` | `-EINVAL` |

这种“不存在时有的返回 0、有的返回 `-EINVAL`”是行为契约的一部分：host ACL 用 `-EINVAL` 判断对应 IP/MAC set 是否根本不存在，vline 过滤则把不存在视为未命中过滤。

使用点：

| 名称来源 | 用途 |
| --- | --- |
| `auth sipgrp` | 认证规则源 IP 范围。 |
| `auth ipwhite` | 认证规则源 IP 白名单。 |
| `auth macwhite` | 认证规则源 MAC 白名单。 |
| `dst_bypasslist_name` | 认证阻断/重定向时目标 IP 旁路。 |
| `src_bypasslist_name` | 认证阻断/重定向时源 IP 旁路。 |
| QoS `user`/`remote` 名称 | 用户/远端 IP 集合。 |
| QoS `user_port`/`remote_port` 名称 | 端口集合。 |
| `vline_filter_dst_netport`、`vline_filter_dst`、`vline_filter_src`、`vline_filter_src_mac` | IPv4 vline 过滤。 |
| `vline_filter6_dst_netport`、`vline_filter6_dst`、`vline_filter6_src`、`vline_filter_src_mac` | IPv6 vline 过滤。 |
| `host_acl_rule<id>_ipv4/ipv6/mac` | host ACL 规则附加过滤。 |

## 10. 核心数据结构

### 10.1 `natflow_route_t`

每个方向保存一次慢路径学习得到的转发信息：

- `mtu`：路由 MTU。
- `vlan_present`、`vlan_proto`、`vlan_tci`：出口 VLAN 信息。
- `l2_head[NF_L2_MAX_LEN]`：二层头缓存，最大 `14 + 8 = 22` 字节，可包含 Ethernet + PPPoE。
- `l2_head_len`：二层头长度；PPP/RAW 等可能为 0。
- `ifname_group`：出口设备是否在 ifname group。
- `ttl_in`：IPv4 TTL 或 IPv6 hop-limit 入值，用于区分 bridge/route 转发。
- `outdev`：出口 `net_device` 指针。

### 10.2 `natflow_t`

挂在 conntrack 扩展中的 NATflow 会话对象：

- `magic`：path magic 快照。magic 变化后重新学习。
- `qos_id`：匹配到的 QoS 组 id，从 1 开始。
- `status`：`NF_FF_*` 状态位。
- `rroute[2]`：两个方向的 `natflow_route_t`。
- `app_id`：DPI 的常驻应用分类结果；`0` 表示 unknown、未分类或没有结果。当前 domain exact/suffix matcher（HTTP Host、TLS/QUIC SNI、DNS QNAME）和 DNS/SSH/WireGuard/STUN/TURN/BitTorrent protocol-only matcher 在规则命中且已有 natflow session 时写入非 0 `app_id`，其他 DPI 细节只进入事件。

重要 `NF_FF_*` 位：

- `NF_FF_ORIGINAL_DSA` / `NF_FF_REPLY_DSA`：记录硬件 offload/DSA 方向相关状态。
- `NF_FF_ORIGINAL_OFFLOAD` / `NF_FF_REPLY_OFFLOAD`：记录方向化硬件 offload 状态。
- `NF_FF_ORIGINAL` / `NF_FF_REPLY`：方向标记。
- `NF_FF_ORIGINAL_OK` / `NF_FF_REPLY_OK`：对应方向路由学习完成。
- `NF_FF_ORIGINAL_CHECK` / `NF_FF_REPLY_CHECK`：对应方向已经检查过。
- `NF_FF_FAIL`：fastnat/offload 失败，配合 `NF_FF_RETRY` 约 8 秒周期重试；源码没有单独的 `ORIGINAL_FAIL/REPLY_FAIL` 常量。
- `NF_FF_BRIDGE` / `NF_FF_ROUTE`：桥转发/路由转发判断。
- `NF_FF_QOS_TESTED` / `NF_FF_TOKEN_CTRL`：QoS 已测试/需要 token 控制。
- `NF_FF_FORCE_FASTNAT`：强制 fastnat 相关标记。
- `NF_FF_USER_USE`：用户认证模块正在占用该流，fast path 必须暂停。
- `NF_FF_URLLOGGER_USE`：URL logger 正在等待解析/记录，fast path 必须暂停。
- `NF_FF_IFNAME_MATCH`：ifname group 过滤已检查。
- `NF_FF_DPI_USE`：预留给 DPI consumer，表示 DPI 正在等待 terminal 结果，fast path 必须暂停。
- `NF_FF_BUSY_USE = NF_FF_USER_USE | NF_FF_URLLOGGER_USE | NF_FF_DPI_USE`。

### 10.3 conntrack status 位

Natflow 复用 `ct->status` 的高位和扩展位：

- `IPS_NATFLOW_MASTER`：bit 31。
- `IPS_NATCAP_SESSION`：bit 30。
- `IPS_NATFLOW_SESSION`：bit 29，表示 conntrack 已挂载 natflow 会话扩展。
- `IPS_NATFLOW_USER`：bit 16，表示 fakeuser conntrack。
- `IPS_NATFLOW_USER_TOKEN_CTRL`：bit 17，用在 fakeuser 上表示用户级限速。
- `IPS_NATFLOW_CT_DROP`：bit 17，用在普通 ct 上表示该连接应丢弃；与上一个宏同 bit，不同上下文使用。
- `IPS_NATFLOW_USER_BYPASS`：bit 15。
- `IPS_NATFLOW_FF_STOP`：bit 18，永久停止该 ct 的 fast path。
- `IPS_NATFLOW_URLLOGGER_HANDLED`：bit 19，legacy URL consumer one-shot 标记。
- `IPS_NATFLOW_SKIP_BRIDGE`：bit 20，用于 bridge/non-bridge 双 hook 去重。
- `IPS_NATFLOW_L7_DPI_HANDLED`：bit 21，L7 DPI host consumer one-shot 标记。
- NATCAP 相关位保留用于兼容。

AI 重建时必须注意 bit 17 在 fakeuser 和普通 ct 上语义不同，不能简单合并成一个枚举。

### 10.4 `natflow_fastnat_node_t`

fastnat 哈希表节点，cacheline 对齐，保存：

- `outdev`、`ifindex`：出口设备和入口 ifindex 校验。
- `jiffies`、`magic`、`status`：老化、版本、并发状态。
- `vlan_present/proto/tci`。
- `flags`：`FASTNAT_EXT_HWNAT_FLAG`、`FASTNAT_PPPOE_FLAG`、`FASTNAT_NO_ARP`、`FASTNAT_BRIDGE_FWD`、`FASTNAT_PROTO_TCP`、`FASTNAT_PROTO_UDP`、`FASTNAT_L3NUM_IPV6`。
- `l2_head`、`l2_head_len`、`l2_fast_fwd`、`l3_fast_fwd`。
- 原始 tuple、NAT 后 tuple、IPv6 地址。
- `mac_source`、`mac_dest`、PPPoE SID、MSS。
- `flow_bytes/packets`、`speed_bytes/packets`、硬件 offload keepalive 信息。
- `user` 指针，用于用户统计和 token 关联。

表大小：

- `natflow_fast_nat_table` 只在 `CONFIG_NETFILTER_INGRESS` 下分配；未定义该宏时，path 仍注册 IPv4/IPv6 PRE_ROUTING 和 POST_ROUTING hook（以及 bridge PRE_ROUTING 兼容 hook），但没有软件 fastnat 表和实际 vline/relay 数据面。
- MT7988/MT7986/MT7981 且启用相关 offload：`16384`，`4-way` 相邻槽探测。
- x86/x86_64：`16384`，`4-way` 相邻槽探测。
- 其他常见 64 位/ARM/ARM64：`8192`，`2-way` 相邻槽探测。
- ATH79/MT7620 等资源较小平台：`4096`，`2-way` 相邻槽探测。

hash 和冲突模型：

- IPv4 hash 输入为源 IP、目的 IP、源端口、目的端口；IPv6 hash 输入为源/目的 IPv6 地址 4 个 32 位分片和端口。
- hash 结果会左移 1 位或 2 位，使低位预留给相邻槽探测；因此逻辑 bucket 数量是 `NATFLOW_FASTNAT_TABLE_SIZE / NATFLOW_FASTNAT_TABLE_WAYS`。
- 2-way 平台最多检查 `base`、`base + 1`；4-way 平台最多检查 `base` 到 `base + 3`。
- 冲突处理不是链表、开放寻址全表探测或动态扩容；只能在固定相邻窗口中使用空槽、过期槽或同 tuple 槽。
- 若固定窗口内都是未过期且不同 tuple 的节点，该方向不能写入 fastnat 表；双向流要求 original/reply 两个方向都获得可用节点。
- `natflow_offload_keepalive()` 和硬件 offload 路径用保存的 hash 回查节点，因此 hash/way 语义是软件 fast path 与硬件 offload 的共享契约。

超时：

- `NATFLOW_FF_TIMEOUT_HIGH = 30s`。
- `NATFLOW_FF_TIMEOUT_LOW = 25s`。
- `NATFLOW_FF_SAMPLE_TIME = 2s`。

### 10.5 fakeuser 与认证数据

fakeuser 不是普通用户态对象，而是特殊 conntrack：

- IPv4 fakeuser tuple：源地址为用户 IP，目标地址为 `NATFLOW_FAKEUSER_DADDR`，UDP 源端口 0、目标端口 65535。
- IPv6 fakeuser tuple：源地址为用户 IPv6，目标地址以前缀 `ffff::` 形式构造。
- fakeuser 扩展尾部挂 `fakeuser_data_t`，保存 MAC、认证状态、规则 id、vline LAN 侧标志、速度窗口、token ctrl 等。
- fakeuser 生命周期依赖 conntrack timeout；默认无流超时 1800 秒。
- `NATFLOW_FAKEUSER_DADDR` 定义为 `htonl(0x7fffffff)`；实现注释把它作为 fakeuser 专用目的地址，不应与真实业务 tuple 混用。

认证状态：

- `AUTH_NONE`
- `AUTH_OK`
- `AUTH_BYPASS`
- `AUTH_REQ`
- `AUTH_NOAUTH`
- `AUTH_VIP`
- `AUTH_BLOCK`
- `AUTH_UNKNOWN`

认证类型：

- `AUTH_TYPE_UNKNOWN = 0`
- `AUTH_TYPE_AUTO = 1`
- `AUTH_TYPE_WEB = 2`

### 10.6 URL store 数据

`urlinfo` 保存：

- `timestamp`：以 uptime 秒为基准。
- 源/目标 IPv4 或 IPv6、端口。
- MAC。
- flags：hostname 来源协议 HTTP/HTTPS/QUIC、IPv6。
- HTTP method：NONE/GET/POST/HEAD。
- `hits`：合并命中次数。
- `acl_idx`、`acl_action`。
- 可变长 `data`：HTTP host+URI、TCP TLS SNI 或 QUIC Initial SNI。

同一时间窗口内相同 tuple/dport/data/flags/method 会合并，超过内存/数量限制时驱逐最老记录。
`timestamp` 使用 `(jiffies - INITIAL_JIFFIES) / HZ`，不是 Unix epoch；用户态若要转换为墙钟时间，需要结合系统 uptime。

## 11. conntrack 扩展和会话初始化

`natflow_session_init()` 在未确认 conntrack 上挂载 natflow 会话扩展：

1. 使用 `IPS_NATFLOW_SESSION_BIT` 防止重复初始化。
2. 确保 NAT 扩展存在。
3. 探测/使用固定扩展偏移，把 `nat_key_t` 和 `natflow_t` 放在 conntrack ext 尾部。
4. 兼容 NATCAP：若已存在 NATCAP key，则在 NATCAP 后追加 natflow key；否则写入 natflow key。
5. 设置 `natflow_off`，并写入共享 key 的 `NATCAP_MAGIC`、`len` 和 `ext_magic = (unsigned long)ct & 0xffffffff`。

硬约束：

- 代码依赖 `krealloc()` shrink 行为和当前内核分配器实现。源码明确说明在 KASAN、SLUB debug、redzone、poisoning 或对象移动语义下存在风险。
- `ct->ext->len` 超过 `NATCAP_MAX_OFF = 512` 不支持。
- `natflow_session_get()` 会校验 status bit、ext、magic、ext_magic 和 offset；任何不匹配均视为无 natflow 会话。
- `static_fixed_ext_off` 会在 `natflow_probe_ct_ext()` 中通过构造临时 conntrack 并添加所有扩展来探测；探测失败时使用默认 `256 / NATCAP_FACTOR`。
- `natflow_ct_ext_layout_validate()` 会验证 `NF_FF_DPI_USE_BIT=21`、`NF_FF_BUSY_USE` 包含 DPI bit、`nat_key_t` 偏移不超过 `NATCAP_MAX_OFF`、`natflow_off` 可放入 `nat_key_t` 的 16 位字段，并确认 `natflow_t` 的对齐后长度覆盖新增 `app_id`。

AI 重建实现时必须显式处理 conntrack ext 内存布局，不能把 `natflow_t` 放进独立哈希表后声称兼容。

### 11.1 NAT 改写和校验和契约

`natflow_path.h` 提供 fast path 使用的内联改写函数：

- IPv4 SNAT/DNAT 会同时改写 IP 地址、TCP/UDP 端口、IPv4 header checksum 和 L4 checksum。
- IPv6 SNAT/DNAT 不存在 IPv6 header checksum，只逐个 32 位分片更新 TCP/UDP pseudo-header checksum，再改写地址。
- UDP checksum 为 0 且 skb 不是 `CHECKSUM_PARTIAL` 时不会强制计算；若更新后 checksum 为 0，会写 `CSUM_MANGLED_0`。
- IPv6 分支只按固定 IPv6 header 后的 TCP/UDP 头计算，不解析 extension header。
- 非 TCP/UDP 返回失败或跳过，因此 fast path 建表和命中都围绕 TCP/UDP。

## 12. fast path 算法

### 12.1 学习阶段

慢路径包经过 POST_ROUTING 后，`natflow_path_post_ct_out_hook()`：

1. 获取 conntrack 和 `natflow_t`。
2. 按当前包方向确定要学习的反向/正向 route。
3. 从 `skb_dst()` 得到 MTU。
4. 从 skb 和出口设备提取二层头、VLAN、PPPoE、出口设备、ifname group、TTL/hop-limit。
5. 比较保存的 `ttl_in` 和当前 TTL/hop-limit，判断桥转发还是路由转发。
6. 如果 conntrack 有 helper，设置 `IPS_NATFLOW_FF_STOP`。

学习会跳过不适合 fast path 的设备或协议，例如不运行/无 carrier、bridge/ovs/bond/macvlan、部分 PPP/PPPoE 或无法可靠构造 L2 头的路径。

### 12.2 命中阶段

`natflow_path_pre_ct_in_hook()` 在 ingress 或 PRE_ROUTING：

1. 如果 `disabled=1`，直接 accept。
2. 若是 netdev ingress，先处理硬件 offload 命中标记。
3. 识别并临时剥离 PPPoE session 头。
4. IPv4/IPv6 基本校验：
   - 必须是 TCP 或 UDP。
   - IPv4 必须头合法、非分片、非组播/广播、校验正确。
   - ingress IPv4 会按 `iph->tot_len` 用 `pskb_trim_rcsum()` 截掉二层 padding/trailer；后续回慢路径采样不会恢复原始尾部字节。
   - IPv6 只直接支持 `nexthdr` 为 TCP/UDP；不解析扩展头。
   - 跳过已有 nfct 的包。
   - 处理线性/非线性/GSO 限制。
5. 按 tuple 计算 hash，检查主 slot、碰撞 slot，部分 MTK 平台额外检查更多 slot。
6. 校验 `magic`、tuple、协议、入口 ifindex、超时和 TCP 状态。
7. 命中后更新统计、TTL/hop-limit、NAT 地址/端口、L4 checksum、L2/VLAN/PPPoE 头。
8. 必要时做 GSO 分段或校验 offload 处理。
9. `dev_queue_xmit()` 并返回 `NF_STOLEN`。

命中会周期性回慢路径：

- fastnat 节点超过 `NATFLOW_FF_SAMPLE_TIME = 2s` 会尝试保活/采样。
- 每 256 个包中某些包会回慢路径刷新 acct 和状态。
- TCP FIN/RST 会使双向节点快速过期并回慢路径。

### 12.3 建表阶段

在慢路径包中，如果满足条件，path 会建立双向 fastnat 节点：

1. conntrack 已 confirmed。
2. 未设置 `IPS_NATFLOW_FF_STOP`。
3. `nf->status` 未包含 `NF_FF_BUSY_USE`。
4. TCP 必须 established；UDP 可建表。
5. 双向 route 都已经 `OK` 且 magic 匹配。
6. 未触发 `delay_pkts`、PMTU、TTL、QoS、ifname group、用户认证等阻断条件。
7. 根据 conntrack NAT 状态构造原始 tuple 和 NAT tuple。
8. 保存出口设备、入口 ifindex、MTU/MSS、L2 头、VLAN/PPPoE、bridge/noarp 标志。
9. 计算 `l3_fast_fwd` 和 `l2_fast_fwd`：
   - 无 NAT 时可 L3 fast forward。
   - 双向 MAC 和 flags 可逆且一致时可 L2 fast forward。
10. 尝试硬件 offload；失败则设置 fail bit，约 8 秒后重试。

hash 约束：

- IPv4/IPv6 使用各自 inline hash。
- hash 返回值是相邻探测窗口的 base slot；窗口宽度由 `NATFLOW_FASTNAT_TABLE_WAYS` 决定。
- MT7621 平台 `natflow_hash_skip()` 会跳过特定 bucket：`12,25,38,51,76,89,102` modulo 128。
- 发生冲突时最多使用有限备用 slot；不能动态扩容。

### 12.4 硬件 offload

在 MTK/Ralink 分支中，path 会基于设备的 `ndo_flow_offload` 或外部设备 offload API 下发流：

- 支持原始/回复方向不同设备组合。
- 支持 VLAN、PPPoE、DSA、bridge、WED 标志。
- `hwnat` 总开关控制是否尝试。
- `hwnat_wed_disabled` 控制 WED 使用。
- `CONFIG_HWNAT_EXTDEV_DISABLED` 会禁用部分外部设备路径。
- 硬件 offload keepalive 会回写流量并延长 conntrack timeout。

硬件 offload 是可选增强；软件 fast path 必须在没有硬件能力时仍可工作。

## 13. 用户认证算法

### 13.1 PRE_ROUTING

`natflow_user_pre_hook()`：

1. 只处理原始方向新连接相关包。
2. 判断入接口或 bridge physdev 是否为 LAN zone。
3. 跳过特殊源地址和已 bypass 流。
4. 根据 `auth_conf` 规则匹配：
   - `src_zone_id` 必须匹配。
   - 源 IP 必须命中 `sipgrp` ipset。
   - `auto` 类型直接进入 `AUTH_OK`。
   - `web` 类型默认 `AUTH_REQ`，若 IP/MAC 白名单命中则 `AUTH_VIP`。
5. 创建/更新 fakeuser，记录 MAC、规则、认证状态；普通活动 timestamp 最多每 32 秒刷新一次，`IP_CT_NEW` 新连接包距离上次刷新超过 2 秒也会刷新。
6. 触发 userinfo event。
7. 若开启 `https_redirect_en`，对 TCP 443 且未命中旁路名单的连接 DNAT 到本机地址和 `https_redirect_port`，并设置 bypass bit。

### 13.2 FORWARD

`natflow_user_forward_hook()`：

1. 若普通 ct 已有 `IPS_NATFLOW_CT_DROP`，丢弃。
2. 找到/创建 fakeuser，并关联到普通 ct 的 `master` 链；GRE 因 double free 风险被特殊跳过。
3. 初始化 `natflow_t`。
4. 首次匹配 QoS，设置 `qos_id` 和 `NF_FF_TOKEN_CTRL`。
5. 根据 fakeuser 认证状态处理：
   - `AUTH_REQ + WEB`：允许 DNS/DHCP/旁路名单；非 TCP 丢弃；HTTP GET/POST 生成 302；其他数据丢弃；裸 ACK 转 RST。生成 302 响应时，采用静态预格式化模板并使用 `skb_copy_expand` 进行 payload 注入，避免运行时大块内存动态分配。
   - `AUTH_REQ + AUTO`：转为 `AUTH_OK`。
   - `AUTH_OK`：可处理 WeChat 自动 portal 特例。
   - `AUTH_VIP` / `AUTH_BYPASS`：设置 bypass。
   - `AUTH_BLOCK`：设置 `IPS_NATFLOW_CT_DROP` 并丢弃。
6. 认证流程占用流时设置 `NF_FF_USER_USE`，阻止 fast path 提前接管。

### 13.3 POST_ROUTING

`natflow_user_post_hook()`：

1. 更新 fakeuser rx/tx 包数和字节数。
2. 更新速度窗口。
3. 执行用户级 token ctrl 或 QoS token ctrl。
4. 使用 `IPS_NATFLOW_SKIP_BRIDGE` 避免 bridge 与非 bridge hook 双计数。

## 14. QoS 算法

匹配方向：

- 先判断包与 fakeuser 的方向关系。
- 用户侧地址/端口与 `user/user_port` 匹配。
- 对端地址/端口与 `remote/remote_port` 匹配。
- 协议字段为 tcp/udp/通配。

匹配类型：

- 精确 IP。
- CIDR。IPv4 mask 由 prefix 构造；IPv6 prefix 通过规范化地址比较。
- ipset 名称。
- 空字段通配。

token bucket：

- 以 payload 长度扣 token；TCP/UDP 会扣除 L3/L4 头。
- 每个 bucket 有 spinlock、tokens、tokens_per_jiffy、上次 jiffies。
- tokens 不足时根据 elapsed jiffies 补充，补充窗口有上限。
- 返回负值表示超过速率，包会被丢弃。

classid 模式：

- 不丢包。
- 只写 `skb->mark`，交给 tc 处理。

## 15. URL logger 和 host ACL 算法

### 15.1 hook 范围

默认注册：

- IPv4 `NF_INET_FORWARD`，priority `NF_IP_PRI_FILTER + 5`。
- IPv6 `NF_INET_FORWARD`，priority `NF_IP_PRI_FILTER + 5`。
- bridge `NF_INET_FORWARD`，priority `NF_IP_PRI_FILTER + 5`。

若 `CONFIG_NATFLOW_URLLOGGER_LOCAL_IN`：

- 只注册 IPv4 `NF_INET_LOCAL_IN`，priority `NF_IP_PRI_FILTER + 5`。

### 15.2 解析流程

1. 若 URL consumer 和 DPI host consumer 都未激活，则直接 accept；`/proc/sys/urllogger_store/enable=1` 激活 URL/HostACL consumer，DPI `enable=1` 且存在 domain rule 激活 DPI host consumer。
2. 跳过已设置 `IPS_NATFLOW_CT_DROP` 的连接。
3. 只处理 original 方向，且至少有一个 active consumer 未设置对应 handled bit：URL consumer 使用 `IPS_NATFLOW_URLLOGGER_HANDLED`，DPI host consumer 使用 `IPS_NATFLOW_L7_DPI_HANDLED`。
4. 设置 `NF_FF_URLLOGGER_USE` 暂停 fast path。
5. 解析 HTTP：
   - 方法只识别 `GET `、`POST `、`HEAD `。
   - URI 必须以 `/` 开头。
   - 查找 `Host:` 头。
   - 记录 host + URI。
   - 不识别 absolute-form URI、CONNECT、HTTP/2 cleartext 或其他 HTTP 方法。
   - 会剥离合法十进制 `:port`，但不支持 IPv6 literal Host，不做 IDNA/punycode 转换。
6. 解析 TLS SNI：
   - 解析 TLS ClientHello extension type 0。
   - 使用 per-CPU SNI cache 拼接跨包数据。仅缓存纯 payload 数据而非原始 skb，以避免复杂的 ownership/destructor 问题和降低内存占用。
   - 单条追加数据小于 32KB。
   - cache 每 CPU 64 个节点，超时 4 秒。attach 新节点时会在遍历过程中主动清理过期节点（cache eviction），避免被过期节点耗尽。
   - TLS record 长度不足但已确认 handshake type 是 ClientHello 时，会继续在已收到字节中探测；若可确认 handshake type 不是 ClientHello，则返回非 ClientHello。
   - TCP SNI cache 只接受按 TCP sequence 连续追加的数据，不做乱序重组。
   - 不支持一个 TLS ClientHello handshake message 横跨多个 TLS record 的完整语义重组。
7. 解析 QUIC SNI：
   - 只处理 UDP/443 QUIC v1 Initial。
   - 只识别 QUIC long header Initial，要求 fixed bit 置位，version 为 `0x00000001`，DCID 长度为 1..20。
   - 使用 QUIC v1 Initial salt 派生 client initial secret，并依赖内核 crypto 的 `hmac(sha256)`、`ecb(aes)` header protection 和 `gcm(aes)` payload 解密。
   - 解密 Initial payload 后解析 CRYPTO frame 中的 TLS ClientHello SNI。
   - 使用 per-CPU QUIC cache 缓存连续 CRYPTO stream 数据。
   - CRYPTO stream 只缓存从 offset 0 开始的连续前缀；offset 大于当前连续长度的片段不会作为稀疏片段保存。
   - 只处理当前 UDP datagram 中解析出的第一个 QUIC packet，不遍历 coalesced datagram 中后续 packet。
   - packet number reconstruction 简化为把解保护后的截断 packet number 当完整 packet number 使用，适合常见首包，不覆盖所有 Initial 重传/高 packet number 场景。
   - QUIC frame parser 只跳过 PADDING、PING、ACK/ACK_ECN，并解析 CRYPTO；遇到其他 frame 会结束本次 SNI 探测。
   - QUIC crypto 上下文按 CPU 分配，并把 key/iv/header-protection key/mask/nonce、HKDF scratch 和 shash desc 缓冲放在 `urllogger_quic_crypto_ctx` 中，避免在 `CONFIG_VMAP_STACK` 内核上把栈地址传给 scatterlist/crypto API，同时降低包处理路径栈占用。
   - 不解析 HTTP/3 `:authority` 或 path，不支持 ECH 内层真实 SNI。
   - QUIC crypto 初始化失败时，URL logger 仍可加载，但 QUIC hostname parser 被禁用。
8. 命中 host 后按 active consumer fan-out：URL consumer 执行 URL CSV 和 Host ACL，正常路径复用 URL record；若 URL record 分配失败，则退到最小 ACL view 尽量执行 ACL，但不会生成对应 `/dev/urllogger_queue` 记录。DPI host consumer 调用 domain classifier，写入 `app_id` 并输出 match event；DPI-only 时不创建 URL record、不执行 Host ACL。
9. 处理完成后分别设置 active consumer 的 handled bit。
10. URL logger 不会因为固定域名命中而自动添加任何全局 ipset；host ACL 只测试 `host_acl_rule<id>_ipv4/ipv6/mac` 这类用户态配置的过滤集合。

实现边界：

- `natflow_l7_copy_host_tolower()` 是 L7 共享 hostname normalize/validate 层；HTTP Host 解析已由 `natflow_l7_http_parse()` 产出共享 feature，TLS ClientHello/SNI 搜索已迁移到 `natflow_l7_tls_*()`，QUIC Initial header、CRYPTO frame 拼接和 SNI 搜索已迁移到 `natflow_l7_quic_*()`，DNS query 第一问 QNAME 由 `natflow_l7_dns_parse()` 产出共享 feature；QUIC AES/HKDF crypto context 和分片 cache 的初始化/清理仍由 legacy URL logger 持有，以保持 crypto 初始化失败只禁用 QUIC hostname parser、不导致 URL logger 初始化失败的旧语义。ASCII 大写转小写，去除末尾 root dot；HTTP Host 允许并剥离合法十进制 `:port`；总长度限制为 1..253，单 label 限制为 1..63，只允许 `[a-z0-9.-]`，拒绝空 label、label 开头或结尾的 `-`、NUL、控制字符、空白、逗号、冒号等非 DNS hostname 字节。
- URL 记录创建前会先完成 hostname/URI 校验，并限制 `normalized_host + uri + NUL <= URLLOGGER_DATALEN`，避免按畸形输入长度做过大的 `GFP_ATOMIC` 分配。
- Host ACL 失败路径使用 `urllogger_acl_lookup` 栈上视图复用同一 hostname normalize 规则，不依赖 URL store record 分配成功。
- TLS/QUIC SNI server_name type 0 的内容会按 DNS hostname 规则校验后使用；严格校验会拒绝包含 `_`、非 ASCII U-label、通配符、IPv6 literal 或其他非标准 DNS hostname 的输入。
- HTTP Host、TLS SNI、QUIC SNI 的识别是审计和粗粒度 ACL 能力，不是不可绕过的 WAF/域名防火墙边界。
- PPPoE bridge 场景下，L7 URL common path 临时剥离 PPPoE header 后构造 packet view，并在 consumer 返回后统一恢复 PPPoE header、`skb->protocol` 和 `network_header`；URL consumer 中等待更多 TLS/QUIC 数据、drop、reset、redirect 或错误路径都必须返回到该 L7 common path。

### 15.3 host ACL

匹配：

- host ACL 规则按 rule id 保存为追加式字符串表；控制面新增/清空会构造新 buffer 并用 RCU 发布，旧 buffer 在 grace period 后释放。
- `hostacl` 读写侧由 `acl_rule_lock` 串行化；URL hook 数据面在 RCU read-side 临界区内读取当前规则 buffer。
- 流量中的 host 会在 `urlinfo_copy_host_tolower()` 中转小写并校验；`hostacl_ctl` 写入的 `<host>` 规则则按原始输入保存，不做大小写转换，因此用户态应写入小写 DNS hostname。
- 先匹配完整 host，再逐级匹配点后的后缀。
- 每条规则前一个 marker 字节保存 action 和 rule id。
- 可结合 `host_acl_rule<id>_ipv4/ipv6/mac` 限制源 IP/MAC。

动作：

- `accept`/0：记录并放行。
- `drop`/1：设置 `IPS_NATFLOW_CT_DROP` 并 drop。
- `reset`/2：TCP 路径发送/改写 RST 并设置 drop 状态；UDP/QUIC 路径没有 RST 等价实现，按非 record 动作丢弃。
- `redirect`/3：若为 HTTP GET/POST 请求则返回 302 重定向到配置的 `redirect_url`（可通过 `redirect_url=...` 写入 /dev/hostacl_ctl）；对于 HTTPS 或 QUIC 则退化为 TCP Reset 或 Drop 丢弃。

### 15.4 DPI domain/proto MVP

`CONFIG_NATFLOW_DPI` 当前启用默认关闭的控制面、domain exact/suffix ruleset、DNS QNAME domain 分类、DNS/SSH/WireGuard/STUN/TURN/BitTorrent protocol-only ruleset、source counters 和 match event 队列：

- `/dev/natflow_dpi_ctl` 使用 seq_file 输出状态，支持 `enable=0|1`、`enable`、`disable`、`rules_begin`、`domain id=<rule_id> app=<app_id> kind=exact|suffix host=<host>`、`proto id=<rule_id> app=<app_id> proto=dns|ssh|wireguard|stun|turn|bittorrent`、`rules_commit`、`rules_abort`、`rules_clear` 和 `events_clear`。
- `rules_begin` 分配 pending ruleset，`domain ...` 和 `proto ...` 只能在事务中写入；`rules_commit` 用 RCU 原子发布完整 ruleset 并递增 generation；`rules_abort` 丢弃 pending；`rules_clear` 发布空 ruleset。
- `events_clear` 清空 `/dev/natflow_dpi_queue` 中已排队事件，并把 `events`、`events_lost`、`events_*` source counters 和 `proto_*` reason counters 归零；不改变 enable 状态、ruleset 或 generation。持续流量下可能立刻产生新事件，单项测试前应先暂停流量或临时禁用 DPI。
- 单个 ruleset 当前最多 128 条 domain 规则和 32 条 proto 规则。`id` 和 `app` 必须非 0，同一事务内 `id` 不能重复；`host` 会转小写、去掉末尾点，并校验 DNS label；`kind=suffix` 匹配完全相同 host 或带点边界的子域名。
- `proto` 当前支持 `dns`、`ssh`、`wireguard`/`wg`、`stun`、`turn`、`bittorrent`/`bt`。
- DNS QNAME detector 在 original direction 的 TCP/UDP 53 标准 query 中解析第一问 QNAME，忽略 response、非 query opcode、压缩 QNAME、畸形或前缀不足的报文；QNAME 经过同一 hostname normalize 后进入 domain exact/suffix ruleset，命中事件 source 为 DNS。
- 端口型 protocol-only detector 当前按 original direction 的目标端口识别：DNS TCP/UDP 53，SSH TCP 22，WireGuard UDP 51820。
- 有界 payload detector 当前覆盖 TCP original direction 的 SSH banner `SSH-<version>-` identification string、STUN/TURN header、length 和 magic cookie，按 TURN 方法区分 TURN；BitTorrent 的 TCP 分支覆盖标准 handshake，UDP 分支覆盖 uTP v1 header 和 DHT bencode token 前缀窗口，其中 uTP 会校验版本、类型和扩展号。IPv6 detector 当前只处理无 extension header 的 TCP/UDP。
- DPI 默认 `disabled`。`enable=1` 后，HTTP/TLS/QUIC host 分类仍来自 legacy URL logger parser，因此需要同时编译 `CONFIG_NATFLOW_URLLOGGER`；但 L7 DPI host consumer 由 DPI enable 和 domain rule 独立激活，不再要求 `/proc/sys/urllogger_store/enable=1`。DNS QNAME domain 分类和 protocol-only detector 由 `natflow_dpi.c` 自己的 IPv4、IPv6、bridge FORWARD hook 处理，优先级 `NF_IP_PRI_FILTER + 6`。DPI hook 在存在任意 DPI 规则时运行；非 DNS payload detector 只在存在 proto 规则时执行。
- `natflow_l7` 已有 `NATFLOW_L7_CONSUMER_URL/DPI` mask 和 URL dispatcher；active mask 按 `/proc/sys/urllogger_store/enable` 发布 URL consumer，按 `natflow_dpi_host_consumer_enabled()` 发布 DPI host consumer。当前不把 DPI protocol-only hook 合并进 L7 URL common path，也不让其受 `/proc/sys/urllogger_store/enable` 控制；后续只有在 L7 拥有完整 dispatcher、consumer mask 和 DPI context 生命周期后，再评审是否合并 hook 入口。
- `natflow_urllogger.c` 在 HTTP Host、TCP TLS SNI、QUIC v1 Initial SNI normalize 成功后调用 `natflow_dpi_classify_host()`；URL record 分配失败时也会通过 `urllogger_acl_lookup` 的最小 host 视图调用 DPI。DNS QNAME 则由 DPI hook 直接解析并调用同一 domain classifier。Host ACL 行为和 `/dev/urllogger_queue` CSV 输出不因 DPI 改变。
- domain 命中时，如果当前 conntrack 已有 natflow session，则写入 `natflow_t.app_id`；不会为了 DPI 创建 session。无 session 时仍可输出 match event。protocol-only 命中要求已有 natflow session 且 `app_id==0`，用于避免每包重复事件。
- `/dev/natflow_dpi_queue` 输出固定头二进制事件；队列为空时 `read()` 返回 0，用户 buffer 小于固定头时返回 `-EINVAL`，`poll()` 在有事件时返回 readable。队列最多缓存 1024 条事件，溢出或分配失败增加 `events_lost`。
- `/dev/natflow_dpi_ctl` status 输出 `events_*` source counters，按 HTTP/TLS/QUIC/DNS/SSH/WireGuard/STUN/TURN/BitTorrent 统计 match event；同时输出 `proto_no_session`、`proto_app_exists` 和 `proto_no_rule`，用于解释 protocol-only detector 已识别但未产生 match event 的原因。
- 固定事件头为 packed `struct natflow_dpi_event_hdr`，`version=1`，包含 `header_len`、`record_len`、`reason`、`generation`、`app_id`、`category_id`、`rule_id`、`flags` 和 `timestamp`。当前 match event 使用 `reason=6`，`category_id=0`，`flags` 表示来源：1=HTTP、2=TLS、3=QUIC、4=DNS、5=SSH、6=WireGuard、7=STUN、8=TURN、9=BitTorrent，`timestamp` 为 `ktime_get_ns()`。
- 当前不会执行 drop/reset/QoS，不覆盖认证、Host ACL 或 conntrack drop 结果；未命中、禁用、无 parser、无 session 或事件队列丢失都 fail-open。

## 16. Zone 设计

zone 元数据编码在 `net_device->name[IFNAMSIZ - 1]` 的隐藏字节：

- zone id 使用低位 mask。
- zone type 使用额外 bit。
- `INVALID_ZONE_ID = 127`。
- `MAX_ZONE_ID = 126`。

约束：

- 只有当可见设备名长度满足 `strlen(name) + 2 <= IFNAMSIZ` 时才能写隐藏字节，否则设置失败并视为 invalid。
- 修改 `dev->name[IFNAMSIZ - 1]` 是强假设：依赖内核设备名数组尾部未用于可见字符串。
- zone 规则列表不做同类型去重；后添加的同类型规则可能与前面规则接口匹配重叠，匹配函数按链表顺序应用。不同类型不能复用同一个 zone id。
- 设备 `NETDEV_UP` 时重新匹配当前设备。

## 17. vline/relay 设计

vline/relay 是 path 模块的一部分，并且实际转发路径依赖 `CONFIG_NETFILTER_INGRESS`。

### 17.1 配置和运行状态

常量：

- `VLINE_FWD_MAX_NUM = 64`。
- `VLINE_FWD_MAP_CONFIG_NUM = 8`。

状态：

- `vline_fwd_map[ifindex] -> outdev` 是运行时 RCU 映射。
- 配置数组保存最多 8 条 `<src,dst,family>`。
- family 为 `ipv4`、`ipv6`、`all`，relay 通过 high bit 标记。

标志复用：

- `net_device->flags` 高位被复用为内部标志：
  - `IFF_PPPOE`
  - `IFF_IFNAME_GROUP`
  - `IFF_VLINE_L2_PORT`
  - `IFF_VLINE_FAMILY_IPV4`
  - `IFF_VLINE_FAMILY_IPV6`
  - `IFF_VLINE_IS_LAN`
  - `IFF_VLINE_RELAY`

### 17.2 配置限制

- endpoint 必须在 `init_net`。
- endpoint 可见接口名最多 15 字节。
- 命名 endpoint 不能已有 master upper dev。
- 如果任一命名 endpoint 是 `IFF_NOARP`，family 必须是 `ipv6`。
- src 不能是 `IFF_NOARP`。
- relay dst 不能是 `IFF_NOARP`。
- 运行映射以入口 `ifindex` 为 key，入口 ifindex 必须 `< 64`。
- 配置不是事务性的；中途失败可能留下部分映射或 flags。
- 没有重复配置和冲突检测。
- `NETDEV_CHANGEUPPER` 只触发有限更新。

### 17.3 IPv4 行为

过滤：

- 若存在 vline 过滤 ipset，会按目标 netport、目标 IP、源 IP、源 MAC 过滤。

relay：

- DHCP UDP dst 67 只有在 IPv4/UDP header 和 BOOTP flags 字段都位于 `iph->tot_len`/`skb->len` 范围内且可写时，才会把 flags 从 `0x0000` 改为 `0x8000` 并更新 checksum；短包或布局不完整时跳过改写。
- ARP relay 只处理 Ethernet/IPv4 ARP 且固定字段布局完整的包。
- ARP 会学习 sender fakeuser 和 vline LAN 侧。
- ARP reply 会用 fakeuser MAC 改写 target/dest。
- 广播/组播/ARP 通常 clone 一份发往 outdev，原包继续。
- 单播要求目标 fakeuser 存在且在对侧，否则不 relay。

plain vline：

- 广播/组播/ARP clone 到 outdev。
- 目标 MAC 是本地则回慢路径。
- 其他包标记 bridge/MTU、confirm skb、推二层头并发送。

### 17.4 IPv6 行为

过滤：

- 使用 `vline_filter6_*` ipset 和 `vline_filter_src_mac`。

relay：

- ND 包会学习源 IPv6/MAC 到 fakeuser。
- ND option 中的 link-layer address 会改写为 outdev MAC，并重算 ICMPv6 checksum。
- 单播要求目标 fakeuser 存在且在对侧。

plain vline：

- 支持 NOARP 到 Ethernet、Ethernet 到 NOARP 的特殊转换。
- Link-local、ND、组播、非 ND ICMPv6 都有分支处理。
- 对 LAN 侧且目标属于 outdev 非 link-local prefix 的包会回路由路径。
- 非 ND ICMPv6 可触发 conntrack。

## 18. Netfilter hook 规格

user hooks：

| hook | family | priority |
| --- | --- | --- |
| PRE_ROUTING | IPv4/IPv6/bridge | `NF_IP_PRI_NAT_DST - 10 + 1` |
| FORWARD | IPv4/IPv6/bridge | `NF_IP_PRI_FILTER` |
| POST_ROUTING | IPv4/IPv6/bridge | `NF_IP_PRI_NAT_SRC + 10` |

path hooks：

| hook | family | priority |
| --- | --- | --- |
| POST_ROUTING | IPv4/IPv6/bridge | `NF_IP_PRI_LAST - 10 + 8` |
| PRE_ROUTING | IPv4/IPv6 | `NF_IP_PRI_CONNTRACK + 1` |
| PRE_ROUTING | bridge | `NF_IP_PRI_CONNTRACK + 1`，仅无 ingress 时 |
| NETDEV_INGRESS | per net_device | `9`，仅 `CONFIG_NETFILTER_INGRESS` |

urllogger hooks：

| hook | family | priority |
| --- | --- | --- |
| FORWARD | IPv4/IPv6/bridge | `NF_IP_PRI_FILTER + 5` |
| LOCAL_IN | IPv4 | `NF_IP_PRI_FILTER + 5`，仅 `CONFIG_NATFLOW_URLLOGGER_LOCAL_IN` |

顺序含义：

- user PRE 在 DNAT 附近运行，用于认证 HTTPS 重定向。
- path PRE 在 conntrack 后尝试 fast path 或补建 conntrack。
- user FORWARD 在 filter 优先级做认证和 QoS 判断。
- urllogger FORWARD 在 filter 后 5 个优先级解析 URL，并暂停 fast path。
- user POST 做统计/限速，path POST 后置学习最终出口。

## 19. 设备 notifier 行为

zone notifier：

- `NETDEV_UP` 时刷新该设备 zone。

path notifier：

- `NETDEV_UP`：
  - 禁用 GRO/GRO_FRAGLIST。
  - 对合格设备注册 ingress hook。
  - 尝试识别 PPPoE/PPE 设备。
  - 触发 vline ifup 更新。
- `NETDEV_CHANGE`：
  - 更新 PPPoE/PPE 标志和 cache。
- `NETDEV_CHANGEUPPER`：
  - 更新 vline 映射。
- `NETDEV_DOWN`：
  - 从 PPE cache 清理设备。
- `NETDEV_UNREGISTER`：
  - 注销 ingress hook。
  - 停止相关硬件 offload。
  - 清除 vline map 对该设备的引用。
  - 通过工作队列延迟同步和 `dev_put()`。
  - bump path magic。

不适合 ingress hook 的设备包括 loopback、bridge、ovs、bond、macvlan 等；rawip 有例外路径。

## 20. 已知限制和风险

### 20.1 内存和 ABI 强假设

- conntrack ext 布局依赖 `krealloc()` shrink 行为，是明确的低层假设。
- zone 使用 `dev->name[IFNAMSIZ - 1]` 存储隐藏状态。
- vline/ifname group/PPPoE 使用 `net_device->flags` 高位存储私有状态，可能与未来内核或驱动私有 flags 冲突。
- 多数字符设备写入使用静态半行 buffer，多 writer 并发不安全。

### 20.2 解析和输入限制

- 控制命令最大 256 字节且必须换行。
- auth 规则和 bypass ipset 名称使用固定长度缓冲并会截断到 `IPSET_MAXNAMELEN - 1`；当前不会越界写，但过长输入不会显式报错，用户态仍应校验长度。
- QoS set 名称最多 15 字节。
- vline endpoint 名最多 15 字节。
- zone 设备名最多 14 字节。
- IPv6 fast path 不解析扩展头。
- HTTP parser 只识别简单明文请求和 `Host:`。
- TLS SNI parser 只覆盖普通 ClientHello SNI extension，不保证支持所有 TLS 变体、ECH 或分片异常。
- hostname 统一入口会做严格 DNS hostname 校验；因此非标准但现实存在的 Host/SNI 值，例如 `foo_bar.example`、`[2001:db8::1]`、非 ASCII U-label，当前会被丢弃而不是记录或匹配 ACL。
- TLS ClientHello 跨多个 TLS record 的场景当前不能完整支持，恶意客户端可利用异常分片降低识别率。
- QUIC 只覆盖 UDP/443 QUIC v1 Initial 中常见的 CRYPTO/ClientHello SNI；不覆盖 QUIC v2、version negotiation、Retry 后复杂路径、coalesced datagram 后续 packet、稀疏 CRYPTO fragment、HTTP/3 `:authority` 或 ECH 内层域名。
- URL logger 的 `url` 字段会做 CSV escaping；用户态仍必须按 RFC 4180 类 CSV 规则解析字段，并处理过长记录静默丢失、partial read 返回 `-EINVAL` 等兼容性限制。
- plain vline IPv6 Ethernet/NOARP 的 Neighbor Advertisement 构造路径仍直接调整 `skb->len` 并依赖当前 tail/headroom 状态，后续应改为更明确的 skb length/tailroom helper 流程并补充回归测试。

### 20.3 行为限制

- URL logger 只有 `enable=1` 时才处理 host ACL。
- host ACL 的 redirect action 支持配置 `redirect_url` 并通过 HTTP 302 重定向。
- `conntrackinfo_ctl` 的 `kickall` 没有实际清理。
- `userinfo_ctl`、`userinfo_event_ctl`、`urllogger_queue` 对小 buffer 不支持 partial read。
- vline 配置非事务、无冲突检测、运行 ifindex key 小于 64。
- fastnat 哈希表固定大小，冲突处理有限。
- `disabled` 默认值：path 默认为 1，user 默认为 1，URL store 默认为 0；模块加载后需要用户态显式开启相关能力。
- 用户认证默认跳转地址是 `10.10.10.10`，HTTPS redirect 端口默认 443 但开关默认关闭。
- QoS 速率小于 `HZ` 或未配置速率时 token 控制等价于放行。
- README 指出 4.10 之前内核若 ingress hook 缺少 `NF_STOLEN` 支持，需要补丁。

### 20.4 安全边界

- 控制设备没有在代码内做能力检查，实际安全依赖设备节点权限和系统管理策略。
- 过长 auth rule/bypass ipset 名称会被截断，可能导致规则引用错误 ipset；部署时必须由用户态校验长度和精确名称。
- URL/host 解析不能作为强安全 WAF，只能作为流量审计/粗粒度访问控制。
- fast path 绕过大量慢路径检查，因此任何策略模块在未完成处理前必须设置对应 busy bit，例如 `NF_FF_USER_USE`、`NF_FF_URLLOGGER_USE` 或 `NF_FF_DPI_USE`。

## 21. AI 可重建实现契约

若 AI 根据本文生成实现，必须满足以下 MUST/SHOULD 条款。

### 21.1 MUST：模块和接口

- MUST 生成一个 Linux 内核模块 `natflow`，而不是用户态代理。
- MUST 保留 `NATFLOW_VERSION`，默认当前版本为 `1.0.1`。
- MUST 提供本文列出的字符设备和命令。
- MUST 实现 256 字节换行命令协议。
- MUST 通过 netfilter hooks 接入 IPv4、IPv6 和 bridge 路径。
- MUST 通过 conntrack 扩展保存 `natflow_t`，并可从普通 conntrack 找回。
- MUST 使用 `NATCAP_MAGIC`/`nat_key_t` 兼容当前 NATCAP/NATflow 共享扩展布局。
- MUST 保留 fakeuser conntrack 模型，用户状态不得仅存在普通哈希表中。
- MUST 支持 ipset 名称测试，并保留“set 不存在时不同 wrapper 返回值不同”的语义。
- MUST 在策略模块占用连接时设置对应 busy bit，避免 fast path 提前转发。

### 21.2 MUST：fast path

- MUST 先通过慢路径学习双向 route，再建立 fastnat 节点。
- MUST 在 fast path 命中时校验 magic、tuple、协议、入口 ifindex 和超时。
- MUST 正确更新 IPv4 header checksum、TCP/UDP pseudo checksum、NAT 地址/端口、TTL/hop-limit。
- MUST 保留 UDP checksum 0 和 `CSUM_MANGLED_0` 的处理语义。
- MUST 支持 VLAN、PPPoE、桥转发和路由转发区分。
- MUST 在 TCP FIN/RST、超时、采样、硬件 offload keepalive 时回慢路径或过期节点。
- MUST 保留固定大小 fastnat 表和有限碰撞槽行为，除非明确重写数据结构并说明兼容差异。

### 21.3 MUST：认证和 QoS

- MUST 用 zone + ipset 匹配认证规则。
- MUST 支持 `auto` 和 `web` 两类认证。
- MUST 支持 HTTP 302、TCP RST、DNS/DHCP bypass、HTTPS DNAT 重定向。
- MUST 支持用户事件阻塞读。
- MUST 支持用户级 token ctrl 和 QoS 规则级 token ctrl。
- MUST 支持 `tc_classid_mode` 只标记不丢包。

### 21.4 MUST：URL logger

- MUST 在 URL store 关闭时完全旁路。
- MUST 解析 HTTP GET/POST/HEAD 的 Host 和 URI。
- MUST 解析 TLS ClientHello SNI，并支持短时间跨包缓存。
- MUST 解析常见 UDP/443 QUIC v1 Initial 中 CRYPTO frame 的 TLS ClientHello SNI；如果目标内核缺少所需 crypto 算法，必须明确降级为无 QUIC hostname 识别。
- MUST 合并时间窗口内重复 URL。
- MUST 执行 host ACL 的 accept/drop 语义，并在 TCP 路径实现 reset/RST 语义。
- MUST 输出指定 CSV 格式。
- MUST 保证等待更多 TLS/QUIC 数据时不会让 fast path 提前接管该连接，并在 PPPoE bridge 路径恢复 skb 状态后再返回。
- MUST 在 QUIC crypto 路径避免把栈缓冲直接传给 scatterlist/crypto API；当前实现使用 per-CPU ctx 中的 crypto scratch 缓冲以兼容 `CONFIG_VMAP_STACK` 并控制栈占用。
- MUST NOT 重新引入固定域名到全局 ipset 的隐式自动添加逻辑；所有 host 相关策略应通过 host ACL 和显式配置的 `host_acl_rule<id>_*` ipset 表达。

### 21.5 SHOULD：工程质量

- SHOULD 把会静默截断的用户输入改为显式长度校验，尤其 auth rule 和 bypass ipset 名称；若保持兼容，则必须保留当前截断语义。
- SHOULD 把 partial read FIXME 改成兼容性更好的 seq_file 或 per-open buffer，但必须记录行为变化。
- SHOULD 为 vline 配置提供事务/冲突检查，但若追求完全兼容，应保留当前非事务行为。
- SHOULD 避免继续复用 `net_device->flags` 高位和 `dev->name` 隐藏字节；若改动，必须提供兼容适配层。
- SHOULD 为 fastnat hash 冲突、URL parser、QoS CIDR、认证状态机、vline NOARP/ND 路径增加测试。
- SHOULD 评估是否需要支持非 DNS Host 值、IDNA U-label 转换、IPv6 literal Host，或把 `/dev/urllogger_queue` 从 CSV 迁移到长度显式的结构化输出；这些都会改变现有行为或 ABI。

## 22. 推荐验证清单

构建验证：

- `make EXTRA_CFLAGS="-DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER"`。
- `make -f Makefile.dkms src_install` 只在可写 `/usr/src` 环境验证。
- 至少在目标内核上验证 `CONFIG_NF_NAT`、conntrack、ipset、bridge netfilter、ingress hook 能力。

接口验证：

- 每个 `/dev/*_ctl` 写入合法命令、无换行半命令、超过 256 字节命令。
- 读接口能输出可重放配置。
- 小 buffer 读取行为符合当前代码或明确变更。

数据面验证：

- IPv4 TCP/UDP NAT 双向流建立 fastnat。
- IPv6 TCP/UDP NAT66 或非 NAT flow。
- PPPoE、VLAN、bridge、route 转发。
- TCP FIN/RST 过期。
- `update_magic` 后旧 fastnat 失效。
- URL logger 开启时首包/待解析流不会进入 fast path。

策略验证：

- zone 前缀规则和设备上下线。
- web auth HTTP 302、HTTPS DNAT、DNS/DHCP bypass、block/drop。
- QoS token 限速和 `tc_classid_mode`。
- host ACL accept/drop/reset，结合 ipset 过滤。
- vline/relay IPv4 ARP/DHCP 和 IPv6 ND/NOARP。

## 23. 当前仓库状态提示

- 当前只保留两份 Markdown 文档：`README.md` 面向使用者和外部接口对接，本文面向实现、审查和自动化重建。
- 当前 Git 工作区的源码和文档清单不包含历史 `.orig`、cscope 索引或 `natflow.mod.c`；后续审阅时若看到这类文件，应按生成物/备份文件处理，不能自动纳入构建规格或 DKMS 源码复制清单。
