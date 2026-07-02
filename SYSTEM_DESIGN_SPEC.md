# Natflow 系统设计与规格限制文档

生成日期：2026-07-02  
扫描范围：当前仓库的源码、头文件、Makefile、DKMS 配置、现有 Markdown 文档、`portal/` 文档和仓库内辅助文件。  
目标读者：内核开发者、运维集成者、代码审查者，以及需要依据本规格重建实现的 AI/自动化工具。

本文是根据仓库当前实现反向整理的系统规格。若本文和代码冲突，以当前源码为准；若要用 AI 生成对应实现，必须同时满足本文的接口、状态位、数据流和限制条件。

## 1. 项目定位

Natflow 是一个 Linux 内核模块，模块名为 `natflow`。它围绕 Netfilter、conntrack、NAT、ipset、网络设备 notifier 和字符设备控制接口实现以下能力：

- 软件快速转发：在慢路径完成路由、NAT、桥转发和 conntrack 学习后，将可加速流写入 fastnat 哈希表，后续包可在 ingress/pre-routing 中直接改写二三层头并发往出口设备。
- 可选硬件 NAT/WED 卸载：在 MTK/Ralink 相关内核配置存在时，将 fastnat 流继续下发到硬件 offload。
- 用户识别和认证控制：用“fakeuser conntrack”表示用户，跟踪 IP/MAC、认证状态、认证规则、流量统计和事件。
- QoS/限速：按用户、端口、远端地址、协议匹配 QoS 规则，并基于 token bucket 或 `skb->mark` 输出 classid。
- URL/SNI 记录和主机访问控制：解析 HTTP Host/URI 和 TLS SNI，记录访问日志，按 host 规则和 ipset 执行动作。
- Zone 标记：按接口名或接口名前缀把设备标记为 LAN/WAN zone，供认证和策略判断使用。
- vline/relay：在 `CONFIG_NETFILTER_INGRESS` 场景下，把指定设备之间建立 L2/L3 直通或 relay 关系。
- 观测接口：输出 conntrack、用户、URL、host ACL、zone、核心配置等状态。

模块不是一个用户态守护进程。`portal/` 目录描述的是配套门户认证系统设计，当前仓库内没有完整的 authd/web server 实现；内核模块只提供底层用户态接口、事件和网络策略执行点。

## 2. 仓库结构

| 路径 | 类型 | 角色 |
| --- | --- | --- |
| `natflow_main.c` | 编译源码 | 模块入口、`/dev/natflow_ctl`、子模块初始化和退出顺序。 |
| `natflow_common.c/.h` | 编译源码/公共头 | 日志、兼容封装、conntrack 扩展探测、natflow 会话扩展、ipset/NAT 封装。 |
| `natflow.h` | 公共头 | 核心数据结构、fastnat 节点、状态位、哈希算法、表大小和超时常量。 |
| `natflow_path.c/.h` | 编译源码/头 | fast path、route 学习、fastnat 表、vline/relay、设备 notifier、硬件 offload。 |
| `natflow_user.c/.h` | 编译源码/头 | 用户 fakeuser、认证、QoS、用户事件、用户信息控制设备。 |
| `natflow_urllogger.c/.h` | 编译源码/头 | URL/SNI 解析、URL 存储、host ACL、sysctl。 |
| `natflow_zone.c/.h` | 编译源码/头 | LAN/WAN zone 控制、设备 zone 标记、zone notifier。 |
| `natflow_conntrack.c/.h` | 编译源码/头 | `/dev/conntrackinfo_ctl` conntrack dump。 |
| `natflow_compat.h` | 公共头 | 大量内核版本和 API 兼容宏。 |
| `Makefile` | 构建入口 | 编译 `natflow.o`，对象始终包含所有 `.o`，功能由 C 宏决定。 |
| `Makefile.dkms`、`dkms.conf` | DKMS 入口 | 安装到 `/usr/src/natflow-<version>` 并通过 DKMS build/install。 |
| `README.md` | 文档 | 项目能力、构建示例、系统要求。 |
| `CORE_CTL.md` | 文档 | 核心控制、zone、conntrack 控制接口说明。 |
| `USER.md` | 文档 | 用户、认证、QoS、事件接口说明。 |
| `HOSTACL.md` | 文档 | URL logger 和 host ACL 说明。 |
| `vline.md` | 文档 | vline/relay 当前规格和限制。 |
| `TECH_REPORT.md` | 文档 | 原有技术报告。 |
| `portal/README.md`、`portal/AUTH_EXT.md` | 文档 | 外部门户认证系统设计草案。 |
| `natflow_path.c.orig` | 非构建源码备份 | 和当前 `natflow_path.c` 不同，但不在 `Makefile`/`cscope.files` 中；AI 重建时不要当作第二份编译入口。 |
| `cscope.files`、`cscope.out` | 辅助索引 | cscope 文件列表和索引，不参与模块行为。 |

## 3. 构建规格

### 3.1 Makefile 行为

主 Makefile：

- 生成内核模块 `natflow.o`。
- `natflow-y` 包含 `natflow_main.o natflow_common.o natflow_path.o natflow_user.o natflow_zone.o natflow_urllogger.o natflow_conntrack.o`。
- 默认 `EXTRA_CFLAGS += -Wall -Werror -Wno-stringop-overread`。
- 定义 `NO_DEBUG` 时追加 `-Wno-unused -Os -DNO_DEBUG`，并关闭 `NATFLOW_DEBUG/INFO/WARN/ERROR/FIXME` 宏输出。
- `KERNELDIR` 默认 `/lib/modules/$(uname -r)/build`，通过 `make -C $(KERNELDIR) M=$(PWD)` 编译。

DKMS Makefile：

- 版本来自 `natflow_common.h` 的 `NATFLOW_VERSION`，当前为 `1.0.1`。
- 拷贝源码和头文件到 `/usr/src/natflow-<version>`。
- 生成的 DKMS Makefile 会把 `#EXTRA_CFLAGS` 行替换为 `EXTRA_CFLAGS = -DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER`。
- DKMS 安装位置为 `/kernel/drivers/net`，`AUTOINSTALL="yes"`。

### 3.2 关键编译宏

| 宏 | 影响 |
| --- | --- |
| `CONFIG_NATFLOW_PATH` | 编译并初始化 fast path、vline/relay、`natflow_ctl` 中 path 相关命令。未定义时 path 能力不生效。 |
| `CONFIG_NATFLOW_URLLOGGER` | 编译并初始化 URL logger、host ACL、sysctl。 |
| `CONFIG_NETFILTER_INGRESS` | 使用 per-netdev ingress hook；vline/relay 只在该模式下有实际转发路径。 |
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

内核版本适配是模块设计的一部分。重建实现时不能只面向单一新内核 API，除非明确放弃旧内核支持。

## 4. 运行时架构

Natflow 分为控制面、策略面、数据面和观测面。

控制面：

- 字符设备：`/dev/natflow_ctl`、`/dev/natflow_zone_ctl`、`/dev/natflow_user_ctl`、`/dev/qos_ctl`、`/dev/userinfo_ctl`、`/dev/userinfo_event_ctl`、`/dev/conntrackinfo_ctl`、`/dev/hostacl_ctl`、`/dev/urllogger_queue`。
- sysctl：`/proc/sys/urllogger_store/*`。
- ipset：认证白名单、旁路名单、QoS 集合、vline 过滤集合、host ACL 过滤集合、`wechat_iplist`。

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

1. 注册 `/dev/natflow_ctl`。
2. 初始化 zone：`natflow_zone_init()`。
3. 初始化 user/auth/QoS/userinfo：`natflow_user_init()`。
4. 初始化 conntrackinfo：`conntrackinfo_init()`。
5. 若 `CONFIG_NATFLOW_PATH`，初始化 path：`natflow_path_init()`。
6. 若 `CONFIG_NATFLOW_URLLOGGER`，初始化 urllogger：`natflow_urllogger_init()`。

退出顺序反向执行：

1. URL logger 退出。
2. path 退出。
3. conntrackinfo 退出。
4. user 退出。
5. zone 退出。
6. 注销 `/dev/natflow_ctl`。

设计含义：

- zone 和 user 在 path 前初始化，因此 fast path 可依赖 zone/user 状态位。
- URL logger 在 path 后初始化，但通过 `NF_FF_URLLOGGER_USE` 与 path 协调，避免未完成 URL 处理的流被快速转发。
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

## 7. 字符设备规格

### 7.1 `/dev/natflow_ctl`

读接口输出：

- `Version: <NATFLOW_VERSION>`。
- 使用说明。
- `debug=<value>`。
- 若启用 path：`disabled`、`hwnat`、`hwnat_wed_disabled`、`delay_pkts`、`go_slowpath_if_no_qos`、`ifname_group_type`。
- 当前 ifname group 和 vline/relay 配置的可重放命令。

写命令：

| 命令 | 条件 | 行为 |
| --- | --- | --- |
| `debug=<u>` | 总是可用 | 设置全局日志 bitmask。 |
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
| `clean` | 清空 zone 规则并刷新所有设备为 invalid zone。 |
| `lan_zone <id>=<if_name>` | 追加 LAN zone 规则。 |
| `wan_zone <id>=<if_name>` | 追加 WAN zone 规则。 |
| `update_match` | 重新扫描 `init_net` 设备并应用匹配。 |
| `print_zone` | 输出设备 zone 信息到内核日志。 |

规则匹配：

- `<if_name>` 最大解析 14 字符。
- `+` 表示前缀通配终止，例如 `eth+` 匹配所有以 `eth` 开头的设备；无 `+` 时要求完整匹配。
- 读接口文档说明有效 id 为 `0..126`，但写解析没有强制范围校验；越界 id 会被 `ZONE_ID_MASK` 裁剪并写入隐藏字节，集成层必须主动限制为 `0..MAX_ZONE_ID`。

### 7.3 `/dev/natflow_user_ctl`

读接口输出：

- `disabled`、`auth_conf_magic`、`redirect_ip`、`no_flow_timeout`。
- `auth_open_weixin_reply`、`https_redirect_en`、`https_redirect_port`。
- 规则数量、`dst_bypasslist_name`、`src_bypasslist_name`。
- 每条 auth 规则的可重放命令。

写命令：

| 命令 | 行为 |
| --- | --- |
| `clean` | 清空所有认证规则。 |
| `disabled=<u>` | 布尔化设置用户认证模块开关。默认 `1`。 |
| `update_magic` | 更新认证配置 magic。 |
| `dst_bypasslist_name=<name>` | 设置目标 IP 旁路 ipset 名称，空值清除。 |
| `src_bypasslist_name=<name>` | 设置源 IP 旁路 ipset 名称，空值清除。 |
| `auth id=<id>,szone=<idx>,type=web/auto,sipgrp=<name>[,ipwhite=<name>][,macwhite=<name>]` | 追加认证规则。 |
| `redirect_ip=a.b.c.d` | 设置 HTTP 302/认证跳转目标 IPv4。 |
| `no_flow_timeout=<u>` | 设置 fakeuser 无流超时秒数，默认 1800。 |
| `https_redirect_en=<u>` | 开启/关闭 HTTPS DNAT 重定向。 |
| `auth_open_weixin_reply=<u>` | 开启/关闭 WeChat 自动 portal 响应。 |
| `https_redirect_port=<u>` | 设置 HTTPS DNAT 端口，内部保存为网络字节序。 |

限制：

- 最多 `MAX_AUTH = 16` 条 auth 规则。
- ipset 名称字段类型为 `IPSET_MAXNAMELEN`，集成层必须限制到 `IPSET_MAXNAMELEN - 1`。当前 `auth` 命令中 `sipgrp/ipwhite/macwhite` 拷贝循环没有边界检查，过长输入是内存安全风险。
- 认证类型仅 `web` 和 `auto`；未提供或非法 type 会返回 `-EINVAL`。
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

`tc_classid_mode=1` 时不消耗 token，而是对 rx/tx 分别设置 `skb->mark = qos_id * 2 - 1` 和 `qos_id * 2`。`tc_classid_mode=0` 时使用 token bucket 丢弃/放行。

### 7.5 `/dev/userinfo_ctl`

读接口输出 fakeuser 列表，每行：

```text
ip_or_ipv6,mac,auth_type_hex,auth_status_hex,rule_id,timeout,rx_pkts:rx_bytes,tx_pkts:tx_bytes,rx_speed_pkts:rx_speed_bytes,tx_speed_pkts:tx_speed_bytes
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

### 7.6 `/dev/userinfo_event_ctl`

行为：

- `open` 时只允许一个 reader；已有 reader 时返回 `-EBUSY`。
- `read` 阻塞等待用户事件，输出格式与 `userinfo_ctl` 行接近。
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
- `type` 为 `HTTP` 或 `SSL`。
- `acl_action` 数值：0 accept/record，1 drop，2 reset，3 redirect。
- IPv6 地址使用 `%pI6` 输出。

限制：

- 如果没有满足老化条件的记录，read 返回 0。
- 如果输出行大于用户 buffer，返回 `-EINVAL`。
- 内部输出缓存大小约 `ALIGN(sizeof(struct urllogger_user), 2048) - sizeof(struct urllogger_user)`。

### 7.9 `/dev/hostacl_ctl`

条件：`CONFIG_NATFLOW_URLLOGGER`。

读接口输出默认 action、usage，以及 `ACL0..ACL31` 的规则内容。

写命令：

| 命令 | 行为 |
| --- | --- |
| `clear` | 清空所有 ACL 规则。 |
| `acl_action_default=accept/drop/reset/redirect` | 设置默认动作。 |
| `add acl=<id>,<act>,<host>` | 添加 host ACL。 |

限制：

- `ACL_RULE_MAX = 32`。
- `<act>` 必须是 `0..3`，含义同 URL logger。
- `<id>` 必须是 `0..31`。
- host 原样追加进规则 buffer，匹配时会按 host 和域名后缀查找。
- 规则 buffer 每次按 `ACL_RULE_ALLOC_SIZE = 256` 扩容。

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

- `natflow_ip_set_test_src_ip()`：源 IP 测试；set 不存在返回 `-EINVAL`。
- `natflow_ip_set_test_dst_ip()`：目标 IP 测试；set 不存在返回 0。
- `natflow_ip_set_test_dst_netport()`：目标 net+port 测试；set 不存在返回 0。
- `natflow_ip_set_add_src_ip()` / `natflow_ip_set_del_src_ip()`。
- `natflow_ip_set_test_src_mac()`：源 MAC 测试；set 不存在返回 `-EINVAL`。

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
| `wechat_iplist` | URL logger 看到 `qq.com`、`wechat.com`、`jd.com`、`taobao.com` 等 host 时添加 IP。 |

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

重要 `NF_FF_*` 位：

- `NF_FF_ORIGINAL_OK` / `NF_FF_REPLY_OK`：对应方向路由学习完成。
- `NF_FF_ORIGINAL_CHECK` / `NF_FF_REPLY_CHECK`：对应方向已经检查过。
- `NF_FF_ORIGINAL_FAIL` / `NF_FF_REPLY_FAIL`：对应方向 fastnat/offload 失败，周期性重试。
- `NF_FF_BRIDGE_FWD` / `NF_FF_ROUTE_FWD`：桥转发/路由转发判断。
- `NF_FF_QOS_TESTED` / `NF_FF_TOKEN_CTRL`：QoS 已测试/需要 token 控制。
- `NF_FF_USER_USE`：用户认证模块正在占用该流，fast path 必须暂停。
- `NF_FF_URLLOGGER_USE`：URL logger 正在等待解析/记录，fast path 必须暂停。
- `NF_FF_BUSY_USE = NF_FF_USER_USE | NF_FF_URLLOGGER_USE`。

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
- `IPS_NATFLOW_URLLOGGER_HANDLED`：bit 19。
- `IPS_NATFLOW_SKIP_BRIDGE`：bit 20，用于 bridge/non-bridge 双 hook 去重。
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

- MT7988/MT7986/MT7981 且启用相关 offload：`16384`。
- 常见 64 位/x86/ARM：`8192`。
- ATH79/MT7620 等资源较小平台：`4096`。

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
- flags：HTTPS、IPv6。
- HTTP method：NONE/GET/POST/HEAD。
- `hits`：合并命中次数。
- `acl_idx`、`acl_action`。
- 可变长 `data`：HTTP host+URI 或 TLS SNI。

同一时间窗口内相同 tuple/dport/data/flags/method 会合并，超过内存/数量限制时驱逐最老记录。

## 11. conntrack 扩展和会话初始化

`natflow_session_init()` 在未确认 conntrack 上挂载 natflow 会话扩展：

1. 使用 `IPS_NATFLOW_SESSION_BIT` 防止重复初始化。
2. 确保 NAT 扩展存在。
3. 探测/使用固定扩展偏移，把 `nat_key_t` 和 `natflow_t` 放在 conntrack ext 尾部。
4. 兼容 NATCAP：若已存在 NATCAP key，则在 NATCAP 后追加 natflow key；否则写入 natflow key。
5. 设置 `natflow_off`，并写入 `NATFLOW_MAGIC` 和 `ext_magic = (unsigned long)ct & 0xffffffff`。

硬约束：

- 代码依赖 `krealloc()` shrink 行为和当前内核分配器实现。源码明确说明在 KASAN、SLUB debug、redzone、poisoning 或对象移动语义下存在风险。
- `ct->ext->len` 超过 `NATCAP_MAX_OFF = 512` 不支持。
- `natflow_session_get()` 会校验 status bit、ext、magic、ext_magic 和 offset；任何不匹配均视为无 natflow 会话。

AI 重建实现时必须显式处理 conntrack ext 内存布局，不能把 `natflow_t` 放进独立哈希表后声称兼容。

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
5. 创建/更新 fakeuser，记录 MAC、规则、认证状态。
6. 触发 userinfo event。
7. 若开启 `https_redirect_en`，对 TCP 443 且未命中旁路名单的连接 DNAT 到本机地址和 `https_redirect_port`，并设置 bypass bit。

### 13.2 FORWARD

`natflow_user_forward_hook()`：

1. 若普通 ct 已有 `IPS_NATFLOW_CT_DROP`，丢弃。
2. 找到/创建 fakeuser，并关联到普通 ct 的 `master` 链；GRE 因 double free 风险被特殊跳过。
3. 初始化 `natflow_t`。
4. 首次匹配 QoS，设置 `qos_id` 和 `NF_FF_TOKEN_CTRL`。
5. 根据 fakeuser 认证状态处理：
   - `AUTH_REQ + WEB`：允许 DNS/DHCP/旁路名单；非 TCP 丢弃；HTTP GET/POST 生成 302；其他数据丢弃；裸 ACK 转 RST。
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

1. `enable=0` 时直接 accept。
2. 跳过已设置 `IPS_NATFLOW_CT_DROP` 的连接。
3. 只处理 original 方向，且未设置 `IPS_NATFLOW_URLLOGGER_HANDLED`。
4. 设置 `NF_FF_URLLOGGER_USE` 暂停 fast path。
5. 解析 HTTP：
   - 方法只识别 `GET `、`POST `、`HEAD `。
   - URI 必须以 `/` 开头。
   - 查找 `Host:` 头。
   - 记录 host + URI。
6. 解析 TLS SNI：
   - 解析 TLS ClientHello extension type 0。
   - 使用 per-CPU SNI cache 拼接跨包数据。
   - 单条追加数据小于 32KB。
   - cache 每 CPU 64 个节点，超时 4 秒。
7. 命中后写 URL store，并设置 `IPS_NATFLOW_URLLOGGER_HANDLED`。
8. 对部分 host 添加目标 IP 到 `wechat_iplist`。

### 15.3 host ACL

匹配：

- host 会转小写。
- 先匹配完整 host，再逐级匹配点后的后缀。
- 每条规则前一个 marker 字节保存 action 和 rule id。
- 可结合 `host_acl_rule<id>_ipv4/ipv6/mac` 限制源 IP/MAC。

动作：

- `accept`/0：记录并放行。
- `drop`/1：设置 `IPS_NATFLOW_CT_DROP` 并 drop。
- `reset`/2：发送/改写 TCP RST，设置 drop 状态。
- `redirect`/3：当前实现按非 record 动作处理，未发现完整 redirect 目标重写逻辑；集成层不要假设它会跳转到特定页面。

## 16. Zone 设计

zone 元数据编码在 `net_device->name[IFNAMSIZ - 1]` 的隐藏字节：

- zone id 使用低位 mask。
- zone type 使用额外 bit。
- `INVALID_ZONE_ID = 127`。
- `MAX_ZONE_ID = 126`。

约束：

- 只有当可见设备名长度满足 `strlen(name) + 2 <= IFNAMSIZ` 时才能写隐藏字节，否则设置失败并视为 invalid。
- 修改 `dev->name[IFNAMSIZ - 1]` 是强假设：依赖内核设备名数组尾部未用于可见字符串。
- zone 规则列表没有去重；后添加规则可能与前面规则冲突，匹配函数按链表顺序应用。
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

- DHCP UDP dst 67 会把 flags 从 `0x0000` 改为 `0x8000` 并更新 checksum。
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

当前 `natflow_path.c` 相对 `natflow_path.c.orig` 的主要差异集中在 IPv6 vline 安全处理：增加 `pskb_may_pull()` 检查、NOARP 到 Ethernet 头部准备、非 ND ICMPv6 判断，以及 `NETDEV_CHANGEUPPER` 时更新 vline。

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
- 部分 auth 字段缺少长度检查。
- QoS set 名称最多 15 字节。
- vline endpoint 名最多 15 字节。
- zone 设备名最多 14 字节。
- IPv6 fast path 不解析扩展头。
- HTTP parser 只识别简单明文请求和 `Host:`。
- TLS SNI parser 只覆盖普通 ClientHello SNI extension，不保证支持所有 TLS 变体、ECH 或分片异常。

### 20.3 行为限制

- URL logger 只有 `enable=1` 时才处理 host ACL。
- host ACL 的 redirect action 没有完整重定向实现。
- `conntrackinfo_ctl` 的 `kickall` 没有实际清理。
- `userinfo_ctl`、`userinfo_event_ctl`、`urllogger_queue` 对小 buffer 不支持 partial read。
- vline 配置非事务、无冲突检测、运行 ifindex key 小于 64。
- fastnat 哈希表固定大小，冲突处理有限。
- `disabled` 默认值：path 默认为 1，user 默认为 1，URL store 默认为 0；模块加载后需要用户态显式开启相关能力。
- README 指出 4.10 之前内核若 ingress hook 缺少 `NF_STOLEN` 支持，需要补丁。

### 20.4 安全边界

- 控制设备没有在代码内做能力检查，实际安全依赖设备节点权限和系统管理策略。
- 过长 auth rule 字段是内核内存破坏风险，部署时必须由用户态校验。
- URL/host 解析不能作为强安全 WAF，只能作为流量审计/粗粒度访问控制。
- fast path 绕过大量慢路径检查，因此任何策略模块在未完成处理前必须设置 `NF_FF_USER_USE` 或 `NF_FF_URLLOGGER_USE`。

## 21. AI 可重建实现契约

若 AI 根据本文生成实现，必须满足以下 MUST/SHOULD 条款。

### 21.1 MUST：模块和接口

- MUST 生成一个 Linux 内核模块 `natflow`，而不是用户态代理。
- MUST 保留 `NATFLOW_VERSION`，默认当前版本为 `1.0.1`。
- MUST 提供本文列出的字符设备和命令。
- MUST 实现 256 字节换行命令协议。
- MUST 通过 netfilter hooks 接入 IPv4、IPv6 和 bridge 路径。
- MUST 通过 conntrack 扩展保存 `natflow_t`，并可从普通 conntrack 找回。
- MUST 保留 fakeuser conntrack 模型，用户状态不得仅存在普通哈希表中。
- MUST 支持 ipset 名称测试，并保留“set 不存在时不同 wrapper 返回值不同”的语义。
- MUST 在策略模块占用连接时设置对应 busy bit，避免 fast path 提前转发。

### 21.2 MUST：fast path

- MUST 先通过慢路径学习双向 route，再建立 fastnat 节点。
- MUST 在 fast path 命中时校验 magic、tuple、协议、入口 ifindex 和超时。
- MUST 正确更新 IPv4 header checksum、TCP/UDP pseudo checksum、NAT 地址/端口、TTL/hop-limit。
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
- MUST 合并时间窗口内重复 URL。
- MUST 执行 host ACL 的 accept/drop/reset 语义。
- MUST 输出指定 CSV 格式。

### 21.5 SHOULD：工程质量

- SHOULD 把所有用户输入长度校验补全，尤其 auth rule 名称。
- SHOULD 把 partial read FIXME 改成兼容性更好的 seq_file 或 per-open buffer，但必须记录行为变化。
- SHOULD 为 vline 配置提供事务/冲突检查，但若追求完全兼容，应保留当前非事务行为。
- SHOULD 避免继续复用 `net_device->flags` 高位和 `dev->name` 隐藏字节；若改动，必须提供兼容适配层。
- SHOULD 为 fastnat hash 冲突、URL parser、QoS CIDR、认证状态机、vline NOARP/ND 路径增加测试。

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

- `natflow_path.c.orig` 是历史/备份文件，与当前 `natflow_path.c` 有差异：约 104 行新增、59 行删除，主要是 IPv6 vline 安全检查、NOARP 头处理、日志措辞和 `NETDEV_CHANGEUPPER` 更新。它不参与当前构建。
- `cscope.out` 是生成索引，不是源代码规范的一部分。
- 现有 Markdown 文档互相补充：`README.md` 是概览，`CORE_CTL.md`/`USER.md`/`HOSTACL.md` 是接口说明，`vline.md` 是 vline 专项规格，`TECH_REPORT.md` 是较早技术报告。本文合并并补充了源码中未显式写入原文档的限制。
