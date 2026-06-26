# NATflow vline 当前实现规格

本文档基于当前工作区源码重新扫描整理，覆盖 `natflow_main.c`、
`natflow_path.c`、`natflow_path.h` 中的 vline/relay 实际实现。这里描述的是
当前代码行为，不是目标设计。

## 1. 功能定位

vline 是 NATflow 在 netdev ingress 路径上的双向转发机制。配置一对接口后，
运行时按入接口 `ifindex` 查找对端出接口，并在 NATflow 主路径尾部决定是否把
skb 直接发到对端设备。

当前实现分为两种模式：

- `vline_add`：普通 vline。大体上做二层透传，但对本机 MAC、广播、组播、IPv6
  ND、PPPoE/NOARP 等场景有特殊处理。
- `relay_add`：relay vline。依赖 `fakeuser` 表维护 IP/IPv6 到 MAC、LAN/WAN
  侧的信息，按目的地址判断是否跨侧转发，并会改写源 MAC 为出接口 MAC。

vline 只在 `CONFIG_NETFILTER_INGRESS` 路径中生效。没有该配置时，当前代码中
主要 vline 转发逻辑不会执行。

## 2. 控制命令

控制入口为 `/dev/natflow_ctl`，相关命令如下：

```sh
echo 'vline_add=<src_ifname>,<dst_ifname>,<family>' > /dev/natflow_ctl
echo 'relay_add=<src_ifname>,<dst_ifname>,<family>' > /dev/natflow_ctl
echo 'vline_apply' > /dev/natflow_ctl
echo 'vline_clear' > /dev/natflow_ctl
```

参数规则：

- `<src_ifname>` 是源侧接口，运行时会标记为 LAN 侧。
- `<dst_ifname>` 是对端接口，运行时会标记为非 LAN 侧。
- `<family>` 只接受小写 `ipv4`、`ipv6`、`all`。
- 接口名按 `%15[^,]` 解析，最大 15 字符，不支持逗号。
- family 按 `%7s` 解析，命令应一行一个。
- 最多缓存 8 条 vline/relay 配置。
- `vline_add` 和 `relay_add` 只写入待应用配置，不立即完整重建运行时转发表。
- `vline_apply` 会先清空运行时 vline 状态，再按配置表顺序逐条建表。
- `vline_clear` 会同时清空待应用配置和运行时 vline 状态。
- `cat /dev/natflow_ctl` 会输出当前保存的配置命令，但不会输出运行时转发表或
  每条配置的 apply 结果。

## 3. 内部状态

运行时转发表：

- `vline_fwd_map[64]`：按入接口 `ifindex` 索引，保存对应出接口 `net_device`。
- 只有入接口 `ifindex < 64` 才能安装转发表项。
- 出接口可以是 `ifindex >= 64` 的设备，因为出接口只作为 map value 保存。
- 转发表指针使用 RCU API 写入和读取。

配置表：

- `vline_fwd_map_config[8][2][IFNAMSIZ]`
- `[0]` 保存源侧接口名，`[1]` 保存目的侧接口名。
- `vline_fwd_map_family_config[8]` 保存 family，并通过 `VLINE_RELAY_MASK`
  表示 relay 模式。

vline 私有标志当前直接保存在 `net_device->flags` 的高位：

- `IFF_PPPOE`：标识 PPPoE 设备。
- `IFF_VLINE_L2_PORT`：桥下挂端口。
- `IFF_VLINE_FAMILY_IPV4`：仅 IPv4。
- `IFF_VLINE_FAMILY_IPV6`：仅 IPv6。
- `IFF_VLINE_IS_LAN`：源侧/LAN 侧。
- `IFF_VLINE_RELAY`：relay 模式。

family 标志语义：

- `all`：不设置 IPv4/IPv6 限制标志，IPv4 和 IPv6 都允许。
- `ipv4`：设置 `IFF_VLINE_FAMILY_IPV4`，IPv4 允许，IPv6 普通路径不允许。
- `ipv6`：设置 `IFF_VLINE_FAMILY_IPV6`，IPv6 允许，IPv4 普通路径不允许。

## 4. 设备参数限制

`vline_apply` 建表时会在 `init_net` 中按接口名查找设备，并执行以下限制：

- 两个命名接口都必须已存在。
- 命名接口不能已经有 master upper device。也就是说，不能直接配置桥下挂端口；
  应配置桥 master。
- 任一命名接口如果带 `IFF_NOARP`，family 必须是 `ipv6`。
- 源侧接口不能是 `IFF_NOARP`。
- `relay_add` 的目的侧接口也不能是 `IFF_NOARP`。
- 因此当前允许的 PPPoE/NOARP 主要组合是：
  - `vline_add=<eth_or_bridge>,<pppoe_or_noarp>,ipv6`
  - 运行时映射仍然是双向的。
- 当前不支持：
  - `vline_add=<pppoe_or_noarp>,<eth_or_bridge>,...`
  - `relay_add` 任意一端为 `IFF_NOARP`
  - `family=all` 或 `family=ipv4` 搭配任何 `IFF_NOARP` 命名接口

注意：是否为 PPPoE 本身不是 vline 校验的核心条件，当前限制主要看
`IFF_NOARP`。`IFF_PPPOE` 由 netdev 事件中对 PPP/PPPoE 设备的识别补充设置。

## 5. 建表规则

建表入口为 `vline_fwd_map_add(dst, src, family, is_relay)`，运行时映射始终按
双向关系安装。

普通接口对普通接口：

- `src_dev` 标记为 LAN 侧。
- `dst_dev` 清除 LAN 侧标记。
- 安装 `src_dev->ifindex => dst_dev`。
- 安装 `dst_dev->ifindex => src_dev`。

桥 master 对普通接口：

- 如果源侧是桥 master，不给桥 master 自身安装入方向表项。
- 遍历所有 master 为该桥的下挂端口。
- 每个下挂端口标记为 LAN 侧和 L2 port。
- 安装 `bridge_port->ifindex => dst_dev`。
- 对端普通接口安装 `dst_dev->ifindex => src_bridge_master`。

普通接口对桥 master：

- 普通源接口安装 `src_dev->ifindex => dst_bridge_master`。
- 目的桥 master 的每个下挂端口标记为非 LAN 侧和 L2 port。
- 安装 `bridge_port->ifindex => src_dev`。

桥 master 对桥 master：

- 源桥的每个下挂端口安装到目的桥 master。
- 目的桥的每个下挂端口安装到源桥 master。
- ingress hook 不挂在 bridge master 自身，实际入方向依赖下挂端口命中 map。

应用配置时：

- `vline_apply` 先清空所有 64 个运行时 map，并清除所有 netdev 上的 vline 标志。
- 然后按配置表顺序逐条安装。
- 如果某条配置失败，会记录错误码但继续安装后续配置。

## 6. netdev 事件处理

`NETDEV_UP`、`NETDEV_CHANGE` 和 `NETDEV_CHANGEUPPER`：

- 对 PPPoE 设备尝试设置 `IFF_PPPOE`。
- 调用 `vline_fwd_map_ifup_handle(dev)`。
- 该函数只查找第一条匹配当前设备名或当前 master 名的 vline 配置，并只重建该
  单条配置。

`NETDEV_CHANGEUPPER` 的处理范围是新增 lower dev 加入已配置 bridge 的场景：

- 当新增设备加入 bridge 后，如果该 bridge 是 vline 配置中的端点，
  `vline_fwd_map_ifup_handle(dev)` 会按当前 master 关系重建该条 vline 映射。
- 设备离开 bridge 或迁移到其他 bridge 时，内核侧不保证自动清理旧的 map/flags，
  也不会做完整 `vline_apply`。
- 离开/迁移 bridge 的拓扑收敛由应用层保证：应用层需要自行感知 bridge 拓扑变化，
  重新下发 vline 配置并触发 `vline_apply`。

`NETDEV_UP` 还会在满足条件的设备上安装 ingress hook：

- 排除 loopback、bridge master、OVS master、bond master、普通 macvlan。
- `ARPHRD_RAWIP` 设备例外，允许安装 hook。

`NETDEV_UNREGISTER`：

- 卸载 ingress hook。
- 清除该设备自身 vline 标志。
- 如果该设备作为入接口 map key，清除对应表项。
- 如果该设备作为任意 map value，也会扫描 64 个表项并清除引用。

`NETDEV_CHANGEUPPER` 不触发完整 vline 重建，只用于覆盖新增下挂口加入已配置
bridge 的场景。

## 7. vline 过滤

进入 vline 转发前，会先检查 ipset 过滤集合。命中后跳过 vline，继续原始路径。

IPv4 过滤集合：

- `vline_filter_dst_netport`
- `vline_filter_dst`
- `vline_filter_src`
- `vline_filter_src_mac`

IPv6 过滤集合：

- `vline_filter6_dst_netport`
- `vline_filter6_dst`
- `vline_filter6_src`
- `vline_filter_src_mac`

PPPoE session 包在主路径前面会临时剥离 PPPoE session header 以便按 IPv4/IPv6
解析；进入 vline 尾部处理前会把 PPPoE header 恢复。

## 8. 普通 vline IPv4 转发

普通 vline IPv4 只在入接口存在 map 且 IPv4 family 允许时执行。

广播、组播、ARP：

- 克隆一份 skb。
- 给克隆 skb push Ethernet header。
- 设置克隆 skb 出接口为对端设备并发送。
- 原 skb 继续原路径。

本机 MAC：

- 如果入接口不是 `IFF_NOARP`，且目的 MAC 等于本机 MAC，则不做 vline 转发，
  原 skb 继续原路径。
- 对桥下挂端口，判断目标 MAC 时使用 bridge master 的 MAC。

其他单播：

- 如果存在 conntrack，会把 NATflow session 标记为 bridge，并记录 MTU。
- 调用 `nf_conntrack_confirm()`。
- push Ethernet header，设置出接口为对端设备并发送原 skb。
- 返回 `NF_STOLEN`，原路径停止。

## 9. 普通 vline IPv6 转发

普通 vline IPv6 在入接口存在 map 且满足以下任一条件时执行：

- IPv6 family 允许。
- skb protocol 是 `ETH_P_PPP_DISC`。
- skb protocol 是 `ETH_P_PPP_SES`。
- skb protocol 不是 `ETH_P_IPV6`，即未知协议也会走该分支。

链路本地 Ethernet 目的 MAC：

- 入接口不是 `IFF_NOARP` 且目的 MAC 是 link-local MAC 时进入特殊处理。
- Pause 帧直接走原路径。
- Bridge group、LLDP 以及其他 link-local MAC，在出接口不是 `IFF_NOARP` 时直接
  发到对端并返回 `NF_STOLEN`。
- 出接口是 `IFF_NOARP` 时不转发，走原路径。

`IFF_NOARP` 入接口到 Ethernet 出接口：

- 仅对 `ETH_P_IPV6` 做处理。
- 在 IPv6 header 前构造 Ethernet header。
- IPv6 源地址为 link-local 时，当前代码会从源 IPv6 地址推导源 MAC。
- IPv6 源地址非 link-local 时，源 MAC 使用出接口 MAC。
- 目的 IPv6 地址可推导 EUI-64 MAC 时按地址推导目的 MAC。
- 目的 IPv6 为 multicast 时生成 `33:33:*` 目的 MAC。
- 否则查询 fakeuser 表获取目的 MAC；查不到则回到原路径。

Ethernet 入接口到 `IFF_NOARP` 出接口：

- 当前只对 Neighbor Solicitation 的特定 link-local 目标地址做特殊处理。
- 命中时原地构造 Neighbor Advertisement 回包，返回 `NF_STOLEN`。
- 未命中特殊条件时继续后续普通 vline 逻辑。
- 最终向 `IFF_NOARP` 出接口发送时不 push Ethernet header。

广播、组播：

- 克隆一份 skb。
- 出接口不是 `IFF_NOARP` 时给克隆 skb push Ethernet header。
- 设置克隆 skb 出接口为对端设备并发送。
- 原 skb 继续原路径。

本机 MAC：

- 与 IPv4 相同，本机 MAC 帧不做 vline 转发。

IPv6 单播补充规则：

- 源侧为 LAN 时，如果目的 IPv6 命中对端设备非 link-local 地址的前缀，则走原
  路径。
- 会根据源 IPv6 地址更新 fakeuser 的 LAN/WAN 侧标记。
- 如果目的 IPv6 对应 fakeuser 与当前入接口同侧，则走原路径。
- NS/NA/RS/RA 会克隆一份 flood 到对端，原 skb 继续原路径。
- 无 conntrack 的非 ND ICMPv6 会尝试调用 `nf_conntrack_in_compat()` 建立
  conntrack。
- 存在 conntrack 时，会标记 NATflow session 为 bridge、记录 MTU，并在 LAN
  入方向周期性学习源 MAC。
- 最终确认 conntrack 后发送到对端，返回 `NF_STOLEN`。

## 10. relay IPv4 转发

relay IPv4 只在出接口带 `IFF_VLINE_RELAY` 且 IPv4 family 允许时执行。

DHCP：

- 对 UDP 目的端口 67 的 IPv4 包，当前代码会尝试把 BOOTP flags 从 `0x0000`
  改为 `0x8000`，并修正 UDP checksum。

广播、组播、ARP：

- 先确保 skb 可读可写，然后复制一份 skb。
- 复制 skb 的 Ethernet 源 MAC 改为出接口 MAC。
- ARP 包会学习 sender IP/MAC 到 fakeuser，并记录 LAN/WAN 侧。
- ARP reply 会尝试按 fakeuser 改写 target hardware address 和目的 MAC。
- 非广播 ARP request 查不到目的 fakeuser 时会改为广播。
- ARP sender hardware address 改为出接口 MAC。
- 复制 skb 发到对端，原 skb 继续原路径。

IPv4 单播：

- 按目的 IPv4 查询 fakeuser。
- 只有目的 fakeuser 在对侧时才转发；同侧或查不到时走原路径。
- 转发时目的 MAC 改为 fakeuser MAC。
- 源 MAC 改为出接口 MAC。
- 确认 conntrack，标记 NATflow session 为 bridge，记录 MTU。
- 发送原 skb 到对端并返回 `NF_STOLEN`。

## 11. relay IPv6 转发

relay IPv6 在出接口带 `IFF_VLINE_RELAY` 且 IPv6 分支条件满足时执行。

ND 包：

- 当前只识别 IPv6 fixed header 中 `nexthdr == IPPROTO_ICMPV6` 的
  NS/NA/RS/RA。
- 按目的 IPv6 查询 fakeuser。
- 如果目的 fakeuser 在对侧，改写原 skb 目的 MAC 并返回 `NF_STOLEN`。
- 如果目的 fakeuser 在同侧，或者查不到 fakeuser，则复制一份 skb 转发，原 skb
  继续原路径。
- 转发 skb 会学习源 IPv6/MAC 到 fakeuser，并记录 LAN/WAN 侧。
- Ethernet 源 MAC 改为出接口 MAC。
- ND option 中的 source/target link-layer address 会改为出接口 MAC，并重新
  计算 ICMPv6 checksum。

广播、组播：

- 复制 skb。
- 源 MAC 改为出接口 MAC。
- 复制 skb 发到对端，原 skb 继续原路径。

IPv6 单播：

- 按目的 IPv6 查询 fakeuser。
- 只有目的 fakeuser 在对侧时才转发；同侧或查不到时走原路径。
- 目的 MAC 改为 fakeuser MAC。
- 源 MAC 改为出接口 MAC。
- 确认 conntrack，标记 NATflow session 为 bridge，记录 MTU。
- 发送原 skb 到对端并返回 `NF_STOLEN`。

非 IPv6 协议：

- 由于 IPv6 分支允许 PPPoE discovery/session 和未知协议进入，该类包在 relay
  模式下也可能被送到 relay 处理尾部。

## 12. PPPoE/NOARP 语义

当前代码把 PPPoE/RAWIP 类设备主要通过 `IFF_NOARP` 约束纳入 vline。

允许的主场景：

- Ethernet/bridge 作为源侧，PPPoE/NOARP 作为目的侧。
- 只能使用普通 `vline_add`。
- family 必须为 `ipv6`。
- 运行时双向转发表仍会建立：Ethernet/bridge 入方向到 PPPoE/NOARP，PPPoE/NOARP
  入方向回到 Ethernet/bridge。

NOARP 到 Ethernet 的 IPv6 回方向：

- 当前实现会补 Ethernet header。
- 源 MAC 并非总是出接口 MAC：源 IPv6 是 link-local 时会按 EUI-64 规则推导；
  其他情况使用出接口 MAC。
- 目的 MAC 可来自 EUI-64 推导、IPv6 multicast 映射或 fakeuser 表。

Ethernet 到 NOARP 的 IPv6 正方向：

- 最终发送到 NOARP 出接口时不带 Ethernet header。
- 对特定 NS/link-local 目标，当前代码会在入侧构造 NA 回包。

relay 与 NOARP：

- 当前 `relay_add` 不允许任意一端是 `IFF_NOARP`。

## 13. 当前实现限制

- 运行时入接口 `ifindex` 必须小于 64。
- 待应用配置最多 8 条。
- 仅查找 `init_net` 中的设备。
- 不能直接配置桥下挂端口，只能配置桥 master。
- 桥 master 自身不挂 ingress hook；桥相关转发依赖下挂端口 map。
- 空 bridge master 可以通过配置校验，但没有下挂端口时不会安装有效入方向表项。
- 配置没有去重，也没有冲突检测。
- 同一个入接口被多条规则覆盖时，后安装的 map 会覆盖前面的 map，但设备 flags
  可能保留前面规则设置后的状态。
- `src_ifname == dst_ifname` 当前没有被显式拒绝。
- `vline_apply` 不是事务式操作，失败时可能留下部分已安装的运行时表项。
- netdev UP/CHANGE/CHANGEUPPER 事件只重建第一条匹配配置，不会完整重建全部
  vline 状态。
- `NETDEV_CHANGEUPPER` 只覆盖 bridge port 新增加入已配置 bridge 的场景。port
  离开或迁移 bridge 时，应用层需要重新下发配置并触发 `vline_apply`。
- ICMPv6/ND 识别不解析 IPv6 extension header。
- 普通 vline 不是严格的“所有包都二层透传”：本机 MAC、同侧 fakeuser、对端
  前缀命中、过滤 ipset 命中等情况会回到原路径。
- relay 单播依赖 fakeuser 表，未知目的单播不会像桥一样泛洪，而是走原路径。

## 14. 可能存在的问题点

1. 私有 vline 状态直接写入 `net_device->flags` 高位，存在与内核/驱动 flags
   冲突、并发修改和语义混淆风险。更稳妥的方式是独立私有状态表或使用明确的
   private 标志存储。

2. `vline_apply` 不是原子操作。它先清空运行时状态，再逐条应用配置；中途失败
   后不会回滚，可能形成部分生效的 vline 状态。

3. 配置缺少冲突检测。重复端点、同一接口参与多条 vline、`src == dst` 等组合
   可能导致 map 覆盖和 flags 不一致。

4. netdev UP/CHANGE/CHANGEUPPER 事件只重建第一条匹配配置。多条规则或桥端口
   变化后，运行时状态可能和配置表不一致。

5. `NETDEV_CHANGEUPPER` 只用于处理新增端口加入已配置 bridge。端口离开或迁移
   bridge 时，内核侧不做自动完整收敛，需要应用层感知后重新下发并 apply 配置。

6. 空 bridge master 配置可能返回成功但不安装任何入方向 map，用户侧不容易发现
   配置实际上无效。

7. `IFF_NOARP` 入接口到 Ethernet 出接口时，当前代码在 IPv6 header 前直接写
   Ethernet header，没有显式检查/扩展 headroom，也没有统一确保 skb 可写，存在
   越界或写共享 skb 的风险。

8. NOARP 到 Ethernet 的源 MAC 规则与“统一使用出接口 MAC”不完全一致。当前代码
   对 link-local IPv6 源地址会推导 MAC，可能需要确认是否符合预期。

9. Ethernet 到 NOARP 的 fake NA 分支会在当前 skb 上构造回包并直接
   `dev_queue_xmit()`，代码没有显式设置 `skb->dev` 为某个目标设备，也没有在
   `skb_push(ETH_HLEN)` 后调用 `skb_reset_mac_header()`。这可能是有意回 ingress
   设备发 NA，也可能隐藏设备/头指针问题，需要实测确认。

10. ICMPv6/ND 只识别 fixed IPv6 header 后紧跟 ICMPv6 的包。带 extension header
    的合法 ND/ICMPv6 包不会按 ND 特殊逻辑处理。

11. relay 的 DHCP flags 改写直接按固定 BOOTP 偏移访问 UDP payload，当前片段未
    看到对 DHCP payload 长度的专门校验，短包场景需要继续确认上游长度保证。

12. `vline_fwd_map_ifup_handle()` 在不清理旧状态的情况下对单条配置重复建表，和
    `vline_apply` 的完整清理语义不同，长期运行后可能残留旧 flags 或旧 map。

13. 配置表和运行时状态修改缺少显式互斥保护。控制写入、netdev notifier、ingress
    读路径之间主要依赖 RCU 指针，但配置表与 dev flags 的并发一致性仍需评估。

14. `cat /dev/natflow_ctl` 只能恢复待应用配置，不能反映 apply 是否成功、哪些桥
    下挂端口实际被展开、哪些 ifindex 因超过 64 被跳过。

15. 普通 vline IPv6 link-local MAC 处理会转发 LLDP/bridge group 等链路本地帧
    到对端，这和常规桥的协议保留行为不同，需要确认是否为目标设计。
