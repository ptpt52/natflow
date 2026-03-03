# NATflow 技术报告（代码与文档全量扫描）

## 1. 项目定位与总体用途

NATflow 是一个 Linux 内核态网络加速与策略控制模块：在报文进入/离开协议栈时，先尝试命中 fast path 哈希表；命中后直接完成二三四层改写并转发到网卡，未命中才进入传统 netfilter 慢路径。核心目标是“高吞吐转发 + 策略控制 + 可观测性”。

从仓库文档和代码看，项目由一个主模块 `natflow` 以及若干子模块组成：

- **Fast path / NAT 加速**（`natflow_path.c` + `natflow.h`）
- **用户识别、认证状态、QoS 限速**（`natflow_user.c/.h`）
- **域名日志与 Host ACL**（`natflow_urllogger.c`）
- **分区（zone）与接口匹配**（`natflow_zone.c/.h`）
- **连接跟踪导出接口**（`natflow_conntrack.c`）
- **会话扩展/公共能力/IPSet 适配**（`natflow_common.c/.h`）
- **统一模块装载、字符设备编排**（`natflow_main.c`）

## 2. 构建、编译期开关与部署形态

### 2.1 模块构成

`Makefile` 将多个 `.o` 链接为一个 `natflow` 内核模块（`obj-m += natflow.o`），子模块默认包含 path/user/zone/urllogger/conntrack/common/main。DKMS 场景由 `Makefile.dkms` 支持。  

### 2.2 编译期开关

README 给出关键宏：

- `CONFIG_NATFLOW_PATH`：启用 fast path
- `CONFIG_NATFLOW_URLLOGGER`：启用 URL 日志与 ACL
- `CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH` / `CONFIG_HWNAT_EXTDEV_DISABLED`：硬件 NAT 外部设备行为切换

因此 NATflow 同时支持：

1. 纯软件 fast forward
2. 平台相关 HWNAT 协同（尤其 MTK 平台）

## 3. 功能模块总览（按可见接口）

### 3.1 控制面字符设备

代码和文档中暴露的控制/数据设备包括：

- `/dev/natflow_ctl`：主控制入口（debug、ifname_group、vline/relay、disable 等）
- `/dev/natflow_zone_ctl`：zone 规则管理
- `/dev/userinfo_ctl`：用户状态查询与管理
- `/dev/qos_ctl`：QoS 规则管理
- `/dev/urllogger_queue`：URL 审计输出队列
- `/dev/hostacl_ctl`：Host ACL 规则管理
- `/dev/conntrackinfo_ctl`：连接跟踪快照导出

并配套 sysctl/proc 开关，例如 `/proc/sys/urllogger_store/enable`。

### 3.2 主模块初始化流程

`natflow_init()` 负责按顺序初始化：

1. 主字符设备 `natflow_ctl`
2. `natflow_zone_init()`
3. `natflow_user_init()`
4. `conntrackinfo_init()`
5. `natflow_path_init()`（若编译启用）
6. `natflow_urllogger_init()`（若编译启用）

退出时逆序释放，保证依赖完整回滚。

## 4. 核心实现机制

### 4.1 Fast path 与慢路径协作机制

NATflow 的关键思路是：

- 利用 conntrack 会话与自定义扩展（`natflow_t`）记录双向转发表征、L2 头、NAT 映射、状态位；
- 在 netfilter 钩子（PRE/POST/FORWARD 等）执行 fast path 决策；
- 命中 fastnat 表后直接改包并投递设备；
- 未命中或不满足条件时进入普通 conntrack/NAT 路径。

`natflow.h` 中 `natflow_route_t` 与 `natflow_t` 是 fast path 会话元数据载体，包含：出接口、MTU、VLAN/PPPoE/L2 头缓存、方向状态位等。

### 4.2 NAT 改写与校验和更新

`natflow_path.h` 提供 `natflow_do_snat/dnat` 及 IPv6 对应版本：

- 按 conntrack tuple 改写源/目的地址与端口；
- 针对 TCP/UDP 分别执行 `inet_proto_csum_replace*`；
- IPv4 额外更新 IP 头校验和；
- IPv6 对地址 128bit 分段更新 L4 校验和。

该路径本质是“增量校验和更新算法 + tuple 映射重写”，避免重新完整计算。

### 4.3 fastnat 哈希表机制

`natflow_fastnat_node_t` 是高频转发槽位结构（按 cache line 对齐）。它保存：

- 五元组（v4/v6）
- NAT 前后地址端口
- MAC、VLAN、PPPoE 信息
- 速率/字节统计
- keepalive/状态

并通过 `natflow_hash_v4/v6` 计算桶位置，`NATFLOW_FASTNAT_TABLE_SIZE` 按平台设定（4096/8192/16384），兼顾内存与碰撞率。另有 `natflow_hash_skip()` 对特定平台桶位做规避。

> 算法特征：混合位运算（与/非/异或/旋转）+ 位移扩展 + 掩码取模，设计目标是低成本分布均衡。

### 4.4 netfilter hook 编排

`natflow_path.c` 注册多协议族 hook（IPv4、IPv6、bridge），覆盖 PRE/POST 等关键节点，实现：

- 报文学习与 fastnat 建立
- 命中后快速转发
- 与 conntrack confirm 的时序协同
- 可选硬件 offload 提交/停止

此外，`natflow_path` 还维护 netdev notifier 与工作队列，处理设备上下线、映射刷新、offload 停止清理。

## 5. 用户与策略控制子系统（natflow_user）

### 5.1 用户数据模型

`struct userinfo` 记录单用户统计/状态：

- IPv4/IPv6 地址、MAC
- auth_type / auth_status / auth_rule_id
- 超时、收发包字节累计
- 短窗速度统计

对应文档 `USER.md` 给出了 `/dev/userinfo_ctl` 的读写协议（kick、set-status、set-token-ctrl）。

### 5.2 认证策略与规则

`auth_conf` + `auth_rule_t` 支持最多 16 条认证规则（`MAX_AUTH`），包含：

- 源 zone 约束
- src ipset / whitelist / mac whitelist
- auth_type（AUTO/WEB 等）

并通过 magic 递增触发配置版本更新。

### 5.3 QoS 规则与令牌桶

`qos_ctl` 支持规则格式：

- user / user_port / remote / remote_port / proto
- rxbytes / txbytes

内部实现：

- `QOS_TOKEN_CTRL_GROUP_MAX=64` 组规则上限
- 每组维护 `rx/tx` 令牌桶（`tokens_per_jiffy = bytes/HZ`）
- 命中规则后在 fast path 中进行收发方向 token 扣减

这属于典型 **Token Bucket** 限速算法在连接级路径上的内核实现。

## 6. URL 审计与 Host ACL（natflow_urllogger）

### 6.1 URL 日志数据结构与存储策略

`struct urlinfo` 包含时间戳、源/目的地址端口、MAC、HTTP 方法、ACL 命中信息、主机名数据区。存储容器是受限链表：

- 内存上限：默认 10MB
- 记录数上限：默认 10000
- 去重合并：在时间窗内（默认 10s）同 tuple + host 合并，`hits++`

因此是“**窗口去重 + 双阈值淘汰（count/mem）**”策略。

### 6.2 Host ACL 规则模型

ACL 规则表达式：`<id>,<act>,<host>`，其中：

- `id`: 0~31
- `act`: record/drop/reset/redirect

支持可选 IPSet 绑定：`host_acl_rule<id>_<fml>`（ipv4/ipv6/mac），用于把主机名命中结果再按源身份过滤。

### 6.3 协议解析机制

从实现和文档可见，urllogger 支持：

- HTTP 方法与 Host 识别
- TLS ClientHello SNI 解析（SSL 类型日志）
- 输出统一 CSV：`timestamp,mac,sip,...,acl_idx,acl_action,url`

同时可在 FORWARD 或 LOCAL_IN 钩子模式运行（由编译宏决定）。

## 7. Zone 子系统（natflow_zone）

Zone 用于将接口归类为 LAN/WAN 并分配 zone id，数据结构为 `zone_match_list`（链表 + rwlock）。

特点：

- 规则形态：`lan_zone <id>=<if_name>` / `wan_zone ...`
- 支持 `+` 通配接口名匹配
- 通过将 zone/type 编码写入 `dev->name[IFNAMSIZ-1]` 的保留位实现快速读取

这是一种空间复用式元数据编码方案，读取开销低，适合高频路径判定。

## 8. conntrack 信息导出（natflow_conntrack）

`conntrackinfo` 子模块提供只读快照流：

- 按 bucket 扫描 conntrack hash
- 将状态、协议、源宿、端口、超时、字节包计数等序列化到可读文本
- 采用分块/限时策略（约 100ms + 计数上限）控制单次读取开销

是一个“**受控遍历 + 流式输出**”的运维诊断接口。

## 9. 关键数据结构与并发控制

### 9.1 数据结构

- 哈希表：fastnat 固定数组（O(1) 近似查找）
- 链表：用户事件、url 存储、zone 规则、ACL 缓冲
- conntrack ext：会话扩展存储 `natflow_t`
- 规则数组：QoS 与 auth 配置（小规模、固定上限）

### 9.2 并发原语

- `spin_lock/spin_lock_bh`：高频快路径和软中断上下文保护
- `rwlock`：zone 规则读多写少
- `mutex`：字符设备读写会话串行化
- `RCU`：conntrack 扩展迁移/访问安全
- `waitqueue`：userinfo 事件流同步

整体并发策略体现为：**快路径用轻量锁/原子，控制面用 mutex，结构迁移用 RCU**。

## 10. 主要算法总结

1. **Fast path 命中算法**：五元组哈希 + 状态位判定 + 方向路由缓存
2. **NAT 增量校验和算法**：地址端口差分更新，不重算全包
3. **QoS 令牌桶算法**：按 jiffies 补充并扣减 token，超限降速/转慢路径
4. **URL 去重聚合算法**：时间窗内同键合并计数
5. **ACL 匹配算法**：host 命中 + 可选 ipset 二次过滤
6. **Zone 匹配算法**：接口名精确/通配匹配 + 编码缓存

## 11. 项目适用场景与边界

### 11.1 适用场景

- 路由器/网关流量高并发 NAT 转发
- 用户审计、按用户限速、Portal/认证联动
- 域名级访问审计与拦截
- 软硬件结合（平台支持时）提升吞吐

### 11.2 工程边界/注意事项

- 依赖 Linux netfilter/conntrack 内核能力与版本差异适配
- 某些旧内核需按 README 补丁处理 ingress `NF_STOLEN`
- 硬件 offload 能力与网卡驱动 `ndo_flow_offload*` 强相关
- QoS/ACL/URL 功能受规则规模与内存上限影响

## 12. 结论

NATflow 不是“单一 NAT 加速模块”，而是一个 **内核态数据面加速 + 策略控制 + 审计可观测** 的综合框架。其工程设计关键在于：

- 用 conntrack 扩展把“慢路径学习结果”沉淀到 fast path 元数据；
- 用固定结构与位运算降低每包处理成本；
- 通过字符设备暴露可运维的控制面；
- 在用户认证、QoS、Host ACL、URL 日志等策略能力上与转发路径强耦合。

如果按路由网关产品视角，这个项目已经覆盖了“性能、管控、审计”三大基础面向。
