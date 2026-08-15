# Natflow 硬编码 DPI 状态机设计与实施计划

状态：Accepted，待分阶段实现
日期：2026-08-15

实施进度：M0-M2 已完成。首批 18 个固定 protocol app 已进入数据面；domain
用户 ruleset 暂留到 M3/M4，compact automaton 尚未实施。

## 1. 决策摘要

Natflow DPI 采用编译进内核模块的固定应用目录和手写 C 状态机，不再提供
domain/proto 用户规则、通用规则解释器、离线 DSL compiler 或运行时规则库。

数据面先完成 L3/L4 和基础协议解析，把原始 payload 转换为有类型的协议事实；
第五层应用分类再选择一个有限、明确、可审计的硬编码状态机。状态机只有到达
终态才直接写入固定 `app_id`：

```text
packet
  -> L3 eligibility
  -> L4 protocol/direction/role
  -> base protocol parser
  -> structured feature extraction
  -> hardcoded application state machine
  -> terminal app_id
```

`app_id` 是唯一常驻分类结果。中间协议事实、candidate 和 state 都不能提前写入
`app_id`，否则 TLS、QUIC 等基础协议会阻止后续细分为 YouTube、Netflix 等应用。

## 2. 目标和非目标

### 2.1 目标

- 只识别维护者明确选择的有限协议和应用。
- 每个识别路径都是手写 C 代码或编译期只读常量表，可逐行审计。
- 不逐包遍历全部应用；先按 L3/L4、方向和基础协议选择候选机器。
- 复用 `natflow_l7` 的 HTTP Host、TLS SNI、QUIC SNI 和 DNS QNAME parser。
- 保持解析循环、包数、字节数、状态数和分支数都有编译期硬上限。
- 不在 conntrack 中保存域名、payload、指针、动态数组或规则对象。
- 终态直接发布固定 `app_id`，然后释放 DPI/L7 owner，让 fast path 继续。
- 保留 DPI enable、统计和事件观测能力，方便验证误判和覆盖率。

### 2.2 非目标

- 不支持用户新增、删除或重映射识别规则。
- 不支持 YAML/JSON DSL、通用 bytecode、PCRE 或运行时插件。
- 不移植完整 nDPI，也不承诺识别任意应用。
- 不做完整 TCP stream reassembly、无限等待或全流 payload 扫描。
- 不通过 DNS 查询流直接给后续独立连接定类；如需 DNS correlation，必须另行设计
  client/address/TTL 有界关联缓存。
- 本阶段不让应用识别结果直接覆盖认证、Host ACL、conntrack 或其他既有拒绝结果。

## 3. 五层分类模型

### 3.1 第一层：网络层准入

负责确认当前包是否进入 DPI：

- IPv4 或基础 IPv6；
- forwarded TCP/UDP；
- conntrack 和 `natflow_t` 可用；
- 非 helper/fakeuser/NATCAP 等已有排除对象；
- payload 可在限定长度内读取。

IPv6 extension header 仍不在当前范围内，无法解析时 fail-open。

### 3.2 第二层：传输层分类

只产生事实和候选，不产生应用结果：

- TCP/UDP；
- original/reply direction；
- client/server port；
- SYN/FIN/RST 等终止条件；
- 每方向 packet/byte budget。

端口只用于候选裁剪，不允许单独写入高置信 `app_id`。

### 3.3 第三层：基础协议识别

通过高确定性结构证据识别基础协议，例如：

- HTTP、TLS、QUIC、DNS；
- SSH、WireGuard、STUN/TURN、BitTorrent；
- FTP、SMTP、POP3、IMAP、SIP、RTSP；
- MQTT、RESP、MySQL、PostgreSQL、RDP、SMB。

基础协议可以直接成为终态，也可以只是第五层应用状态机的入口。SSH、WireGuard
等当前没有进一步品牌细分的协议可直接终态；HTTP、TLS、QUIC 通常继续等待
Host/SNI/ALPN 等结构化事实。

### 3.4 第四层：结构化特征提取

parser 将 payload 转换为调用期只读事实：

```c
enum natflow_dpi_feature_type {
	NATFLOW_DPI_FEAT_HTTP_HOST,
	NATFLOW_DPI_FEAT_HTTP_METHOD,
	NATFLOW_DPI_FEAT_TLS_SNI,
	NATFLOW_DPI_FEAT_TLS_ALPN,
	NATFLOW_DPI_FEAT_QUIC_SNI,
	NATFLOW_DPI_FEAT_DNS_QNAME,
	NATFLOW_DPI_FEAT_NATIVE_PROTOCOL,
};
```

feature 中的字符串指针只在当前调用链有效，不得保存到 conntrack 或异步队列。

### 3.5 第五层：硬编码应用状态机

第四层事实决定选择哪台机器：

```text
HTTP feature -> HTTP_APP_MACHINE
TLS feature  -> TLS_APP_MACHINE
QUIC feature -> QUIC_APP_MACHINE
DNS feature  -> DNS_APP_MACHINE
native high-confidence protocol -> direct terminal app_id
```

机器内部使用显式 `switch (state)` 和静态只读 matcher。没有候选的机器不会执行，
已经由某台机器接管后也不再遍历其他 detector。

## 4. 结果、状态和 ID

### 4.1 `app_id` 是稳定 UAPI

固定 ID 编译进 `natflow_dpi.h`，发布后不得改号、复用或因表项排序变化而变化。
建议分段预留，但运行时不得依赖数值范围推断属性：

```text
0x00000000              UNKNOWN/PENDING
0x00000001-0x000000ff   基础协议终态
0x00000100-0x000001ff   Web/加密协议兜底终态
0x00001000-0x00001fff   视频/流媒体应用
0x00002000-0x00002fff   通信应用
0x00003000-0x00003fff   游戏应用
```

应用名称、类别和基础协议由静态元数据表表达：

```c
struct natflow_dpi_app_meta {
	u32 app_id;
	u16 category_id;
	u16 base_proto;
	const char *name;
};
```

表仅用于控制面输出、事件填充和一致性校验；热路径识别不能线性扫描该表。

### 4.2 状态机返回值

`app_id == 0` 不能同时表达 pending、excluded 和 budget exhausted，因此机器返回
显式状态：

```c
enum natflow_dpi_result_status {
	NATFLOW_DPI_RESULT_PENDING,
	NATFLOW_DPI_RESULT_TERMINAL,
	NATFLOW_DPI_RESULT_EXCLUDED,
	NATFLOW_DPI_RESULT_LIMIT,
};

struct natflow_dpi_result {
	u32 app_id;
	u8 status;
	u8 source;
	u8 confidence;
	u8 reserved;
};
```

约束：

- `TERMINAL` 必须携带非零且已登记的固定 `app_id`。
- 非 `TERMINAL` 必须携带 `app_id=0`。
- 只有统一 commit helper 可以写 `nf->app_id` 和产生 match event。
- 第一个成功终态获胜；后续识别不得用弱证据覆盖非零 `app_id`。

### 4.3 基础协议和应用分离

内部 `base_proto`、`machine_id`、`state_id` 不属于 UAPI，也不等于 `app_id`：

```text
TCP -> TLS -> SNI -> YouTube
       ^             ^
       base_proto    terminal app_id
```

不能在刚确认 TLS 时立刻写 generic TLS，除非扫描预算已经耗尽且设计明确选择
generic TLS 作为兜底终态。

## 5. 静态目录和域名分类

### 5.1 初始固定目录

第一阶段直接覆盖当前已有高确定性 detector 的 18 个协议，并为后续域名应用
预留固定 ID。首批域名应用应以维护者单独审核过的静态表为准，不从用户规则加载。

当前协议 detector 的直接终态包括：DNS、SSH、WireGuard、STUN、TURN、
BitTorrent、FTP、SMTP、POP3、IMAP、SIP、RTSP、MQTT、RESP、MySQL、
PostgreSQL、RDP 和 SMB。

### 5.2 域名 matcher

HTTP Host、TLS SNI、QUIC SNI 和 DNS QNAME 共用同一规范化和静态域名分类器，
但事件必须保留 feature source。优先级固定为：

```text
exact
  > longest label-boundary suffix
  > shorter label-boundary suffix
  > protocol fallback
```

suffix 必须检查 DNS label 边界。例如 `badgooglevideo.com` 不得命中
`googlevideo.com`。

静态表按 hostname 长度从长到短排列，构建时使用 `BUILD_BUG_ON`、单元检查或
生成期脚本验证顺序、重复项、合法 label 和固定 app ID；数据面仍只扫描被选择的
小型应用表。若域名数量明显增长，再评审静态 trie/hash，不预先引入通用引擎。

DNS QNAME 只给 DNS flow 或“查询意图”分类，不能把该结果当作另一个连接的证据。

## 6. Dispatcher 和手写状态机

### 6.1 两阶段调度

Discovery 阶段只运行便宜的候选裁剪：

```text
L4 + direction + server-port hint + payload prefix
  -> candidate machine class
```

Claimed 阶段由一个机器接管：

```text
machine_id + state_id + new feature
  -> next state / terminal / excluded / limit
```

禁止 `for each app`。允许遍历一个很小且编译期有上限的候选机器数组；候选选定后
必须只调用对应机器。

### 6.2 C 代码形态

```c
static struct natflow_dpi_result
natflow_dpi_tls_app_step(struct natflow_dpi_flow *flow,
			 const struct natflow_dpi_feature *feature)
{
	switch (flow->state) {
	case NATFLOW_DPI_TLS_APP_INITIAL:
		if (feature->type != NATFLOW_DPI_FEAT_TLS_SNI)
			return natflow_dpi_pending();
		flow->state = NATFLOW_DPI_TLS_APP_HAVE_SNI;
		return natflow_dpi_match_domain(feature);
	case NATFLOW_DPI_TLS_APP_HAVE_SNI:
		/* 可用后续 ALPN 或其他确定性事实继续细分。 */
		return natflow_dpi_pending();
	default:
		return natflow_dpi_excluded();
	}
}
```

每台机器必须声明：输入 feature、方向、最大包数、最大字节数、最大状态数、终态、
排除条件和误判模型。

## 7. 每流状态与并发

### 7.1 8 字节边界

当前 `natflow_t` 已有 8 字节瞬态 DPI context。第一阶段保持结构大小不变：

- 双向 byte counter：4 字节；
- 双向 packet counter：2 字节；
- 最后 2 字节逐步从 8-bit detector mask 迁移为 compact automaton word。

概念编码：

```text
bit 15 = 0: discovery candidate-class mask
bit 15 = 1: claimed machine/state
             bits 14..8 machine_id
             bits 7..0  state_id
```

这允许最多 127 台机器、每台 256 个状态。实际首期远低于该上限。若某协议需要
保存 nonce、challenge、长 prefix 或多 candidate 数组，必须申请独立、可证明上限
的 context；不能挤入该字段或扩大所有 conntrack。

### 7.2 并发更新合同

同一 conntrack 的双向包可能并发进入：

- 状态转换必须单调、幂等；
- commit 使用 `READ_ONCE/WRITE_ONCE` 并坚持第一个非零 `app_id` 获胜；
- compact automaton word 作为整体更新，不能分别写 machine/state；
- 真正加入多包状态转换前，必须评审 `cmpxchg` 或有界 owner 方案；
- 不依赖非原子 `nf->status` writer 保证状态机顺序。

第一阶段可先把现有单包 detector 迁移为静态直接终态；只有具备并发测试后才开放
需要严格 A -> B -> C 的跨包机器。

## 8. 控制面和事件 ABI

### 8.1 `/dev/natflow_dpi_ctl`

保留：

- `enable=0|1`；
- 状态、固定 catalog revision、app 数量和 counters；
- `events_clear`。

删除：

- `rules_begin`、`domain`、`proto`、`rules_commit`、`rules_abort`、`rules_clear`；
- pending/active ruleset、RCU 规则发布和动态 proto mask。

启用 DPI 即启用内置分类器。配置变化仍不枚举或重新武装旧连接。

### 8.2 `/dev/natflow_dpi_queue`

迁移首期保留 v3 固定头大小，降低用户态工具同步成本：

- `app_id` 为固定 catalog ID；
- `category_id` 来自静态元数据；
- `generation` 改为固定 catalog revision；
- `rule_id` 固定为 0，标记结果不来自用户规则。

如果后续要删除 `rule_id` 或新增 machine/state evidence，应升级事件版本，不复用 v3
字段的其他含义。

## 9. Fast path 和生命周期

- DPI enabled 时，新 eligible flow 进入内置分类器，不依赖 ruleset 是否非空。
- 等待更多包时保持 `NF_FF_L7_USE`/`NF_FF_DPI_USE`，阻止提前 offload。
- terminal、excluded、transport end 或预算耗尽后清理瞬态 context 并设置对应 done。
- URL consumer 与 DPI consumer 继续独立；URL 失败或关闭不能结束 DPI。
- `app_id` 非零后 DPI 终态，不再重新识别或覆盖。
- disable 只影响后续 active consumer，不扫描全局 conntrack，不清理已有连接。

## 10. 实施计划

### M0：设计冻结

- 本文成为新目标架构。
- 更新 `docs/agent/DECISIONS.md`、`ROADMAP.md` 和长期记忆。
- 明确固定 ID、控制 ABI 迁移和测试边界。

退出条件：文档一致，`git diff --check` 通过。

### M1：固定 app catalog 和统一 commit helper

- 在公共 DPI 头中定义稳定 `app_id`、category 和 base protocol。
- 增加静态 app metadata lookup。
- 增加统一 terminal commit helper，保证只写合法固定 ID。
- 暂不改变 detector 行为，用编译检查和用户态测试固定 ID。

退出条件：构建矩阵通过，`natflow_t` 大小不变。

### M2：协议 detector 静态化

- 现有 18 个 protocol detector 命中后直接映射固定 `app_id`。
- active detector mask 改为编译期候选，不再来自 proto ruleset。
- 移除 protocol rule lookup 和 `proto_no_rule` 路径。
- 更新 75 项 corpus，使其不再创建 proto rules。

退出条件：正反 corpus 结果与当前 detector 证据边界一致，只改变 app ID 来源。

### M3：域名应用状态机

- 把 HTTP Host、TLS/QUIC SNI 和 DNS QNAME 接入统一静态 matcher。
- 首批每个应用及其域名表单独评审并增加正反 corpus。
- 基础协议事实保持 pending，只有应用终态或预算兜底才写 `app_id`。

退出条件：label-boundary、最长 suffix、source 和过早终态测试全部通过。

### M4：移除用户 ruleset ABI

- 删除 ruleset parser、pending/active RCU 对象和规则计数。
- 收敛 ctl status 和 smoke 工具。
- 同步 README、系统规格、事件 reader 注释和部署示例。

退出条件：旧规则命令明确返回 `-EINVAL`，enable 后无需规则即可分类。

### M5：compact automaton 和多包状态

- 把最后两个 context 字节迁移为 automaton word。
- 先实现一台确有 A -> B -> C 需要的机器。
- 补双向并发、乱序、重传、预算和 transport end 测试。

退出条件：状态转换单调可证明，未扩大 `natflow_t`，没有无界等待或扫描。

### M6：验证和发布

- 对本轮 C/H 文件运行 `astyle -t -n`。
- 运行 `git diff --check`、基础构建和完整 build matrix。
- 运行 corpus、queue pressure、queue stream；真机项目无法执行时明确记录。
- 使用 `.su`/`size`/`nm` 复核栈、代码体积和热路径增长。

## 11. 提交拆分建议

每个里程碑独立提交，避免把 ABI 删除、数据面迁移和测试重写混成一个不可审查的
commit：

1. `docs: define hardcoded DPI application state machine`
2. `dpi: add fixed application catalog`
3. `dpi: map protocol detectors directly to app ids`
4. `dpi: add static domain application classifier`
5. `dpi: remove runtime classifier rules`
6. `dpi: add compact handwritten automaton state`

本设计文档本身不授权自动提交；提交仍按维护者明确指令执行。
