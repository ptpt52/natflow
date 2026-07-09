# Natflow 深度包检测 (DPI) 详细设计文档

## 1. 设计背景与总体定位

### 1.1 背景
Natflow 目前已经具备 `urllogger`，能够解析 HTTP Host/URI、TCP TLS SNI、QUIC Initial SNI，并支持基础的 Host ACL 拦截。为了支持更精细的访问控制、QoS 流控策略以及上层审计需求，需要在内核级别引入应用层级的 DPI（深度包检测）识别能力。

### 1.2 总体定位
* **轻量级与机会性**：本 DPI 设计不追求成为全量重载的 WAF 或反规避网关。
* **Fast-Path 友好**：以不拖累内核转发性能为第一要务。识别出应用后立刻交由 Fast Path 加速，避免持续全包深度检测。
* **高度复用**：最大程度复用现有的协议嗅探、HTTP/TLS/QUIC 提取逻辑，避免重造轮子。

## 2. 核心架构与数据建模

DPI 系统在架构上分离了**特征提取（解析器）**和**特征匹配（规则引擎）**两部分。

### 2.1 应用与类别定义模型
将应用抽象为数字 ID 与属性，避免内核中充斥大量字符串比较。
```c
// 应用定义基础信息
struct dpi_app_info {
    uint32_t app_id;          // 全局唯一的应用 ID (例如: 1001 代表微信)
    uint16_t category_id;     // 应用分类 ID (例如: 社交=1, 视频=2)
    uint16_t flags;           // 标志位 (例如: 流量特征是否易混淆)
};
```

### 2.2 结构化特征匹配字典
内核层面不使用正则表达式，采用**层级化、基于树/表**的快速匹配结构。
1. **L7 域名/主机字典** (优先级最高)：
   * 采用前缀树/基数树 (Radix Tree) 或 Hash 表实现。
   * **输入**：从 `urllogger` 提取出的 SNI 或 HTTP Host（如 `v.qq.com`，`*.googlevideo.com`）。
   * **输出**：映射到对应的 `app_id`。
2. **L3/L4 五元组字典** (兜底机制)：
   * 采用 Hash 表或 IP 网段树 (类似 IPSet)。
   * **输入**：目标 IP/网段 + 目标端口 + 协议 (TCP/UDP)。
   * **输出**：映射到对应的 `app_id`。
3. **L7 载荷偏移特征字典 (Payload Offset 匹配)**：
   * 针对无明显域名特征或私有应用协议（如游戏、特定 P2P 等）。
   * **输入**：数据流前 N 个报文中，在特定的一个或多个偏移量 (`offset`) 处，提取特定长度 (`len`) 的字节，并与特征内容（如 Hex 字符串）进行比对。
   * **输出**：所有指定的 offset 条件均匹配时，映射到对应的 `app_id`。
   * *注意：内核级匹配应限制匹配深度与检测报文数，严格避免全文正则搜索和不确定宽度的遍历，以保障性能。*
4. **L7 HTTP 头部特征字典 (如 User-Agent 匹配)**：
   * 针对依赖 HTTP 特殊请求头（如特定 APP 的 User-Agent 关键字）识别的应用。
   * **输入**：从 HTTP 报文中提取的特定 Header 字段值（例如 `User-Agent: MicroMessenger/...`）。
   * **输出**：当值中包含指定的关键字（子串匹配）时，映射到对应的 `app_id`。
   * *注意：内核中仅做固定边界的简单子串匹配 (Substring Matching) 或前缀匹配，并需控制提取的 Header 最大长度，防止内存安全风险。*
5. **L7 HTTP Path 与 URI 特征字典**：
   * 针对同一域名下根据路径区分不同业务的场景。
   * **输入**：从 HTTP 报文中提取的 URI 或 Path 字段。
   * **输出**：前缀或包含匹配命中时，映射到对应的 `app_id`。
6. **L7 TLS 客户端指纹字典 (JA3 / JA4)**：
   * 针对强混淆代理软件或非标客户端的识别。
   * **输入**：通过 TLS Client Hello 的版本、加密套件、扩展等字段计算出的特征 Hash 值 (如 JA3 MD5)。
   * **输出**：Hash 值命中时，映射到对应的 `app_id`。
7. **DNS Snooping 动态 IP 关联缓存**：
   * 解决纯 IP 直连或 ECH（完全加密无 SNI）场景下的流量识别。
   * **输入**：通过嗅探 DNS 响应包，动态建立起 `IP -> Domain` 的临时生命周期映射。后续无特征流量只需查 IP 即可关联回原始域名。
   * **输出**：IP 命中动态缓存表时，映射到该域名对应的 `app_id`。

### 2.3 多条件组合匹配 (Compound Rules)
单一维度的特征往往不足以精确定位应用（例如需要同时匹配 HTTP Host 和 URI 才能区分主站与某个特定子业务）。
* 内核规则引擎支持**多条件组合 (AND 逻辑)**。一条规则可同时要求命中 `Host` + `URI` + `User-Agent`。
* **高性能查表算法**：为避免内核中出现 O(N) 的线性遍历，匹配引擎以区分度最高的特征（通常是 Domain/SNI）作为**一级索引 (Primary Index)** 构建 Trie 树。
* **候选链表**：一级索引查表命中后，返回的不是单一的 `app_id`，而是一个**候选规则链表 (Rule Candidates)**。随后在链表中执行次要条件（如 URI、UA 子串）的校验。只有所有要求条件均满足，才算最终命中对应的 `app_id`。

## 3. 识别流程与状态机 (DPI Pipeline)

核心思路是：**拦截首包 -> 提取元数据 -> 查表匹配 -> 缓存结果 -> 释放交由 Fast Path**。

### 3.1 状态机设计 (Conntrack 联动)
新增或复用一个“忙碌位”（Busy Bit），如 `NF_FF_DPI_INSPECTING`。
* 当一条新建流（New Flow）建立时，默认置起 `NF_FF_DPI_INSPECTING`。
* 只要该标志位存在，`natflow_path` (Fast Path) 就会放弃接管该流，强制报文走慢路径供 DPI 解析。
* 一旦 DPI 解析完成（或超时失败），清除该标志位，并写入 `app_id`。

### 3.2 具体识别步骤
1. **流量拦截**：首个包到达 Hook 点，状态机为 `INSPECTING`。
2. **协议分类与元数据提取**：
   * 复用 `natflow_urllogger` 逻辑，识别魔数 (Magic Number)。
   * **DNS 嗅探**：如果开启 DNS Snooping，嗅探 DNS 响应包提取 A/AAAA 记录，更新动态 IP 关联表。
   * 从 HTTP 中提取 `Host`、`URI/Path` 以及其他指定的关键 Header（如 `User-Agent`）。
   * 从 TLS Client Hello 提取 `SNI`，并提取相关字段计算 `JA3` 指纹 Hash。
   * 从 QUIC Initial 包提取 `SNI`。
3. **查表规则匹配 (Rule Matching)**：
   * **动态关联兜底**：对于新建立的无特征加密流，先查 **DNS Snooping 动态缓存表**，命中则继承 `app_id`。
   * 如果成功提取出域名/SNI 或 HTTP 特征，送入 **L7 组合规则引擎**：
     * 以域名/SNI 作为一级索引查 Trie 树，获取候选规则链表。
     * 遍历校验链表中的次要条件（如对应的 HTTP Path 前缀、User-Agent 关键字等）。
     * 若某条组合规则的所有条件均命中，则返回其 `app_id`。
   * 对于 TLS 协议，若未命中域名规则，将计算出的 JA3 Hash 送入 **L7 TLS 客户端指纹字典** 匹配。
   * 对于未命中上述规则或非 HTTP/TLS 流，执行 **L7 载荷偏移特征 (Payload Offset)** 匹配。根据配置提取报文指定 `offset` 处的内容，如果一组 offset 的特征全部命中，返回 `app_id`。
   * 如果以上所有手段皆未命中，最终将 IP+Port 送入 **L3/L4 五元组字典** 进行静态查表兜底。
4. **结果缓存与释放**：
   * 将匹配到的 `app_id` 和 `category_id` 写入到当前连接的 `conntrack` 扩展或 `mark` 中。
   * 清除 `NF_FF_DPI_INSPECTING` 位。
5. **策略执行**：
   * 后续模块 (QoS、Host ACL) 根据该流缓存的 `app_id` 直接下发限速或阻断策略。
   * `natflow_path` 察觉 `INSPECTING` 位清除，正式接管后续报文进行硬件/软件卸载加速。

## 4. 用户态接口与 ABI (Userspace Interface)

为保持与当前 Natflow 架构一致，设计如下 ABI：

### 4.1 规则下发接口
新增类似 `/dev/natflow_dpi_ctl` 的字符设备（或复用现有设备指令）：
* **下发/删除应用映射记录**：`add_app <app_id> <category_id> <name>`
* **下发/删除 L7 域名特征**：`add_domain_rule <domain> <app_id>` (支持泛域名如 `*.youtube.com`)
* **下发/删除 L3/L4 特征**：`add_ip_rule <ip/cidr> <proto> <port> <app_id>`
* **下发/删除 Payload Offset 特征**：`add_payload_rule <app_id> <proto> <offset1,len1,hex_str1> [offset2,len2,hex_str2...]`
* **下发/删除多条件组合特征 (Compound Rule)**：`add_compound_rule <app_id> [domain=<xxx>] [path=<xxx>] [ua=<xxx>]` (支持动态组合 AND 逻辑)
* **下发/删除 TLS JA3 特征**：`add_tls_ja3_rule <app_id> <ja3_md5_hash_string>`
* **配置 DNS Snooping**：`set_dns_snooping <0|1>` (开启/关闭动态 DNS 到 IP 的嗅探关联)

> *注：为了兼容性，写入命令以 `\n` 结尾，单条命令限制 `MAX_IOCTL_LEN` 内。*

### 4.2 审计日志输出
新增独立的 `/dev/dpi_queue` 字符设备用于输出 DPI 审计日志，避免直接修改 `urllogger_queue` 破坏现有 ABI。
```c
struct natflow_dpi_log_info {
    // 基础流信息
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    
    // DPI 识别结果
    uint32_t app_id;        // 识别出的应用 ID
    uint16_t category_id;   // 应用分类 ID
    
    // 其它可选扩展的元数据 (如匹配到的具体特征)
};
```
（采用独立的输出队列可以使得 DPI 模块与 URL Logger 解耦，方便外部消费程序单独开启和拉取应用分类日志）。

## 5. 降级机制与约束条件 (Limitations & Fallbacks)

* **识别超时**：为防止恶意的空流或慢速攻击导致流永远停留在慢路径。必须设定包数阈值（如前 5 个包）或时间阈值（如 2 秒）。若超时未提取出特征，强行结束 DPI，`app_id` 标记为 `UNKNOWN` 并移交 Fast path。
* **加密与混淆 (ECH)**：对于启用了 TLS ECH (Encrypted Client Hello) 的流量，无法提取 SNI。DPI 会自动降级到 L3/L4 IP+Port 特征匹配。若无法命中，归类为未识别。
* **分片处理**：对跨包分片、TCP 乱序严重的情况，不进行复杂的重组缓冲（控制内存栈开销），采取机会性截断处理，必要时降级跳过。

## 6. 分阶段实施计划 (Implementation Phases)

* **Phase 1: 被动审计输出 (MVP)**
  * 定义 `dpi_app_info` 数据结构。
  * 实现基于 Hash/Trie 的内核特征字典。
  * 新增 `/dev/dpi_queue` 输出 DPI 的独立审计日志，对外部可见。不干扰现有 Fast Path，也不破坏原有 URL logger ABI。
* **Phase 2: 状态机与 Fast Path 对接**
  * 引入 `NF_FF_DPI_INSPECTING` busy bit。
  * 改造 `natflow_path`，强制在 DPI 完成前等待。
* **Phase 3: QoS 与访问控制联动**
  * 修改 QoS 模块，支持依据 `app_id` 进行独立限速。
  * 修改 Host ACL，支持下发 `app_id` 级别的 Block/Redirect 规则。
