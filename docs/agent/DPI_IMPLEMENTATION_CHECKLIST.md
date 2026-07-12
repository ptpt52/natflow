# DPI 实现基线检查清单

本文记录 `DPI_DESIGN.md` 进入实现阶段时每个提交必须自审的基线。它不替代源码和设计文档，只用于避免后续小步提交破坏 legacy URL logger、Host ACL、conntrack layout 和 fast path 协作。

## 通用提交流程

每个实现步骤按以下顺序执行：

1. 修改前确认 `git status --short`，避免覆盖未提交改动。
2. 只做当前阶段的最小改动，不把后续阶段的 ABI、策略动作或 detector 顺手塞进同一提交。
3. 修改后先做代码自审，重点看热路径、锁、RCU、conntrack extension、skb 读写边界和旧 ABI。
4. 修复自审发现的问题后再提交。
5. 人工流量验证、生产 shadow 和需要外部用户态工具的测试可以暂时跳过，但必须记录未执行原因。

## Legacy URL logger 基线

M0/M1 期间必须保持：

- `/dev/urllogger_queue` 设备名、读取方式和 CSV 字段兼容。
- `/proc/sys/urllogger_store/enable=0` 仍同时关闭 URL 记录和 Host ACL 处理。
- `/proc/sys/urllogger_store/*` 其他节点路径、默认值和读写语义兼容。
- `CONFIG_NATFLOW_URLLOGGER` 仍独立控制 legacy URL logger 和 Host ACL 能力。
- `CONFIG_NATFLOW_URLLOGGER_LOCAL_IN` 的 legacy local-in 行为不能影响 DPI 的 forward/bridge hook 目标。

## Host ACL 基线

M0/M1 期间必须保持：

- `/dev/hostacl_ctl` 命令格式、槽位范围和动作值兼容。
- Host ACL 继续依赖 `urllogger_store/enable`，DPI enable 不能让 Host ACL 单独生效。
- reset、drop、redirect 和 allow/bypass 的优先级不因 DPI 默认关闭而改变。
- 若拆分 parser/consumer，Host ACL 可以消费共享 feature，但不能依赖 URL record 分配成功。

## Conntrack 与 fast path 基线

M0/M1 期间必须保持：

- `NF_FF_L7_USE` 和 `NF_FF_DPI_USE` 必须纳入 `NF_FF_BUSY_USE`；shared HTTP/TLS/QUIC parser 使用 L7 busy bit，URL/DPI-domain/DPI-packet consumer 终态分别使用 `NF_FF_L7_URL_DONE`/`NF_FF_L7_DPI_DOMAIN_DONE`/`NF_FF_L7_DPI_PACKET_DONE` 且不纳入 busy mask，后续独立 DPI context 使用 DPI busy bit。
- `natflow_t` 只追加 `app_id` 作为常驻 DPI flow result；其他 DPI 细节只进入 terminal event。
- 追加字段前必须验证 shared conntrack extension 布局，失败时不能注册 DPI/L7 hook。
- L7 入口必须先调用 `natflow_session_in()` 统一确保 URL/DPI 终态有 `natflow_t.status` 可写；已 confirm 且没有 natflow session 的 flow 仍不能安全追加扩展，必须 fail-open 跳过 L7 解析，不能退回无状态 DPI/URL 事件。
- writer 顺序保持为：写结果、写对应 consumer terminal done bit、所有 active consumer 均 done 后清 busy bit 并设置 `IPS_NATFLOW_L7_HANDLED` L7_SKIP 派生 hint。

## DPI ABI 基线

新增 DPI ABI 前必须先冻结：

- `/dev/natflow_dpi_ctl` 的命令、错误返回和状态输出。
- `/dev/natflow_dpi_queue` 的固定事件头、长度、版本、短 buffer 行为、poll/read 语义。
- `app_id=0` 永远表示 unknown、未命中、未分类或尚无结果。
- DPI 默认关闭、fail-open、audit-only；drop/reset/QoS 不进入 M1。

## 自动检查建议

每个代码提交至少尝试：

```sh
git diff --check
make
make EXTRA_CFLAGS="-DCONFIG_NATFLOW_URLLOGGER"
make EXTRA_CFLAGS="-DCONFIG_NATFLOW_DPI"
make EXTRA_CFLAGS="-DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER -DCONFIG_NATFLOW_DPI"
make NO_DEBUG=1 EXTRA_CFLAGS="-DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER -DCONFIG_NATFLOW_DPI"
```

若当前环境缺少内核头文件或某个配置尚未实现导致构建失败，提交说明或最终结果必须说明失败原因，不能标记为已验证。
