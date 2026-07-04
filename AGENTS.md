# AGENTS.md

本文件是智能体进入 natflow 仓库后的启动入口，作用范围为整个仓库。

## 仓库定位

Natflow 是一个 Linux 内核模块，围绕 Netfilter、conntrack、NAT、ipset、字符设备和可选硬件 NAT/WED offload，实现路由/NAT 快速转发、用户认证、QoS、URL/SNI 记录和主机访问控制。

代码是最终事实来源。文档是压缩后的长期记忆，帮助智能体更快恢复上下文、减少重复扫描，并把重要设计约束显式化。

## 启动顺序

每次开始工作先按顺序读取：

1. `AGENTS.md`。
2. `docs/agent/MEMORY.md`。
3. 与任务相关的源码和头文件。
4. 与任务相关的 `SYSTEM_DESIGN_SPEC.md` 章节。
5. 如果影响用户接口、部署、命令或行为，再读 `README.md` 的相关章节。

开始修改前必须查看工作区状态，避免覆盖用户未提交改动。

## 记忆地图

| 路径 | 角色 |
| --- | --- |
| `natflow_*.c`、`natflow_*.h` | 当前实现，任何结论都要回到源码确认。 |
| `SYSTEM_DESIGN_SPEC.md` | 面向开发、审查和自动化重建的长期技术记忆。 |
| `README.md` | 面向部署和对接人员的公开使用手册。 |
| `docs/agent/MEMORY.md` | 智能体快速恢复上下文的压缩记忆。 |
| `docs/agent/WORKFLOW.md` | 智能体在本仓库中的工作方法。 |
| `docs/agent/DECISIONS.md` | 需要长期保留的设计决策。 |
| `docs/agent/TASK_TEMPLATE.md` | 交给智能体执行任务时的结构化模板。 |

## 工程边界

- 这是内核模块仓库，不是用户态守护进程仓库。不要在没有明确需求时引入 daemon、web server 或复杂构建系统。
- 热路径修改必须谨慎，避免阻塞、重分配、过量日志和无界循环。
- 字符设备控制协议、输出格式、状态值、编译宏和兼容层都属于外部或准外部接口，修改时必须同步更新 `README.md` 和 `SYSTEM_DESIGN_SPEC.md`。
- 兼容旧内核是当前设计的一部分。不要只按单一新内核 API 重写兼容封装，除非明确决定放弃旧内核支持。
- 构建产物、临时备份、索引文件和 Kbuild 生成文件不要纳入记忆或提交。
- 如果文档与源码冲突，以源码为准，并把文档修正作为任务的一部分。

## 修改流程

1. 读取记忆和相关源码，确认真实行为。
2. 给出最小可行改动范围。
3. 修改代码或文档。
4. 做与风险匹配的验证。
5. 若改变了行为、接口、约束或长期判断，同步更新仓库记忆。
6. 最终说明改了什么、如何验证、还有什么风险。

## 记忆更新规则

以下情况需要更新长期记忆：

- 新增、删除或改变字符设备命令、sysctl、输出格式、状态值、编译宏。
- 改变 fast path、user/auth、QoS、URL logger、zone、conntrack dump 的关键流程。
- 改变构建、DKMS、内核兼容策略或部署方式。
- 做出需要后续智能体遵守的工程决策。
- 发现 `SYSTEM_DESIGN_SPEC.md`、`README.md` 或 `docs/agent/MEMORY.md` 与源码不一致。

普通重排、拼写修正和局部实现细节不需要扩大记忆，除非它们影响后续工作判断。

## 验证建议

文档改动至少运行：

```sh
git diff --check
```

代码改动优先运行：

```sh
make
```

需要完整功能时按实际目标追加：

```sh
make EXTRA_CFLAGS="-DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER"
make NO_DEBUG=1 EXTRA_CFLAGS="-DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER"
```

如果当前机器没有匹配的内核头文件或构建环境，必须在结果中说明未能完成构建验证。
