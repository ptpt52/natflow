# QoS 缓存验证

宿主机预约与 CPU 绑定回归：

```sh
sh tests/qos/run.sh
```

从当前源码提取预约函数和 bucket 结构，编译实际实现，模拟 skb payload 长度、
时钟和 spinlock。ASan/UBSan 覆盖突发平滑、时延边界、组/用户共同限速、
不限速、零 payload、空闲不积累 burst、generation 切换、最高速率的向上
取整和 8 线程共享组的 800 次无重复预约。

同时直接编译 `natflow_qos.c`，以逻辑 CPU、timer/tasklet、树、hook 和引用
模型检查：快路径发送及 IPv4/IPv6/bridge POST continuation 的 CPU 与入队
一致；固定 CPU 的 timer 重置、相同时间的 FIFO、128 包预算；CPU 下线清队、
上线复用、意外迁移不访问远程树；其他 CPU 发起 generation reset 不远程启动 timer；
全局 4096 包/8 MiB 上限；分配、dst、socket 和 hotplug 注册失败；逐包引用
平衡；三个 CPU 并发入队的 2400 个 skb。

新增本 CPU BH 互斥模型和树访问断言，检查所有树操作在所属 CPU 的 BH 禁用
区域执行。三 CPU 两组各 9000 次入队分别打满包数/内存上限，并发读取统计
确认额度不瞬时超限，失败不泄漏额度，清队后归零。受控竞态暂停 CPU 0 的
入队（已预占包数、未预占内存），同时开始配置清队和 CPU 下线，验证 CPU 1
仍能推进入队，清队同步等待本地操作完成，返回后所有旧包/额度被回收。
另验离线 CPU 不接收清队工作、重新上线继承最新 generation。

树模型不实现 RB 平衡；u64_stats_sync 使用读写锁模型，不模拟真实 seqcount。
逻辑 CPU 模型不执行真实内核软中断、CPU hotplug 或 RCU 调度。

目标设备测试需在可重置的测试路由器上进行，保存配置后对比 `buffer_ms=0`
和 `buffer_ms=100`：

1. TCP/UDP 双向施加超过限速值的突发流量，用接收端抓包比较 10 ms 时间窗
   的字节分布、丢包、TCP 重传、吞吐和 RTT；分别覆盖规则限速、用户限速、
   两者同时启用、两个用户共享组和多个独立规则。限速值必须至少为 HZ。
2. 覆盖 IPv4、IPv6、软件快路径、禁用 path 的慢路径、bridge、PPPoE、VLAN，
   以及 GSO 开关。以数据包为粒度检查延迟，不能用用户统计当作发送完成时间。
3. 用 POST_ROUTING priority >110 的计数/drop hook 验证延迟放行后仍执行
   后续 hook；确认新连接完成 conntrack confirm，NAT/PPPoE 正确且用户统计
   只增加一次。并发增删其他 hook，确认不使用失效的保存索引。
4. 产生多个方向/规则的大量小包和大 skb，检查控制读出的 packets <=4096、
   memory <=8388608；时延或资源超限时 dropped 增加，停止流量后占用归零。
   buffer_ms=-1/1001/非数字应失败；0/1/1000 应被接受。
5. 排队期间执行 clear、buffer_ms 切换、classid 模式切换、规则重载、用户
   速率更新、设备删除、模块卸载/重载。以 KASAN/lockdep 检查引用、锁顺序、
   hrtimer/tasklet 清理和无双重释放；验证旧 generation 不重新入队。
6. 用 ftrace/kprobe 或测试探针记录 skb 入队和 Natflow 出队发送/后续 hook
   的 CPU，核对每个缓存 skb 的 CPU 一致；覆盖多接收队列和 RPS。排队期间
   下线对应 CPU，确认其未发送缓存计入 dropped、释放引用且不迁移续发；
   重新上线后恢复入队。后续 qdisc/驱动的执行 CPU 不属于此保证。

这些目标设备测试未由宿主机回归自动执行。
