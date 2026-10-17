# QoS 缓存验证

宿主机预约算法回归：

```sh
sh tests/qos/run.sh
```

从当前源码提取预约函数和 bucket 结构，编译实际实现，模拟 skb payload 长度、
时钟和 spinlock。ASan/UBSan 覆盖突发平滑、时延边界、组/用户共同限速、
不限速、零 payload、空闲不积累 burst、generation 切换、最高速率的向上
取整和 8 线程共享组的 800 次无重复预约。不模拟真实内核 timer、RCU、
红黑树或网络 continuation。

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

这些目标设备测试未由宿主机回归自动执行。
