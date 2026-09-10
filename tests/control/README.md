# 控制输入与配置并发回归

宿主机输入解析回归：

```sh
sh tests/control/run.sh
```

测试直接编译 `natflow_control.h`（仅删除内核 include），用 pthread mutex、
模拟 copy_from_user 和 seq 分配替代内核设施。ASan/UBSan 检查两个 open
交错半行、续写空白、短写多行、0 字节写、256/512 字节边界、关闭后重新
打开、部分 copy 失败、解析错误、EAGAIN 完整重试、读写缓冲分离和同 open
8 线程共 16000 次写入。测试不加载模块，不证明内核 RCU 或真实 uaccess
并发安全。运行目录和二进制保留在打印出的 `/tmp/natflow-control-test.*`。

## 目标机补充验证（未自动运行）

仅在可重置配置的测试路由器上执行；以下测试会清空/替换认证和 QoS 规则，
不能在生产机上直接运行。先保存现有配置，准备串口/远程日志，结束后由部署
脚本恢复。建议分别启用 KASAN、KCSAN 和 lockdep 的调试固件。

1. 在多个独立 fd 上并行循环 auth `clean`、`auth id=1,szone=1,type=auto,sipgrp=test`、
   `dst_bypasslist_name=test`、`src_bypasslist_name=test`、`update_magic`；
   同时持续读取 auth control。test ipset 应预先创建，规则必须完整且数量不超过 16。
2. 多 fd 并行循环 QoS `clear`、`tc_classid_mode=0/1` 和完整 IPv4/IPv6 `add`；
   同时读取 QoS control，规则数不超过 64。另做无 clear 的容量测试：auth
   第 17 次追加返回 ENOMEM；QoS 第 65 次保留既有忽略语义，读出仍为 64 条。
3. 上述更新期间持续发送 IPv4/IPv6 双向流量，覆盖 auth/bypass、QoS 首次匹配、
   原有连接、clear 后槽位复用、零速率和 classid 标记。检查无 refcount、UAF、
   OOB、RCU、KCSAN 或 lockdep 告警，核对 classid 奇偶方向与限速行为。
4. 验证 clean/add 不自动改变 auth magic，仅 update_magic 增加；无法分配新
   快照时返回 ENOMEM 且原规则保持不变。验证反复卸载/加载后旧快照无残留。
5. userinfo kickall 在 EAGAIN 后重发完整命令，conntrackinfo kickall 检查权限
   及原有过滤语义；这里不包含 conntrack hash 扩缩容一致性问题的修复。

写者必须处理短写。每条命令是一次配置发布，不保证整个 reload 原子；并发
配置内容的最终顺序以实际锁获取顺序为准。不要把无告警的宿主机解析测试当作
目标固件上的并发压力验证。
