# 采集点内核兼容矩阵

> 目的：baseline-guard 各事件采集点在 4.18 / 5.4 / 5.10 / 6.x 四档内核下的
> 可用性结论与依据，作为跨内核部署与降级路径设计的依据。
>
> 颜色约定：
> - 🟢 绿：原生可用（当前代码形态直接可跑）
> - 🟡 黄：挂点可用，但需降级路径（格内注明）
> - 🔴 红：不可用（格内注明替代方案）
>
> 纪律：每格附依据（特性合入版本号或机制存在性）；未实测、未逐项核实处明确标
> **待实测**，不臆造实测结论。

## 1. 关键机制版本速查（矩阵公共依据）

| 机制 | 上游合入 | 依据 |
|------|----------|------|
| BPF kprobe 程序类型 | 4.1（`2541517c32be`） | deepflow 内核版本特性表 |
| BPF 挂 tracepoint | 4.7（`98b5c2c65c29`） | 同上 |
| perf buffer（`BPF_MAP_TYPE_PERF_EVENT_ARRAY`） | map 4.3（`ea317b267e9d`），`bpf_perf_event_output` helper 4.4（`a43eec304259`） | 同上 |
| BPF ring buffer（`BPF_MAP_TYPE_RINGBUF`） | 5.8（`bf99c936f947`，Andrii Nakryiko） | [BPF ring buffer 原文](https://nakryiko.com/posts/bpf-ringbuf/)、[kernel-internals 对照表](https://kernel-internals.org/bpf/bpf-ringbuf/) |
| BPF LSM（`CONFIG_BPF_LSM`） | 5.7（`641cd7b06c91`） | [Ubuntu Launchpad #1905975](https://bugs.launchpad.net/bugs/1905975)、[openEuler issue](https://gitee.com/openeuler/kernel/issues/IAGNKW) |
| BTF 基础机制 | 4.18（`e8b6b25351c0`） | BPF 特性表 |
| 内核内嵌 BTF / `/sys/kernel/btf/vmlinux`（`CONFIG_DEBUG_INFO_BTF`） | 5.2 | v5.1 的 `lib/Kconfig.debug` 无 `DEBUG_INFO_BTF`，v5.2 有（torvalds/linux 对应 tag 源码核实） |
| RHEL8 的 4.18 BTF backport | RHEL8 系 backport（小版本待实测） | 社区共识（libbpf CO-RE 资料称企业版 4.18 有 BTF backport）；以目标机 `/sys/kernel/btf/vmlinux` 为准 → **待实测** |
| syscall tracepoints（`syscalls:sys_enter_*`） | 早于 4.18（确切首版未逐一核实） | **机制存在性已源码核实**：v4.18 `arch/x86/Kconfig` `select HAVE_SYSCALL_TRACEPOINTS`；v4.18 `kernel/trace/trace_syscalls.c` 动态注册 `syscalls` 系统 per-syscall 事件 |
| `module:module_load` tracepoint | 2009-08（"tracing/events: Add module tracepoints"） | v3.10 / v4.18 / v5.10 / v6.6 / master 的 `include/trace/events/module.h` 源码核实：负载布局均为 `taints(u32) + name(__data_loc)`，四档一致 |
| `tcp_v4_connect` / `inet_csk_accept` 函数 | 远早于 4.18 | 机制存在性：两函数在 v4.18/v5.4/v5.10/v6.x 源码树均存在（非 static，可 kprobe） |

## 2. 主矩阵

| 采集点 | 4.18（RHEL8/CentOS8） | 5.4（Ubuntu 20.04） | 5.10 | 6.x |
|--------|----------------------|---------------------|------|-----|
| LSM file_open（BPF LSM） | 🔴 BPF LSM 5.7 才合入，RHEL8 未 backport；替代：kprobe `security_file_open`（仓库 `bpf/lsm_kprobe.bpf.c`） | 🔴 同上，替代同上 | 🟢 5.7+ 满足，ringbuf 5.8+ 满足 | 🟢 原生 |
| sched_process_exec（tracepoint） | 🟡 挂点存在；ringbuf 需 5.8 → 走 perf buffer 降级 | 🟡 同上 | 🟢 原生 | 🟢 原生 |
| tcp_v4_connect（kprobe） | 🟡 函数存在；ringbuf 降级；RHEL8 BTF backport 下 CO-RE 可用（小版本待实测） | 🟡 函数存在；ringbuf 降级；BTF 可用性以目标机 /sys/kernel/btf/vmlinux 为准（待实测），若无 BTF 需按内核头文件编译 | 🟢 原生 | 🟢 原生 |
| inet_csk_accept（kretprobe） | 🟡 同 tcp_v4_connect | 🟡 同 tcp_v4_connect | 🟢 原生 | 🟢 原生 |
| sys_enter_bind | 🟡 syscall tracepoint 4.18 已存在（源码核实）；ringbuf 降级 | 🟡 同上 | 🟢 原生 | 🟢 原生 |
| sys_enter_sendto（DNS） | 🟡 同 sys_enter_bind | 🟡 同 sys_enter_bind | 🟢 原生 | 🟢 原生 |
| sys_enter_setuid 系 | 🟡 同 sys_enter_bind | 🟡 同 sys_enter_bind | 🟢 原生 | 🟢 原生 |
| sys_enter_capset | 🟡 同 sys_enter_bind | 🟡 同 sys_enter_bind | 🟢 原生 | 🟢 原生 |
| sys_enter_ptrace | 🟡 同 sys_enter_bind | 🟡 同 sys_enter_bind | 🟢 原生 | 🟢 原生 |
| module:module_load | 🟡 挂点存在且负载布局一致（taints+`__data_loc`，v3.10→master 源码核实）；ringbuf 降级 | 🟡 同上 | 🟢 原生 | 🟢 原生（仓库解析按此布局实现，开发机 7.0 运行） |
| sys_enter_mount | 🟡 syscall tracepoint 存在；ringbuf 降级 | 🟡 同上 | 🟢 原生 | 🟢 原生 |
| sys_enter_unshare | 🟡 同上（unshare(2) 自 2.6.16 起存在） | 🟡 同上 | 🟢 原生 | 🟢 原生 |
| sys_enter_setns | 🟡 同上（setns(2) 自 3.0 起存在） | 🟡 同上 | 🟢 原生 | 🟢 原生 |

说明：
- "ringbuf 降级"指事件通道从 `BPF_MAP_TYPE_RINGBUF`（5.8+）降级到 perf buffer
  （`BPF_MAP_TYPE_PERF_EVENT_ARRAY`，4.3/4.4+）。仓库已有 `bpf/lsm_file_perf.bpf.c`
  先例（`Makefile` 中 `-DUSE_PERF_BUFFER` 构建目标）；`priv_watch` / `net_watch`
  的 perf buffer 降级版**尚未实现**，是黄格落地的前提（待开发+实测）。
- 6.x 档"原生"含 `lsm/mmap_file`（5.9+ 钩子；仓库 `bpf/lsm_file.bpf.c` 已用
  `__weak` 兼容 5.8）。
- 5.10 / 6.x 默认假定发行版内核开启 `CONFIG_DEBUG_INFO_BTF`（主流发行版均开启；
  具体镜像仍以目标机 `/sys/kernel/btf/vmlinux` 实测为准）。

## 3. 逐行依据与降级/替代路径

### LSM file_open（BPF LSM）
- **4.18 / 5.4 🔴**：`BPF_PROG_TYPE_LSM` 5.7 合入（`641cd7b06c91`），4.18 与 5.4
  均不可用，RHEL8 亦未 backport（红帽未提供 BPF LSM）。
- 替代路径：kprobe `security_file_open`。LSM 钩子函数自 LSM 框架（2.6 时代）起
  存在，四档内核均有；仓库已实现 `bpf/lsm_kprobe.bpf.c`（始终 perf buffer，
  `Makefile` 有独立构建目标），即 4.18/5.4 档的文件监控走该实现。
- **5.10 / 6.x 🟢**：5.7+ 且 ringbuf 5.8+，仓库默认 `bpf/lsm_file.bpf.c` 直接可用。

### sched_process_exec（tracepoint）
- 挂点本身四档全存在（sched 类追踪点远早于 4.18；BPF 挂 tracepoint 需 4.7+，
  亦满足）。4.18/5.4 的 🟡  solely 因事件通道 ringbuf 需 5.8 → perf buffer 降级。

### tcp_v4_connect（kprobe）/ inet_csk_accept（kretprobe）
- 两个函数在四档内核源码树均存在且非 static，kprobe/kretprobe 基础设施 4.1 起
  支持 BPF —— 挂点层面四档全绿。
- 🟡 的两层前提：① ringbuf 需 perf buffer 降级（同 sched_process_exec）；
  ② CO-RE 需内核 BTF：RHEL8 有 BTF backport（具体小版本 **待实测**）；
  Ubuntu 20.04 GA 5.4 内核的 BTF 可用性**待实测**（以目标机
  `/sys/kernel/btf/vmlinux` 是否存在为准）；若无 BTF 则需按目标内核头文件
  非 CO-RE 编译（或换 HWE 内核）。

### sys_enter_* 系（bind / sendto / setuid 系 / capset / ptrace / mount / unshare / setns）
- syscall tracepoints 机制在 4.18 已存在（`HAVE_SYSCALL_TRACEPOINTS` + 动态注册
  syscalls 事件，v4.18 源码核实）；各系统调用本身远早于 4.18
  （mount/bind/sendto/setuid/ptrace 为 1.0 时代，capset 2.2，unshare 2.6.16，
  setns 3.0）。
- tracepoint 上下文的 syscall 参数为稳定 ABI（`args[]` 数组），不随内核结构布局
  变化 —— 这正是权限/命名空间事件全 tracepoint 选型的核心理由（见第 5 节）。
- 4.18/5.4 🟡 仅因 ringbuf 降级；挂点与解析逻辑四档通用。

### module:module_load
- tracepoint 2009 年即存在，远早于 4.18；负载布局
  `trace_entry(8) + taints(u32) + name(__data_loc u32)` 经 v3.10/v4.18/v5.10/
  v6.6/master 五处源码核实一致 —— 仓库 `bpf/priv_watch.bpf.c` 的解析（按
  `name_loc` 低 16 位偏移 / 高 16 位长度取值）在四档直接适用。
- 备注：bpf/priv_watch.bpf.c 头注释称"5.x 为 module_base/module_size + 内联
  name"——该说法对应 3.10 之前（2.6 时代）的更老布局，对矩阵四档不构成限制。
- 4.18/5.4 🟡 仅因 ringbuf 降级。

## 4. 待实测清单（未验证项汇总）

1. RHEL8 具体小版本是否有 `/sys/kernel/btf/vmlinux`（决定 4.18 档 CO-RE 可用性）。
2. Ubuntu 20.04 GA 5.4 内核是否开启 `CONFIG_DEBUG_INFO_BTF`（决定 5.4 档 CO-RE
   可用性 / 是否必须按内核头文件编译）。
3. `lsm_kprobe` 替代路径在 RHEL8 4.18 上的加载实测（红格替代方案的落地验证）。
4. `priv_watch` / `net_watch` perf buffer 降级版的开发与在 4.18/5.4 上的实测
   （当前未实现，黄格未落地）。
5. `module:module_load` 事件在 5.x 真机上的实际上报字段（布局已源码核实一致，
   但未在 5.x 运行过事件通道）。
6. syscall tracepoints 的确切首次合入版本（矩阵只依赖 4.18 机制存在性，已源码
   核实；如需追溯首版再专项考据）。

## 5. W2D2 先行决策复核（权限事件全 tracepoint 选型）

背景：W2D2 决定将权限/命名空间事件全部挂在 syscall tracepoints
（`sys_enter_*`）与 `module:module_load` tracepoint 上，不采用 kprobe
（`__x64_sys_*`）或 LSM。逐条结论：

1. **挂点可用性（四档）——成立。**
   syscall tracepoints 机制 4.18 已存在（v4.18 源码核实，见第 1 节）；
   `module:module_load` 四档存在且布局一致（源码核实）。bind/sendto/setuid 系/
   capset/ptrace/mount/unshare/setns 各 syscall 本身远早于 4.18。
   → 挂点层面不需要按内核档位调整。
2. **相比 kprobe `__x64_sys_*` 方案的稳定性——成立。**
   kprobe 方案依赖 `sys_call_table`/`__x64_sys_*` 符号，受 `kptr_restrict` 符号
   裁剪与内核改名（`sys_` → `__x64_sys_`）影响；tracepoint 参数取自 pt_regs 快照，
   纯稳定 ABI。四档一致成立。
3. **相比 LSM 方案的能力边界——成立（已知取舍）。**
   sys_enter 不感知调用结果（成功/失败/被 LSM 拒绝），且无法阻断；与"只采集、
   不阻断"的监控定位一致，与内核档位无关。
4. **需调整项：事件通道，而非挂点选型。**
   ringbuf 5.8 才可用，4.18/5.4 两档必须随附 perf buffer 降级通道
   （`priv_watch_perf` / `net_watch_perf`），否则矩阵中的黄格不落地。这是
   W2D2 选型之外必须补齐的交付物，挂点选型本身在四档内核下成立，无需调整。
5. **module_load 解析——无需调整（四档）。**
   仓库解析按 `taints + __data_loc` 布局实现，与 v3.10 以来的实际布局一致
   （源码核实）；头注释中"5.x 布局不同"的说法仅适用于 3.10 之前的 2.6 内核，
   超出当前支持档位。结论：维持现解析。
