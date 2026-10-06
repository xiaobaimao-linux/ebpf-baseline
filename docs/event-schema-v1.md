# 事件 Schema v1

> 状态：v1.0（W4 D3 前置产出）
> 用途：规则 DSL（`docs/rule-dsl-v1.md`）的**唯一字段来源**。DSL 字段名必须与本表一致，禁止新造。
> 口径：以 `events.db` 的 `events.payload` JSON 路径为准（消费线程 enrich 后的落库命名），源码位置逐节标注。

## 1. 顶层公共字段（所有落库事件）

来源：`render_file_payload`（src/baseline/monitor.cpp:1103）、`render_process_exec_event`（src/baseline/monitor_process.cpp:37）、`render_network_event`（src/baseline/monitor_network.cpp:82）、`render_privilege_event`（src/baseline/monitor_privilege.cpp:137）。

| JSON 路径 | 类型 | 含义 |
|---|---|---|
| `event_type` | string | 点分层级事件类型，全集见 §2 |
| `ts` | u64 | 事件时间戳（ns，CLOCK_MONOTONIC 系） |
| `process.pid` | u32 | 触发进程 pid |
| `process.ppid` | u32 | 父进程 pid |
| `process.uid` | u32 | real uid |
| `process.gid` | u32 | real gid |
| `process.comm` | string | 进程名（task comm，≤16 字符，可能截断） |
| `process.exe` | string | 可执行文件路径（exec 事件内核尽力填充；文件事件由 enrich 补） |
| `process.ancestors` | array | 祖先链，见 §3 |
| `container.container_id` | string | 容器短 ID（12 位）；宿主机进程该对象**省略** |

events 表索引列（不在 payload 内，但可用于规则预过滤）：`category`（file/process/priv/ns/network/dns）、`action`、`priority`、`severity`、`exe`、`container_id`。建表 SQL：src/storage/event_store.cpp:235。

## 2. event_type 全集与各类型负载

映射代码：monitor.cpp:982-994（file）、monitor_process.cpp:37-60、monitor_network.cpp:82-137、monitor_privilege.cpp:137-242。

### 2.1 文件类（category=file，LSM file_permission + 变更类钩子）

| event_type | 触发 | 负载字段（`file.*`） |
|---|---|---|
| `file.read` | open 读（内核 MAY_READ 归一化，lsm_file.bpf.c:44-46） | `file.path`(string 完整路径)、`file.ino`(u64)、`file.mask`(u64)、`file.action`(string: allow/alert/block/kill/throttle) |
| `file.write` | open 写 | 同上 |
| `file.access` | 其它访问 | 同上 |
| `file.chmod` | 权限变更 | 同上 + `file.new_mode`(string，如 "0644") |
| `file.chown` | 属主变更 | 同上 + `file.new_uid`(u64)、`file.new_gid`(u64) |
| `file.unlink` | 删除 | 同 file.read |
| `file.rename` | 重命名 | 同 file.read |
| `file.mmap` | mmap 保护位 | 同 file.read |

注意：告警链路（alerts 表）的 `event_type` 是另一套取值（`read`/`write`/`perm_changed`/`own_changed`/`missing`/`hash_changed`/`check_mismatch`/`access_failed`，monitor.cpp:584、monitor_baseline.hpp:20-25），与本表 payload 的 `event_type` 命名体系不同，DSL 一律引用本表。

### 2.2 进程类（category=process）

| event_type | 负载字段 |
|---|---|
| `process.exec` | `process.*` 公共字段（含 exe）；**无 argv/cmdline**（已知边界，dev-log-w2.md:70） |

fork/exit 只维护进程树，不落库、不可被规则匹配。

### 2.3 网络类（category=network / dns）

| event_type | 负载字段 |
|---|---|
| `network.connect` | `network.family`(u8)、`network.protocol`(u8: 6=TCP 17=UDP)、`network.sip`(string 点分)、`network.sport`(u16)、`network.dip`(string)、`network.dport`(u16) |
| `network.accept` | 同上 |
| `network.bind` | 同上 |
| `network.dns` | `dns.domain`(string 点分文本，用户态已解码 QNAME 线格式)、`dns.qtype`(u16) |

### 2.4 权限类（category=priv）

| event_type | 负载字段（`priv.*`） |
|---|---|
| `priv.setuid` / `priv.setgid` | `priv.target_id`(u32) |
| `priv.capset` | `priv.effective_lo`(u32，cap 位图低 32 位) |
| `priv.ptrace` | `priv.target_pid`(u32)、`priv.request`(string，如 PTRACE_ATTACH，未知为 PTRACE_UNKNOWN)、`priv.request_value`(u64) |
| `priv.module_load` | `priv.name`(string 模块名) |

### 2.5 命名空间类（category=ns）

| event_type | 负载字段（`ns.*`） |
|---|---|
| `ns.mount` | `ns.source`(string)、`ns.target`(string)、`ns.fstype`(string)、`ns.flags`(u64) |
| `ns.unshare` | `ns.flags`(u64)、`ns.names`(string 数组，如 ["CLONE_NEWNS"]) |
| `ns.setns` | `ns.fd`(int)、`ns.nstype`(u32)、`ns.nstype_name`(string)、`ns.target_ns`(string) |

## 3. 富化字段

### 3.1 祖先链 `process.ancestors`

- 结构：array，每层对象仅 3 个字段 `{pid, comm, exe}`（无 args/uid）。
- 顺序：自近及远，`ancestors[0]` 为直接父进程。
- 深度：≤8 层（kMaxAncestors=8，src/telemetry/enricher.cpp:4）；链断/环路即停，可能不足 8 层甚至为空。
- 来源：消费线程内 Enricher 查进程树（(pid,start_time) 缓存 + 预序列化）。

### 3.2 容器归属 `container`

- 仅 `container.container_id`（12 位短 ID），解析自 `/proc/<pid>/cgroup`，识别 docker/cri-containerd/crio（src/common/container.hpp:8）。
- **无** container name/image 字段。宿主机进程整个 `container` 对象省略——规则引擎须容忍该字段缺失。

## 4. 已知字段边界（v1）

- 无进程 cmdline/argv（exec 不采集）。
- 祖先链每层无 uid/gid/args。
- 无容器 name/image。
- file 事件内核侧 `comm` 上限 16 字符，长进程名被截断；匹配进程身份优先用 `process.exe`。
- `ts` 为单调时钟 ns，非墙钟；墙钟在 events 表 `ts_ns` 列之外的记录时间由落库侧生成。

## 5. 与内核态结构体的对应（备查）

| JSON | 内核 struct | 位置 |
|---|---|---|
| file.* | `struct event` | bpf/event.h:58-72 |
| process.exec | `struct proc_event` | bpf/proc_event.h:16-27 |
| network.*/dns.* | `struct net_event` | bpf/net_event.h:20-39 |
| priv.*/ns.* | `struct priv_event`（联合体 `u.*` 用户态扁平化） | bpf/priv_event.h:17-50 |

命名差异：`ts_ns`→`ts`；`saddr/daddr`（原始字节）→`sip/dip`（点分串）；`domain`（线格式）→`dns.domain`（点分文本）；`new_mode`(u32)→JSON 权限字符串；`comm` 截 NUL。
