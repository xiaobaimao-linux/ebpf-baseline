# W6 D1 误报扫描记录（rules/core 8 条规则）

> 方法：monitor 以 tests/attack-cases/config.yaml 运行（rules_dir=rules，112 条 DSL 规则），
> 执行一组日常操作，核对 alerts 表中 dsl.* 新增告警。扫描脚本 /tmp/w6-fpr-scan.sh（临时）。
> 另有 3 条收紧来自 run_all 联调期实测（见下）。

## 扫描项与结果

| 日常操作 | 预期 | 结果 |
|---|---|---|
| `cat /etc/passwd`（读） | 不命中（cred-write-passwd 为 write-only） | ✓ 无告警 |
| `sudo true` 认证（unix_chkpwd/sudo 读 shadow） | 不命中 cred-read-shadow-whitelist（已白名单） | ✓ 无告警 |
| bash 追加写测试 .bash_history（模拟正常登出写历史） | 不命中 cred-clear-shell-history（shell exe 白名单） | ✓ 无告警 |
| `python3 -c subprocess.run(echo)`（解释器派生非 shell） | 不命中 exec-reverse-shell-under-interpreter | ✓ 无告警 |
| `nc -zv 127.0.0.1 22`（运维端口探测） | **命中** exec-reverse-shell-dual-use-tool | ✗ 命中 1 条（已知双义，见下） |
| `dpkg -l` / `apt list --installed`（常规查询） | 不命中 | ✓ 无告警 |
| 常规 ls/echo 临时文件 | 不命中 | ✓ 无告警 |

## 误报记录（N=1）

1. **exec-reverse-shell-dual-use-tool ← nc 端口探测**（high，exe=/usr/bin/nc.openbsd）。
   nc 是双用途工具，无 cmdline（G1）无法区分 `nc -zv` 探测与 `nc -e` 反弹。
   处置：保持规则不变，fpr_note 已写明该场景与研判方法（结合祖先链 + network.connect 人工研判）。
   不可再收紧——任何按 exe 的豁免都会同时豁免攻击载荷。

## 联调期实测收紧（M=3，已落入规则 condition/fpr_note）

1. **exec-reverse-shell-under-interpreter：祖先列表移除 node**。开发机 vscode-server 的 node 链
   位于几乎所有进程的 8 层祖先内，规则曾每 ~10s 环境命中一次，淹没告警通道并遮蔽后续规则（G8）。
2. **exec-webspawner-shell：祖先列表移除 node**（同上根因）。node webshell 场景由示例规则
   Reverse Shell From Web Service 兜底（examples 后加载，单事件单告警下与本规则不冲突）。
3. **cred-clear-shell-history：加 shell exe 白名单**（bash/sh/zsh）。交互式 shell 正常退出追加
   history 会产生 file.write，不豁免则每次登出都告警；代价是 bash 内建 history -c/-w 不可见（G1），
   属刻意取舍，已在 fpr_note 声明。

## 备注

- 示例规则 dsl.reverse_shell_from_web_service（含 node）在本开发机会环境命中（vscode node 链派生 bash），
  属 examples 既有规则行为，core 规则不受影响，未改动示例。
- perf-100/storm 规则随 rules_dir=rules 一并加载，攻击用例期间无干扰（rule_id 维度隔离）。
