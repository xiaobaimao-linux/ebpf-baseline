# 谛听（Diting）
**基于 eBPF 的 Linux 主机安全监控 Agent：内核级文件完整性监控（FIM）+ 全量运行时遥测**

适配等保2.0、服务器运维、工控、容器安全、云主机与 AI 工作负载防护场景。
项目正从「eBPF LSM FIM 工具」演进为「云安全与 AI 安全监控 Agent」。

## 核心功能

- **基线快照管理**：文件哈希/权限/属主采集入 SQLite，可信基准全生命周期管理（snapshot / list / delete / check / clean）
- **实时文件监控双模式**：纯 YAML 规则监控；基线监控模式（开机自检 + 实时篡改校验，区分存量风险与运行时入侵）
- **运行时遥测**：网络 connect/accept/bind 五元组、DNS 查询域名、权限事件（setuid/capset/ptrace/内核模块）、命名空间事件（mount/unshare/setns），全部携带进程归属与容器 ID，JSON 结构化输出
- **告警降噪**：钉钉机器人推送，实时/基线告警独立冷却
- **合规交付**：HTML 审计报表、告警历史查询、事件汇总导出
- **低资源开销**：事件驱动无轮询，遥测开关默认关闭、对既有功能零影响

## 快速上手

```bash
make                                                # 编译
sudo ./baseline-guard baseline snapshot /etc        # 采集基线
sudo ./baseline-guard baseline check                # 离线核查
sudo ./baseline-guard monitor --db baseline.db -c config.yaml   # 实时监控
```

开启遥测（`baselines/default.yaml` 中 `telemetry.network/dns/privilege` 置 true）后：

```bash
sudo ./baseline-guard monitor -c baselines/default.yaml
curl -s http://example.com -o /dev/null   # → network.connect
dig example.com                            # → network.dns
sudo -u nobody id                          # → priv.setuid
```

## 文档与帮助

| 文档 | 内容 |
|------|------|
| [docs/help/index.html](docs/help/index.html) | **帮助中心**（浏览器打开） |
| [docs/help/fim-guide.html](docs/help/fim-guide.html) | FIM 完整使用手册：子命令参数、双模式、告警规则、钉钉配置 |
| [docs/help/telemetry-guide.html](docs/help/telemetry-guide.html) | 遥测手册：开关、采集点、事件字段、触发验证、已知限制 |
| [docs/kernel-compat-matrix.md](docs/kernel-compat-matrix.md) | 采集点内核兼容矩阵（4.18 / 5.4 / 5.10 / 6.x） |
| [docs/ring_buffer_optimization.md](docs/ring_buffer_optimization.md) | ring buffer 水位背压优化 |

## 目录结构

```
├── src/            # 用户态：baseline(FIM+遥测消费) / alerts / storage / cli / ops / common
│                   # 预留：asset(M1) / detect(M3) / ai(M4) / ebpf
├── manager/        # [M9 预留] 管理中心（企业版）
├── bpf/            # lsm_file / net_watch / priv_watch 探针 + 完整版 vmlinux.h（CO-RE）
├── docs/           # 帮助中心(help/) + 兼容矩阵 + 设计文档
├── tests/          # unit / integration（遥测端到端验收）/ fixtures
└── Makefile
```

## 技术栈与环境

C++17 · libbpf CO-RE（LSM BPF / kprobe / tracepoint）· yaml-cpp · SQLite（WAL）· spdlog · nlohmann/json
推荐内核 5.10+/6.x；4.18、5.4 降级路径见兼容矩阵。开发验证环境：Ubuntu 24.04，clang 18，libbpf 1.3。

## 版本与路线图

- ✅ **v0.3 已冻结**：FIM 全量功能（基线子命令、双模式监控、三类告警隔离、HTML 报表）
- ✅ **运行时遥测已入库**：网络/DNS/权限/命名空间事件 + 容器归属（内核 6.x/7.0 实测验收）
- 🔄 **迭代中**：事件总线 + 落库管道、威胁检测（M3）、资产清点（M1）、AI 工作负载防护（M4）、管理中心（M9）

## 商业服务与许可证

企业定制与等保交付服务：邮箱 kabc005009@163.com · 微信 houduankf · [知乎](https://zhihu.com/people/q1w2e3r4t5y6-86)

本项目采用 [Business Source License 1.1](LICENSE)（BSL 1.1），商标见 [TRADEMARK.md](TRADEMARK.md)：

| 使用场景 | 是否免费 |
|---|---|
| 个人学习、研究、开发测试、内部评估、参与贡献 | ✅ 免费 |
| 公司生产环境部署 / 集成进对外销售产品 | ❌ 需购买商业许可 |
| 发布满 3 年的历史版本 | ✅ 自动转为 GPLv2+ |
