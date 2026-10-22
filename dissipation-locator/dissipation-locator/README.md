# dissipation-locator

资源耗散定位器：对一个会「越跑越慢」的服务做短跑与长跑观测，用三通道耗散指数把启动瞬态与延续性漂移分开，再给出函数级定位与修复建议。

配套文章：《短跑测不出，长跑才暴露：我用「资源耗散」定位一个越跑越慢的漏洞》

## 目录

```
target/server.py     靶场：缺陷版 / 修复版（--fixed）
probe/probe.py       探针：0.5s 采样、4s 聚块、冻结基线、三通道耗散
run_all.py           四组条件批量运行、汇总、出图
real_cve/            真实 CVE-2023-46136 的最小复测环境
cve/                 自签漏洞记录与判据攻击脚本
results/             逐次观测 JSON、matrix/summary.json、figures/
```

靶场故意留了两个缺陷：

- `/search` 每次请求全量扫描历史查询，O(n)，历史越长越慢
- `/burst` 任务进入无界队列，消费速度小于生产速度，队列无限堆积

修复版分别改成增量聚合 O(1)、有界队列 + 阻塞背压。

## 环境

- Python 3.10+
- `target/server.py` 与 `probe/probe.py` 只用标准库
- `run_all.py` 需要 matplotlib：

```bash
pip install matplotlib
```

## 复现

```bash
python3 run_all.py --quick   # 约 8 分钟，短跑 20s / 长跑 60s
python3 run_all.py           # 约 14 分钟，短跑 45s / 长跑 120s
```

单次观测：

```bash
python3 probe/probe.py --mode search --duration 60 --rate 100
python3 probe/probe.py --mode search --duration 60 --rate 100 --fixed
python3 probe/probe.py --mode burst --n 500 --duration 15
```

## 判据

时间判定：`insufficient_window`（窗口不足）、`baseline_unstable`（基线不稳）、`transient_only`（仅瞬态）、`sustained`（延续性耗散）、`clean`（无耗散）、`no_load`（无负载）。

背压判定：`no_load`（无负载）、`no_backpressure`（无背压）、`backpressure_blocking`（背压生效）、`backpressure_rejecting`（背压靠拒绝）、`backpressure_light`（轻背压）、`no_pressure`（无压力）。

合成：`E_total_z = z_int + z_leak + z_ext`。

## 实测结果

以下数值取自 `results/matrix/summary.json`，每组两轮，E 为两轮算术平均，峰值为两轮最大。

| 条件 | 判定 | 背压 | E_int | E_leak | E_ext | E_total_z | 峰值队列 | 峰值 P99 |
|---|---|---|---:|---:|---:|---:|---:|---:|
| fixed_short | insufficient_window | no_load | 0 | 0 | 0 | 0.00 | 0 | 0ms |
| vuln_short | insufficient_window | no_load | 0 | 0 | 0 | 0.00 | 0 | 0ms |
| fixed_long | transient_only | no_load | 0 | 0 | 0 | 0.00 | 0 | 0ms |
| vuln_long | sustained | no_load | 81.0932 | 0.0571 | 0 | **138.24** | 0 | 0ms |
| fixed_burst | sustained | backpressure_blocking | 0 | 0 | 7.8656 | 7.87 | 100 | 1030.48ms |
| vuln_burst | sustained | no_backpressure | 0 | 0 | 40.7074 | **40.71** | 480 | 4996.98ms |

## 真实 CVE 复测

`real_cve/` 用最小 WSGI 服务复测 CVE-2023-46136（Werkzeug multipart 解析，3.0.1 修复）。8MB 载荷，基线段为每 8KB 带 CRLF 的正常内容，观测段为 CRLF 开头且不含 CRLF 的触发内容，1 次/秒。

```bash
python3 -m venv /tmp/venv-300 && /tmp/venv-300/bin/pip install werkzeug==3.0.0
python3 -m venv /tmp/venv-301 && /tmp/venv-301/bin/pip install werkzeug==3.0.1
python3 real_cve/run_cve.py --python /tmp/venv-300/bin/python --label vuln_300
python3 real_cve/run_cve.py --python /tmp/venv-301/bin/python --label fixed_301
```

实测（`results/real_cve/`）：

| 版本 | 基线 CPU/请求 | 观测段 CPU/请求 | verdict |
|---|---:|---:|---|
| 3.0.0 | 11.99ms | 286.4–299.4ms | sustained |
| 3.0.1 | 13.07ms | 11.9–12.6ms | clean |

注意：这个 CVE 是「每次请求都贵」，不是「越跑越慢」，短跑同样能抓到；工具判 `sustained` 的含义是延续性偏离基线，不代表耗时随时间增长。

## 自签判据与攻击

`cve/TRG-2026-0001.md` 把「修好」定义成五条判据：功能等价、CPU 不漂移、内存有界、尾延迟、长跑等价短跑（180s）。`cve/attack.py` 拿这五条攻击修复版。

```bash
python3 cve/attack.py --label v1 --v1 --long   # 第一版修复，G1 应失败
python3 cve/attack.py --label v2 --long        # 第二版修复，应全部通过
```

第一版修复把 O(n) 扫描改成只累加 `total_len`，CPU 归零，但返回值也变了，300/300 不一致；第二版补回首字符计数，五项全过，180 秒长跑末段/首段 = 0.964。结果在 `results/cve/`。

## 原始数据

- `results/*.json`：逐次观测原始输出，含每 0.5 秒采样与 4 秒块序列
- `results/matrix/summary.json`：四组条件的汇总与基线
- `results/real_cve/*.json`：真实 CVE 复测原始输出
- `results/cve/*.json`：自签判据攻击原始输出
- `results/figures/*.png`：文章用图

## 边界

- 主靶场是自造的；真实 CVE 只用最小 WSGI 调用面复测了单条解析路径，不是完整业务系统，不能直接外推到生产项目
- 测试环境无 `perf`、无 RAPL，测不了 CPI 与真实能耗；`E_leak` 是有效功转化率的代理量，不是电子数
- 只跑了「运行时长」轴，没跑「代码规模」轴
- 定位粒度是函数级，不是行级
- 自签判据只覆盖搜索接口的五条（含 180s 长跑不变性），不覆盖并发竞态、跨接口组合与长时间内存碎片
- 短跑的 0 表示「窗口不足」，不能读成「没有耗散」
