# 耗散定位器：实测汇总

| 条件 | 判定 | 背压 | E_int | E_leak | E_ext | E_total_z | 峰值队列 | 峰值 P99(ms) | 丢弃 |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| fixed_short | insufficient_window | no_load | 0.0000 | 0.0000 | 0.0000 | 0.00 | 0 | 0.0 | 0 |
| vuln_short | insufficient_window | no_load | 0.0000 | 0.0000 | 0.0000 | 0.00 | 0 | 0.0 | 0 |
| fixed_long | transient_only | no_load | 0.0000 | 0.0000 | 0.0000 | 0.00 | 0 | 0.0 | 0 |
| vuln_long | sustained | no_load | 81.0932 | 0.0571 | 0.0000 | 138.24 | 0 | 0.0 | 0 |
| fixed_burst | sustained | backpressure_blocking | 0.0000 | 0.0000 | 7.8656 | 7.87 | 100 | 1030.5 | 0 |
| vuln_burst | sustained | no_backpressure | 0.0000 | 0.0000 | 40.7074 | 40.71 | 480 | 4997.0 | 0 |

## 定位与建议

### vuln_long
- `handle_search`（占比 53%）：搜索路径过重，把统计从请求路径移出，改为维护计数器
- `scan_history`（占比 47%）：全量历史扫描 O(n)，改为增量聚合或索引，别在请求路径里遍历历史

### fixed_burst
- `enqueue_burst`（占比 51%）：背压已生效，但排队仍超 SLA；检查队列容量是否过大
- `worker_job`（占比 49%）：背压已生效，但排队仍超 SLA；增加消费者并发或降低队列容量

### vuln_burst
- `worker_job`（占比 97%）：无背压：生产端未受阻、队列持续增长；根因是无界队列，先补背压，再谈扩容
- `enqueue_burst`（占比 3%）：无背压：生产端未受阻、队列持续增长；先改有界队列 + 阻塞/拒绝，再评估消费者并发
