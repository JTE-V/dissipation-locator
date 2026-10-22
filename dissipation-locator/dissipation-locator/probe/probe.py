#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""耗散探针：对靶场做一次观测，算出三通道耗散。

用法：
  python3 probe/probe.py --mode search --duration 30 --rate 50
  python3 probe/probe.py --mode search --duration 120 --rate 50 --fixed
  python3 probe/probe.py --mode burst --n 500 --duration 15
"""

import argparse
import http.client
import json
import os
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "target" / "server.py"
SAMPLE_INTERVAL = 0.5

# 靶场设计参数
QUEUE_CAPACITY = 100
P99_SLA_MS = 500.0


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_server(fixed=False, capacity=QUEUE_CAPACITY, job_sleep=0.01, variant="none"):
    port = free_port()
    cmd = [sys.executable, str(SERVER), "--port", str(port),
           "--capacity", str(capacity), "--job-sleep", str(job_sleep),
           "--variant", variant]
    if fixed:
        cmd.append("--fixed")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            c = Client(port)
            c.get("/metrics")
            return proc, port
        except Exception:
            if proc.poll() is not None:
                out, err = proc.communicate(timeout=1)
                raise RuntimeError(f"server exited: {out}\n{err}")
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("server did not start")


def stop_server(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


class Client:
    def __init__(self, port):
        self.conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)

    def get(self, path):
        self.conn.request("GET", path)
        resp = self.conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}: {body[:200]}")
        return json.loads(body)

    def close(self):
        self.conn.close()


def collect_search(port, duration, rate):
    """按固定速率压 /search，同时采样指标。"""
    sampler = Client(port)
    worker = Client(port)
    stop = threading.Event()
    stats = {"sent": 0, "errors": []}

    def drive():
        interval = 1.0 / rate if rate else 0.0
        next_t = time.perf_counter()
        i = 0
        while not stop.is_set():
            try:
                worker.get(f"/search?q=q{i % 1000}")
                stats["sent"] += 1
                i += 1
            except Exception as exc:
                stats["errors"].append(str(exc))
                break
            if interval:
                next_t += interval
                delay = next_t - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)

    thread = threading.Thread(target=drive, daemon=True)
    thread.start()
    samples = []
    t0 = time.time()
    while time.time() - t0 < duration:
        time.sleep(SAMPLE_INTERVAL)
        samples.append(sampler.get("/metrics"))
    stop.set()
    thread.join(timeout=2)
    samples.append(sampler.get("/metrics"))
    sampler.close()
    worker.close()
    return samples, stats


def collect_burst(port, n, duration):
    """先静默 3s 建立基线，再一次性压 n 个任务，观察队列与延迟。"""
    sampler = Client(port)
    burst_client = Client(port)
    result = {}

    def send():
        try:
            result["resp"] = burst_client.get(f"/burst?n={n}")
        except Exception as exc:
            result["error"] = str(exc)

    samples = []
    t0 = time.time()
    while time.time() - t0 < 3.0:
        time.sleep(0.2)
        samples.append(sampler.get("/metrics"))

    thread = threading.Thread(target=send, daemon=True)
    thread.start()
    burst_at = time.time()
    while time.time() - burst_at < duration:
        time.sleep(0.2)
        samples.append(sampler.get("/metrics"))
    thread.join(timeout=60)
    samples.append(sampler.get("/metrics"))
    sampler.close()
    burst_client.close()
    return samples, result


def windowize(samples):
    """把累计指标切成窗口增量。"""
    if len(samples) < 2:
        return []
    t_base = samples[0]["uptime_s"]
    windows = []
    for a, b in zip(samples, samples[1:]):
        dt = b["uptime_s"] - a["uptime_s"]
        if dt <= 0:
            continue
        profiles = {}
        keys = set(a.get("profile", {})) | set(b.get("profile", {}))
        for key in keys:
            profiles[key] = b.get("profile", {}).get(key, 0.0) - a.get("profile", {}).get(key, 0.0)
        windows.append({
            "t": a["uptime_s"] - t_base,
            "dt": dt,
            "cpu": (b["cpu_user_s"] + b["cpu_sys_s"]) - (a["cpu_user_s"] + a["cpu_sys_s"]),
            "rss": b["rss_kb"],
            "io": (b["io_read_bytes"] + b["io_write_bytes"])
                  - (a["io_read_bytes"] + a["io_write_bytes"]),
            "work": (b["search_completed"] + b["jobs_completed"])
                    - (a["search_completed"] + a["jobs_completed"]),
            "arrived": b["jobs_arrived"] - a["jobs_arrived"],
            "dropped": b["jobs_dropped"] - a["jobs_dropped"],
            "search_timeouts": b.get("search_timeouts", 0) - a.get("search_timeouts", 0),
            "enqueue_blocked_s": b.get("enqueue_blocked_s", 0.0) - a.get("enqueue_blocked_s", 0.0),
            "enqueue_blocks": b.get("enqueue_blocks", 0) - a.get("enqueue_blocks", 0),
            "dequeue_wait_s": b.get("dequeue_wait_s", 0.0) - a.get("dequeue_wait_s", 0.0),
            "enqueue_max_wait_s": b.get("enqueue_max_wait_s", 0.0),
            "dequeue_max_wait_s": b.get("dequeue_max_wait_s", 0.0),
            "queue": b["queue_depth"],
            "threads": b["threads"],
            "p99_ms": b["latency_p99_ms"],
            "profile": profiles,
        })
    return windows


def rebin(windows, block=4.0):
    """把 0.5s 窗口聚合成 block 秒的大窗，压掉单点调度噪声。"""
    blocks = []
    cur = None
    for w in windows:
        if cur is None or w["t"] - cur["t"] >= block:
            if cur is not None:
                blocks.append(cur)
            cur = {
                "t": w["t"], "dt": 0.0, "cpu": 0.0, "rss": w["rss"], "io": 0.0,
                "work": 0, "arrived": 0, "dropped": 0,
                "search_timeouts": 0, "enqueue_blocked_s": 0.0,
                "enqueue_blocks": 0, "dequeue_wait_s": 0.0,
                "enqueue_max_wait_s": 0.0, "dequeue_max_wait_s": 0.0,
                "queue": w["queue"],
                "threads": w["threads"], "p99_ms": w["p99_ms"], "profile": {},
            }
        cur["dt"] += w["dt"]
        cur["cpu"] += w["cpu"]
        cur["io"] += w["io"]
        cur["work"] += w["work"]
        cur["arrived"] += w["arrived"]
        cur["dropped"] += w["dropped"]
        cur["search_timeouts"] += w.get("search_timeouts", 0)
        cur["enqueue_blocked_s"] += w.get("enqueue_blocked_s", 0.0)
        cur["enqueue_blocks"] += w.get("enqueue_blocks", 0)
        cur["dequeue_wait_s"] += w.get("dequeue_wait_s", 0.0)
        cur["enqueue_max_wait_s"] = max(
            cur["enqueue_max_wait_s"], w.get("enqueue_max_wait_s", 0.0))
        cur["dequeue_max_wait_s"] = max(
            cur["dequeue_max_wait_s"], w.get("dequeue_max_wait_s", 0.0))
        cur["rss"] = max(cur["rss"], w["rss"])
        cur["queue"] = max(cur["queue"], w["queue"])
        cur["threads"] = max(cur["threads"], w["threads"])
        cur["p99_ms"] = max(cur["p99_ms"], w["p99_ms"])
        for key, value in w["profile"].items():
            cur["profile"][key] = cur["profile"].get(key, 0.0) + max(0.0, value)
    if cur is not None:
        blocks.append(cur)
    return blocks


def stats(values):
    if not values:
        return 0.0, 0.0
    return statistics.fmean(values), statistics.pstdev(values)


def median_mad(values):
    """中位数 + 1.4826*MAD，抗单点尖刺。"""
    if not values:
        return 0.0, 1e-9
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values])
    return med, max(1.4826 * mad, 1e-9)


def baseline_from_windows(windows, warmup=4.0, baseline=8.0, require_work=True):
    picked = [w for w in windows
              if warmup <= w["t"] < warmup + baseline
              and (w["work"] > 0 or not require_work)]
    if not picked and require_work:
        picked = [w for w in windows if w["work"] > 0][: max(1, len(windows) // 5)]
    cpu_per_work = [w["cpu"] / w["work"] for w in picked if w["work"] > 0]
    med_cpu, mad_cpu = median_mad(cpu_per_work)
    # 基线自身是否稳定：离散度太大时，任何阈值都不可信
    rel_mad = mad_cpu / med_cpu if med_cpu > 0 else 0.0
    spread = ((max(cpu_per_work) - min(cpu_per_work)) / med_cpu
              if cpu_per_work and med_cpu > 0 else 0.0)
    stable = len(cpu_per_work) >= 2 and rel_mad <= 0.10 and spread <= 0.40
    # 基线方差为 0 时给 5% 相对底噪，避免 z 发散
    mad_cpu = max(mad_cpu, 0.05 * med_cpu, 1e-9)
    med_rss, mad_rss = median_mad([w["rss"] for w in picked])
    med_io, mad_io = median_mad([w["io"] for w in picked])
    return {
        "t_end": (max(warmup + baseline, picked[-1]["t"]) if picked else 0.0),
        "cpu_per_work": med_cpu,
        "mad_cpu": mad_cpu,
        "stable": stable,
        "rel_mad": round(rel_mad, 4),
        "spread": round(spread, 4),
        "samples": len(cpu_per_work),
        "mu_rss": med_rss, "sd_rss": mad_rss,
        "mu_io": med_io, "sd_io": mad_io,
        "k_ref": 1.0 / med_cpu if med_cpu > 0 else 1.0,
    }


def analyze(windows, base, mode="search"):
    start = base["t_end"]
    if mode == "burst":
        # 突发场景看的是外部损耗，停机窗口也要算进来，否则入队与完成会错位
        first_arrival = next((w["t"] for w in windows if w["arrived"] > 0),
                             base["t_end"])
        start = min(base["t_end"], first_arrival)
        # 外部损耗只在整个突发活跃期内积分；队列排空后的空转不算
        measure = [w for w in windows
                   if w["t"] >= start and (w["work"] > 0 or w["queue"] > 0)]
    else:
        # 搜索场景只看有效功窗口：没有完成请求的窗口无法计算 CPU/请求
        measure = [w for w in windows if w["t"] >= base["t_end"] and w["work"] > 0]
        if not measure:
            measure = [w for w in windows if w["work"] > 0][len(windows) // 5:]

    e_int = e_leak = e_ext = 0.0
    series = []
    profile = {}
    z_hist = []
    timeouts = 0
    transient_peaks = 0
    bp_arrived = bp_dropped = bp_blocks = 0
    bp_blocked_s = bp_dequeue_wait_s = 0.0
    bp_max_block_s = bp_max_wait_s = 0.0
    # 入队与完成不在同一窗口：背压统计要覆盖整个观测段，不能只看有完成量的窗口
    bp_windows = [w for w in windows if w["t"] >= start]
    for w in bp_windows:
        bp_arrived += w["arrived"]
        bp_dropped += w["dropped"]
        bp_blocks += w.get("enqueue_blocks", 0)
        bp_blocked_s += w.get("enqueue_blocked_s", 0.0)
        bp_dequeue_wait_s += w.get("dequeue_wait_s", 0.0)
        bp_max_block_s = max(bp_max_block_s, w.get("enqueue_max_wait_s", 0.0))
        bp_max_wait_s = max(bp_max_wait_s, w.get("dequeue_max_wait_s", 0.0))

    for w in measure:
        if mode == "burst":
            # 突发场景不用 CPU 通道判漂移，只看队列/等待/拒绝
            cpu_per_work = z_cpu = z_rss = z_io = 0.0
            sustained = False
        else:
            cpu_per_work = w["cpu"] / w["work"] if w["work"] > 0 else 0.0
            z_cpu = (cpu_per_work - base["cpu_per_work"]) / base["mad_cpu"]
            z_rss = (w["rss"] - base["mu_rss"]) / base["sd_rss"]
            z_io = (w["io"] - base["mu_io"]) / base["sd_io"]

        # 连续 3 窗中位数 > 3 才算漂移；单点尖刺被压掉
        z_hist.append(z_cpu)
        if len(z_hist) > 3:
            z_hist.pop(0)
        z_smooth = statistics.median(z_hist)
        sustained = len(z_hist) >= 3 and z_smooth > 3.0

        # 单窗越过 3σ、但没构成连续三窗：只记瞬态，不判漂移
        if z_cpu > 3.0 and not sustained:
            transient_peaks += 1

        e_int_rate = max(0.0, z_smooth - 3.0) if sustained else 0.0
        ideal_cpu = w["work"] * base["cpu_per_work"]
        leak = max(0.0, w["cpu"] - ideal_cpu) if sustained else 0.0
        drop_rate = w["dropped"] / w["arrived"] if w["arrived"] > 0 else 0.0
        e_ext_rate = (max(0.0, w["queue"] / QUEUE_CAPACITY - 0.5)
                      + drop_rate
                      + max(0.0, w["p99_ms"] / P99_SLA_MS - 1.0))

        e_int += e_int_rate * w["dt"]
        e_leak += leak
        e_ext += e_ext_rate * w["dt"]
        timeouts += w.get("search_timeouts", 0)

        for key, value in w["profile"].items():
            profile[key] = profile.get(key, 0.0) + max(0.0, value)

        series.append({
            "t": round(w["t"], 3),
            "cpu": round(w["cpu"], 6),
            "work": w["work"],
            "cpu_per_work": round(cpu_per_work, 6),
            "z_cpu": round(z_cpu, 3),
            "z_smooth": round(z_smooth, 3),
            "z_rss": round(z_rss, 3),
            "z_io": round(z_io, 3),
            "e_int_rate": round(e_int_rate, 3),
            "e_leak": round(leak, 6),
            "queue": w["queue"],
            "threads": w["threads"],
            "p99_ms": round(w["p99_ms"], 2),
            "dropped": w["dropped"],
            "enqueue_blocks": w.get("enqueue_blocks", 0),
            "enqueue_blocked_ms": round(w.get("enqueue_blocked_s", 0.0) * 1000, 3),
            "dequeue_wait_ms": round(w.get("dequeue_wait_s", 0.0) * 1000, 3),
            "e_ext_rate": round(e_ext_rate, 3),
        })

    total_profile = sum(profile.values()) or 1.0
    suspects = [
        {"function": k, "cpu_s": round(v, 6), "share": round(v / total_profile, 3)}
        for k, v in sorted(profile.items(), key=lambda kv: kv[1], reverse=True)
        if v > 0
    ][:5]

    completed = sum(w["work"] for w in measure)
    peak_queue = max((s["queue"] for s in series), default=0)
    reject_rate = bp_dropped / bp_arrived if bp_arrived > 0 else 0.0
    queue_filled = peak_queue >= 0.9 * QUEUE_CAPACITY
    if bp_arrived <= 0:
        bp_verdict = "no_load"
    elif reject_rate > 0.01:
        bp_verdict = "backpressure_rejecting"
    elif bp_blocks > 0 and queue_filled:
        bp_verdict = "backpressure_blocking"
    elif queue_filled:
        bp_verdict = "no_backpressure"
    elif bp_blocks > 0:
        bp_verdict = "backpressure_light"
    else:
        bp_verdict = "no_pressure"

    # 时间判据：先看有没有延续性耗散，再看能不能判
    if mode == "burst" and bp_arrived <= 0:
        verdict = "no_load"
    elif e_int > 0 or e_leak > 0 or e_ext > 0:
        verdict = "sustained"
    elif len(measure) < 3:
        verdict = "insufficient_window"
    elif not base.get("stable", True):
        verdict = "baseline_unstable"
    elif transient_peaks > 0:
        verdict = "transient_only"
    else:
        verdict = "clean"

    return {
        "E_int": round(e_int, 4),
        "E_leak": round(e_leak, 4),
        "E_ext": round(e_ext, 4),
        "suspects": suspects,
        "series": series,
        "measure_windows": len(measure),
        "measure_seconds": round(sum(w["dt"] for w in measure), 2),
        "mean_z_smooth": round(statistics.fmean([s["z_smooth"] for s in series]), 3) if series else 0.0,
        "peak_queue": peak_queue,
        "peak_threads": max((s["threads"] for s in series), default=0),
        "peak_p99_ms": max((s["p99_ms"] for s in series), default=0.0),
        "dropped": sum(s["dropped"] for s in series),
        "search_timeouts": timeouts,
        "transient_peaks": transient_peaks,
        "verdict": verdict,
        "backpressure": {
            "verdict": bp_verdict,
            "arrived": bp_arrived,
            "dropped": bp_dropped,
            "reject_rate": round(reject_rate, 4),
            "blocked_events": bp_blocks,
            "blocked_ms_per_job": round(bp_blocked_s / bp_arrived * 1000, 3) if bp_arrived else 0.0,
            "max_block_ms": round(bp_max_block_s * 1000, 3),
            "wait_ms_per_job": round(bp_dequeue_wait_s / completed * 1000, 3) if completed else 0.0,
            "max_wait_ms": round(bp_max_wait_s * 1000, 3),
        },
    }


FIX_HINTS = {
    "scan_history": "全量历史扫描 O(n)，改为增量聚合或索引，别在请求路径里遍历历史",
    "handle_search": "搜索路径过重，把统计从请求路径移出，改为维护计数器",
    "enqueue_burst": "无界队列改为有界队列 + 背压/拒绝策略，避免无限堆积",
    "worker_job": "下游处理能力不足，增加并发或前置限流，避免队列击穿",
}


def suggestions(suspects, e_int=0.0, e_ext=0.0, variant="none",
                timeouts=0, backpressure=None):
    if e_int <= 0 and e_ext <= 0:
        return []
    bp = (backpressure or {}).get("verdict", "no_load")
    out = []
    for s in suspects:
        fn = s["function"]
        if fn in ("scan_history", "handle_search") and e_int <= 0:
            continue
        if fn in ("enqueue_burst", "worker_job") and e_ext <= 0:
            continue
        hint = FIX_HINTS.get(fn)
        if fn in ("enqueue_burst", "worker_job") and bp != "no_load":
            if bp == "no_backpressure":
                hint = ("无背压：生产端未受阻、队列持续增长；"
                        + ("先改有界队列 + 阻塞/拒绝，再评估消费者并发"
                           if fn == "enqueue_burst"
                           else "根因是无界队列，先补背压，再谈扩容"))
            elif bp == "backpressure_blocking":
                hint = ("背压已生效，但排队仍超 SLA；"
                        + ("检查队列容量是否过大"
                           if fn == "enqueue_burst"
                           else "增加消费者并发或降低队列容量"))
            elif bp == "backpressure_rejecting":
                hint = "背压靠拒绝生效；调整容量或前置限流，避免丢弃"
            elif bp == "backpressure_light":
                hint = "有轻微阻塞但队列未满；继续观察吞吐与等待"
        if fn == "scan_history" and variant == "timeout" and timeouts > 0:
            hint = "超时只提前返回，扫描线程还在跑；改成可取消的扫描或增量聚合"
        if hint:
            out.append({
                "function": fn,
                "share": s["share"],
                "suggestion": hint,
            })
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["search", "burst"], default="search")
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--rate", type=float, default=50)
    parser.add_argument("--n", type=int, default=500)
    parser.add_argument("--fixed", action="store_true")
    parser.add_argument("--variant", choices=["none", "timeout"], default="none")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    proc, port = start_server(fixed=args.fixed, variant=args.variant)
    try:
        if args.mode == "search":
            samples, stats_ = collect_search(port, args.duration, args.rate)
        else:
            samples, stats_ = collect_burst(port, args.n, args.duration)
        windows = windowize(samples)
        windows = rebin(windows, 0.5 if args.mode == "burst" else 4.0)
        if args.mode == "burst":
            base = baseline_from_windows(windows, warmup=0.0, baseline=2.5,
                                         require_work=False)
        else:
            # 长跑用更长的基线，2 个块估出的 MAD 太容易被启动噪声带偏
            span = 8.0 if args.duration <= 30 else min(
                16.0, max(8.0, args.duration * 0.27))
            base = baseline_from_windows(windows, warmup=4.0, baseline=span)
        result = analyze(windows, base, args.mode)
        result.update({
            "mode": args.mode,
            "fixed": args.fixed,
            "variant": args.variant,
            "duration": args.duration,
            "rate": args.rate,
            "n": args.n,
            "sent": stats_.get("sent"),
            "errors": stats_.get("errors"),
            "baseline": {k: round(v, 6) if isinstance(v, float) else v for k, v in base.items()},
            "suggestions": suggestions(result["suspects"],
                                         result["E_int"], result["E_ext"], args.variant,
                                         result["search_timeouts"], result["backpressure"]),
        })
    finally:
        stop_server(proc)

    print(json.dumps({k: v for k, v in result.items() if k != "series"},
                     ensure_ascii=False, indent=2))
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"saved {args.out}")


if __name__ == "__main__":
    main()
