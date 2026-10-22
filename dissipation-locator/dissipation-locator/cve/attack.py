#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对「自签 CVE」的修复版做对抗复测。

判据（只针对搜索路径）：
  G1 功能等价：同一查询序列，修复前后每次响应一致
  G2 CPU 不漂移：30s 内每请求 CPU，末两窗 / 首两窗 ≤ 1.2
  G3 内存有界：10000 次请求后 RSS 增长 ≤ 2048KB
  G4 尾延迟：2000 次请求的 P99 ≤ 50ms

用法：
  python3 cve/attack.py --label v1
  python3 cve/attack.py --label v2
"""

import argparse
import http.client
import json
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "target" / "server.py"
OUT = ROOT / "results" / "cve"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start(fixed, fixed_v1=False):
    port = free_port()
    cmd = [sys.executable, str(SERVER), "--port", str(port), "--no-nagle"]
    if fixed:
        cmd.append("--fixed")
    if fixed_v1:
        cmd.append("--fixed-v1")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            c = Client(port)
            c.get("/metrics")
            c.close()
            return proc, port
        except Exception:
            if proc.poll() is not None:
                raise RuntimeError("server exited")
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("server not ready")


class Client:
    def __init__(self, port):
        self.conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)

    def get(self, path):
        self.conn.request("GET", path)
        resp = self.conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")
        return json.loads(body)

    def close(self):
        self.conn.close()


def queries(n):
    return [f"{chr(97 + i % 26)}{i}" for i in range(n)]


def check_correctness(port_vuln, port_fixed, n=300):
    cv, cf = Client(port_vuln), Client(port_fixed)
    mismatches = []
    for q in queries(n):
        a = cv.get(f"/search?q={q}")["result"]
        b = cf.get(f"/search?q={q}")["result"]
        if a != b:
            mismatches.append({"q": q, "vuln": a, "fixed": b})
    cv.close()
    cf.close()
    return {"criterion": "G1", "name": "功能等价", "pass": not mismatches,
            "requests": n, "mismatches": len(mismatches),
            "samples": mismatches[:3]}


def check_memory(port, n=10000):
    c = Client(port)
    c.get("/reset")
    rss0 = c.get("/metrics")["rss_kb"]
    for q in queries(n):
        c.get(f"/search?q={q}")
    rss1 = c.get("/metrics")["rss_kb"]
    c.close()
    delta = rss1 - rss0
    return {"criterion": "G3", "name": "内存有界", "pass": delta <= 2048,
            "requests": n, "rss_before_kb": rss0, "rss_after_kb": rss1,
            "delta_kb": delta}


def check_latency(port, n=2000):
    c = Client(port)
    c.get("/reset")
    lat = []
    for q in queries(n):
        t0 = time.perf_counter()
        c.get(f"/search?q={q}")
        lat.append((time.perf_counter() - t0) * 1000)
    lat.sort()
    p99 = lat[min(len(lat) - 1, int(len(lat) * 0.99))]
    c.close()
    return {"criterion": "G4", "name": "尾延迟", "pass": p99 <= 50.0,
            "requests": n, "p50_ms": round(statistics.median(lat), 3),
            "p99_ms": round(p99, 3)}


def cpu_check(port, criterion, name, warmup, seconds, rate, limit=1.2, min_blocks=4):
    c = Client(port)
    c.get("/reset")
    interval = 1.0 / rate
    sent = 0
    t_warm = time.time()
    while time.time() - t_warm < warmup:
        c.get(f"/search?q=w{sent % 100}")
        sent += 1
        delay = t_warm + sent * interval - time.time()
        if delay > 0:
            time.sleep(delay)

    blocks = []
    t0 = time.time()
    m = c.get("/metrics")
    base_cpu = m["cpu_user_s"] + m["cpu_sys_s"]
    base_n = m["search_completed"]
    next_block = t0 + 4.0
    sent = 0
    while time.time() - t0 < seconds:
        c.get(f"/search?q=q{sent % 100}")
        sent += 1
        delay = t0 + sent * interval - time.time()
        if delay > 0:
            time.sleep(delay)
        if time.time() >= next_block:
            cur = c.get("/metrics")
            cpu = cur["cpu_user_s"] + cur["cpu_sys_s"]
            dn = cur["search_completed"] - base_n
            if dn > 0:
                blocks.append(round((cpu - base_cpu) / dn * 1e6, 3))
            base_cpu, base_n = cpu, cur["search_completed"]
            next_block += 4.0
    c.close()
    if len(blocks) >= min_blocks:
        first = statistics.median(blocks[:3])
        last = statistics.median(blocks[-3:])
        ratio = last / first if first > 0 else 99.0
    else:
        ratio = 99.0
    return {"criterion": criterion, "name": name, "pass": ratio <= limit,
            "warmup_s": warmup, "seconds": seconds, "rate": rate,
            "windows_us_per_req": blocks, "last_over_first": round(ratio, 3)}


def check_cpu(port):
    return cpu_check(port, "G2", "CPU 不漂移", 8.0, 16.0, 200.0)


def check_short_equals_long(port):
    """G5：长跑后段与短跑前段同价，才算把长运行拆成了短运行。"""
    return cpu_check(port, "G5", "长跑等价短跑", 10.0, 180.0, 100.0, min_blocks=6)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--v1", action="store_true", help="复现第一版修复")
    ap.add_argument("--long", action="store_true", help="追加 G5：180s 长跑等价短跑")
    args = ap.parse_args()

    pv, port_v = start(False)
    pf, port_f = start(True, fixed_v1=args.v1)
    try:
        g1 = check_correctness(port_v, port_f)
        g2 = check_cpu(port_f)
        g3 = check_memory(port_f)
        g4 = check_latency(port_f)
        g5 = check_short_equals_long(port_f) if args.long else None
    finally:
        for p in (pv, pf):
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    checks = [g1, g2, g3, g4] + ([g5] if g5 else [])
    result = {"label": args.label, "checks": checks,
              "all_pass": all(c["pass"] for c in checks)}
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"attack_{args.label}.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    for c in checks:
        print(f"{c['criterion']} {c['name']}: {'PASS' if c['pass'] else 'FAIL'}  "
              + json.dumps({k: v for k, v in c.items() if k not in ('criterion', 'name', 'pass')},
                           ensure_ascii=False))
    print("all_pass:", result["all_pass"], "->", path)


if __name__ == "__main__":
    main()
