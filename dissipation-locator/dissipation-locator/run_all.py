#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跑完短/长/突发/修复四组条件，算三通道标准化耗散并出图。

用法：
  python3 run_all.py --quick     # 约 8 分钟
  python3 run_all.py             # 约 14 分钟
"""

import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results" / "matrix"
FIGURES = ROOT / "results" / "figures"

CHANNELS = ["E_int", "E_leak", "E_ext"]
# 基线方差为 0 时的单位底噪，保证指数不发散
FLOORS = {"E_int": 1.0, "E_leak": 1e-3, "E_ext": 1.0}
LABELS = {
    "E_int": "E_int（CPU 漂移，σ·s）",
    "E_leak": "E_leak（电子泄漏，CPU·s）",
    "E_ext": "E_ext（外部损耗，指数·s）",
}


def conditions(quick=False):
    short = 20 if quick else 45
    long = 60 if quick else 120
    reps = 2 if quick else 3
    return [
        {"name": "fixed_short", "mode": "search", "fixed": True, "duration": short, "rate": 100, "repeats": reps},
        {"name": "vuln_short", "mode": "search", "fixed": False, "duration": short, "rate": 100, "repeats": reps},
        {"name": "fixed_long", "mode": "search", "fixed": True, "duration": long, "rate": 100, "repeats": reps},
        {"name": "vuln_long", "mode": "search", "fixed": False, "duration": long, "rate": 100, "repeats": reps},
        {"name": "fixed_burst", "mode": "burst", "fixed": True, "duration": 15, "n": 500, "repeats": 2},
        {"name": "vuln_burst", "mode": "burst", "fixed": False, "duration": 15, "n": 500, "repeats": 2},
    ]


def run_one(cond, index):
    out = RESULTS / f"{cond['name']}_{index}.json"
    cmd = [sys.executable, str(ROOT / "probe" / "probe.py"),
           "--mode", cond["mode"], "--duration", str(cond["duration"]),
           "--out", str(out)]
    if cond["mode"] == "search":
        cmd += ["--rate", str(cond["rate"])]
    else:
        cmd += ["--n", str(cond["n"])]
    if cond["fixed"]:
        cmd.append("--fixed")
    subprocess.run(cmd, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    return json.loads(out.read_text(encoding="utf-8"))


def mean_sd(values):
    if len(values) < 2:
        return values[0] if values else 0.0, 0.0
    return statistics.fmean(values), statistics.pstdev(values)


def normalize(results):
    baseline = [r for r in results if r["name"] == "fixed_short"]
    stats = {}
    for ch in CHANNELS:
        vals = [r["data"][ch] for r in baseline]
        mu, sd = mean_sd(vals)
        denom = max(sd, FLOORS[ch])
        stats[ch] = {"mu": mu, "sd": sd, "denom": denom}

    groups = {}
    for r in results:
        groups.setdefault(r["name"], []).append(r)

    summary = []
    for name, runs in groups.items():
        means = {ch: statistics.fmean([r["data"][ch] for r in runs]) for ch in CHANNELS}
        zs = {ch: max(0.0, (means[ch] - stats[ch]["mu"]) / stats[ch]["denom"])
              for ch in CHANNELS}
        first = runs[0]["data"]
        summary.append({
            "name": name,
            "mode": runs[0]["mode"],
            "fixed": runs[0]["fixed"],
            "runs": len(runs),
            "E_int": round(means["E_int"], 4),
            "E_leak": round(means["E_leak"], 4),
            "E_ext": round(means["E_ext"], 4),
            "z_int": round(zs["E_int"], 2),
            "z_leak": round(zs["E_leak"], 2),
            "z_ext": round(zs["E_ext"], 2),
            "E_total_z": round(sum(zs.values()), 2),
            "peak_queue": max(r["data"]["peak_queue"] for r in runs),
            "peak_p99_ms": max(r["data"]["peak_p99_ms"] for r in runs),
            "dropped": max(r["data"]["dropped"] for r in runs),
            "verdict": first.get("verdict", ""),
            "bp_verdict": first.get("backpressure", {}).get("verdict", ""),
            "suspects": first["suspects"],
            "suggestions": first["suggestions"],
        })
    return {"baseline_stats": stats, "summary": summary}


def pick(results, name, index=0):
    return [r for r in results if r["name"] == name][index]["data"]


def cum_series(data):
    total = 0.0
    out = []
    for s in data["series"]:
        total += s["e_int_rate"] * 4.0  # 4s 块
        out.append((s["t"], total))
    return out


def plot_search(vuln, fixed, path):
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.2), sharey=True)
    for ax, data, title in [(axes[0], vuln, "缺陷版"), (axes[1], fixed, "修复版")]:
        xs = [s["t"] for s in data["series"]]
        ys = [s["cpu_per_work"] * 1e6 for s in data["series"]]
        smooth = []
        for i in range(len(ys)):
            window = ys[max(0, i - 2): i + 1]
            smooth.append(statistics.median(window))
        ax.plot(xs, ys, lw=1, alpha=0.35, label="逐块值")
        ax.plot(xs, smooth, lw=2, label="3 块中位数")
        ax.axhline(data["baseline"]["cpu_per_work"] * 1e6, ls="--", lw=1,
                   label="冻结基线")
        ax.set_title(f"{title}：每请求 CPU（µs）")
        ax.set_xlabel("时间（s）")
        ax.legend(loc="upper left")
    axes[0].set_ylabel("CPU / 请求（µs）")
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)


def plot_eint(vuln, fixed, path):
    fig, ax = plt.subplots(figsize=(8, 4))
    for data, label in [(vuln, "缺陷版长跑"), (fixed, "修复版长跑")]:
        xs, ys = zip(*cum_series(data))
        ax.plot(xs, ys, lw=1.8, label=label)
    ax.set_title("累计内源耗散 E_int")
    ax.set_xlabel("时间（s）")
    ax.set_ylabel("E_int（σ·s）")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)


def plot_burst(vuln, fixed, path):
    fig, axes = plt.subplots(2, 1, figsize=(9, 6), sharex=True)
    for data, label in [(vuln, "缺陷版"), (fixed, "修复版")]:
        xs = [s["t"] for s in data["series"]]
        axes[0].plot(xs, [s["queue"] for s in data["series"]], lw=1.5, label=label)
        axes[1].plot(xs, [s["p99_ms"] for s in data["series"]], lw=1.5, label=label)
    axes[0].set_ylabel("队列深度")
    axes[1].set_ylabel("P99 延迟（ms）")
    axes[1].set_xlabel("时间（s）")
    axes[0].axhline(100, ls="--", lw=1, color="gray")
    axes[1].axhline(500, ls="--", lw=1, color="gray")
    for ax in axes:
        ax.legend()
    fig.suptitle("突发 500 任务：队列与延迟")
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)


def plot_bar(summary, path):
    names = [s["name"] for s in summary]
    values = [s["E_total_z"] for s in summary]
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(names, values, color=["#4c78a8" if "fixed" in n else "#e45756" for n in names])
    ax.set_ylabel("E_total_z")
    ax.set_title("三通道标准化耗散指数")
    ax.set_yscale("symlog", linthresh=1)
    ax.tick_params(axis="x", rotation=20)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)

    results = []
    for cond in conditions(args.quick):
        for i in range(cond["repeats"]):
            print(f"[{cond['name']}] run {i + 1}/{cond['repeats']} ...", flush=True)
            data = run_one(cond, i)
            results.append({
                "name": cond["name"],
                "mode": cond["mode"],
                "fixed": cond["fixed"],
                "data": data,
            })

    norm = normalize(results)
    (RESULTS / "summary.json").write_text(
        json.dumps(norm, ensure_ascii=False, indent=2), encoding="utf-8")

    # 取每组第一份结果画图
    vuln_long = pick(results, "vuln_long")
    fixed_long = pick(results, "fixed_long")
    vuln_burst = pick(results, "vuln_burst")
    fixed_burst = pick(results, "fixed_burst")

    plot_search(vuln_long, fixed_long, FIGURES / "cpu_per_request.png")
    plot_eint(vuln_long, fixed_long, FIGURES / "eint_cumulative.png")
    plot_burst(vuln_burst, fixed_burst, FIGURES / "burst_queue_latency.png")
    plot_bar(norm["summary"], FIGURES / "summary_bar.png")

    lines = ["# 耗散定位器：实测汇总", "",
             "| 条件 | 判定 | 背压 | E_int | E_leak | E_ext | E_total_z | 峰值队列 | 峰值 P99(ms) | 丢弃 |",
             "|---|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for s in norm["summary"]:
        lines.append(
            f"| {s['name']} | {s['verdict']} | {s['bp_verdict']} | "
            f"{s['E_int']:.4f} | {s['E_leak']:.4f} | {s['E_ext']:.4f} | "
            f"{s['E_total_z']:.2f} | {s['peak_queue']} | {s['peak_p99_ms']:.1f} | {s['dropped']} |")
    lines += ["", "## 定位与建议", ""]
    for s in norm["summary"]:
        if s["suggestions"]:
            lines.append(f"### {s['name']}")
            for item in s["suggestions"]:
                lines.append(f"- `{item['function']}`（占比 {item['share']:.0%}）：{item['suggestion']}")
            lines.append("")
    (RESULTS / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"\nfigures: {FIGURES}")


if __name__ == "__main__":
    main()
