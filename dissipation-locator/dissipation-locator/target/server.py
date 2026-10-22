#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""耗散靶场：一个带资源耗尽缺陷的日志检索服务。

两个版本：
- 缺陷版（默认）
  * /search 每次全量扫描历史查询，复杂度 O(n)，历史越长 CPU 越高 → 内源漂移
  * /burst 任务进入无界队列，消费速度 < 生产速度 → 队列堆积、延迟升高 → 外部损耗
- 修复版（--fixed）
  * /search 只维护增量聚合，O(1)
  * /burst 使用有界队列 + 阻塞背压，队列深度受控

暴露接口：
  GET /search?q=xxx
  GET /burst?n=500
  GET /metrics
  GET /reset
"""

import argparse
import json
import os
import queue
import resource
import sys
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")


class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.search_completed = 0
        self.jobs_arrived = 0
        self.jobs_completed = 0
        self.jobs_dropped = 0
        self.late_drops = 0
        self.search_timeouts = 0
        self.enqueue_blocked_s = 0.0
        self.enqueue_blocks = 0
        self.enqueue_max_wait_s = 0.0
        self.dequeue_wait_s = 0.0
        self.dequeue_max_wait_s = 0.0
        self.latencies = deque(maxlen=2000)
        self.profile = defaultdict(float)
        self.first_counts = defaultdict(int)
        self.history = []
        self.total_len = 0


class Service:
    def __init__(self, fixed=False, capacity=100, job_sleep=0.01, variant="none",
                 fixed_v1=False):
        self.fixed = fixed
        self.fixed_v1 = fixed_v1
        self.capacity = capacity
        self.job_sleep = job_sleep
        self.variant = variant
        self.m = Metrics()
        self.queue = queue.Queue(maxsize=capacity if fixed else 0)
        self.worker = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker.start()

    # ---------- 搜索 ----------
    def handle_search(self, q):
        t0 = time.process_time()
        with self.m.lock:
            self.m.search_completed += 1

        if self.fixed:
            # 修复版：O(1) 聚合，且保持与缺陷版相同的返回值
            with self.m.lock:
                self.m.total_len += len(q)
                if self.fixed_v1:
                    # 第一版修复（已证伪）：只返回 total_len，改变了返回值
                    result = self.m.total_len
                else:
                    prefix = q[:1]
                    if prefix:
                        self.m.first_counts[prefix] += 1
                        result = self.m.total_len + self.m.first_counts[prefix]
                    else:
                        result = self.m.total_len
        elif self.variant == "timeout":
            # 错误修法：加 50ms 超时，但线程不会被取消，扫描还在跑
            with self.m.lock:
                self.m.history.append(q)
                history = list(self.m.history)
            box = {}

            def scan():
                box["result"] = self.scan_history(history, q)

            th = threading.Thread(target=scan, daemon=True)
            th.start()
            th.join(0.05)
            if "result" in box:
                result = box["result"]
            else:
                # 超时真的触发了：请求已返回，扫描线程还在后台跑
                result = -1
                with self.m.lock:
                    self.m.search_timeouts += 1
        else:
            # 缺陷版：每次全量扫描历史，O(n)
            with self.m.lock:
                self.m.history.append(q)
                history = list(self.m.history)
            result = self.scan_history(history, q)

        with self.m.lock:
            self.m.profile["handle_search"] += time.process_time() - t0
        return result

    def scan_history(self, history, q):
        """缺陷所在：历史越长，这一段越慢。"""
        t0 = time.process_time()
        total = 0
        prefix = q[:1]
        for item in history:
            total += len(item)
            if prefix and item.startswith(prefix):
                total += 1
        with self.m.lock:
            self.m.profile["scan_history"] += time.process_time() - t0
        return total

    # ---------- 突发任务 ----------
    def enqueue_burst(self, n):
        t0 = time.process_time()
        accepted = 0
        for _ in range(n):
            with self.m.lock:
                self.m.jobs_arrived += 1
            item = (time.time(), "x" * 64)
            if self.fixed:
                # 修复版：有界队列，满了就阻塞等待（背压）
                t_put = time.perf_counter()
                try:
                    self.queue.put(item, timeout=0.05)
                    waited = time.perf_counter() - t_put
                    with self.m.lock:
                        self.m.enqueue_blocked_s += waited
                        if waited >= 0.001:
                            self.m.enqueue_blocks += 1
                        self.m.enqueue_max_wait_s = max(
                            self.m.enqueue_max_wait_s, waited)
                    accepted += 1
                except queue.Full:
                    waited = time.perf_counter() - t_put
                    with self.m.lock:
                        self.m.jobs_dropped += 1
                        self.m.enqueue_blocked_s += waited
                        if waited >= 0.001:
                            self.m.enqueue_blocks += 1
                        self.m.enqueue_max_wait_s = max(
                            self.m.enqueue_max_wait_s, waited)
            else:
                # 缺陷版：无界队列，来多少收多少
                self.queue.put(item)
                accepted += 1
        with self.m.lock:
            self.m.profile["enqueue_burst"] += time.process_time() - t0
        return accepted

    def _worker_loop(self):
        while True:
            item = self.queue.get()
            if item is None:
                break
            enqueued_at, _payload = item
            wait = time.time() - enqueued_at
            with self.m.lock:
                self.m.dequeue_wait_s += wait
                self.m.dequeue_max_wait_s = max(self.m.dequeue_max_wait_s, wait)
            t0 = time.process_time()
            time.sleep(self.job_sleep)  # 模拟下游处理
            # 少量 CPU 工作，保证 worker 也有可观测的耗时
            acc = 0
            for i in range(200):
                acc += i
            proc = time.process_time() - t0
            latency = time.time() - enqueued_at
            with self.m.lock:
                self.m.jobs_completed += 1
                self.m.latencies.append(latency)
                self.m.profile["worker_job"] += proc

    # ---------- 指标 ----------
    def snapshot(self):
        usage = resource.getrusage(resource.RUSAGE_SELF)
        rss_kb = 0
        try:
            with open("/proc/self/statm", "r") as f:
                rss_kb = int(f.read().split()[1]) * PAGE_SIZE // 1024
        except OSError:
            pass

        io_read = io_write = 0
        try:
            with open("/proc/self/io", "r") as f:
                for line in f:
                    if line.startswith("read_bytes:"):
                        io_read = int(line.split()[1])
                    elif line.startswith("write_bytes:"):
                        io_write = int(line.split()[1])
        except OSError:
            pass

        with self.m.lock:
            lat = sorted(self.m.latencies)
            p99 = lat[min(len(lat) - 1, int(len(lat) * 0.99))] if lat else 0.0
            data = {
                "uptime_s": time.time() - self.started_at,
                "cpu_user_s": usage.ru_utime,
                "cpu_sys_s": usage.ru_stime,
                "rss_kb": rss_kb,
                "io_read_bytes": io_read,
                "io_write_bytes": io_write,
                "search_completed": self.m.search_completed,
                "jobs_arrived": self.m.jobs_arrived,
                "jobs_completed": self.m.jobs_completed,
                "jobs_dropped": self.m.jobs_dropped,
                "late_drops": self.m.late_drops,
                "search_timeouts": self.m.search_timeouts,
                "enqueue_blocked_s": round(self.m.enqueue_blocked_s, 6),
                "enqueue_blocks": self.m.enqueue_blocks,
                "enqueue_max_wait_s": round(self.m.enqueue_max_wait_s, 6),
                "dequeue_wait_s": round(self.m.dequeue_wait_s, 6),
                "dequeue_max_wait_s": round(self.m.dequeue_max_wait_s, 6),
                "queue_depth": self.queue.qsize(),
                "threads": threading.active_count(),
                "latency_p99_ms": round(p99 * 1000, 3),
                "profile": {k: round(v, 6) for k, v in self.m.profile.items()},
            }
        return data

    def reset(self):
        with self.m.lock:
            self.m.search_completed = 0
            self.m.jobs_arrived = 0
            self.m.jobs_completed = 0
            self.m.jobs_dropped = 0
            self.m.late_drops = 0
            self.m.search_timeouts = 0
            self.m.enqueue_blocked_s = 0.0
            self.m.enqueue_blocks = 0
            self.m.enqueue_max_wait_s = 0.0
            self.m.dequeue_wait_s = 0.0
            self.m.dequeue_max_wait_s = 0.0
            self.m.latencies.clear()
            self.m.profile.clear()
            self.m.first_counts.clear()
            self.m.history.clear()
            self.m.total_len = 0
        try:
            while True:
                self.queue.get_nowait()
        except queue.Empty:
            pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = False

    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        service = self.server.service
        query = parse_qs(parsed.query)

        if parsed.path == "/search":
            q = query.get("q", [""])[0]
            self._json({"result": service.handle_search(q)})
        elif parsed.path == "/burst":
            n = int(query.get("n", ["100"])[0])
            self._json({"accepted": service.enqueue_burst(n)})
        elif parsed.path == "/metrics":
            self._json(service.snapshot())
        elif parsed.path == "/reset":
            service.reset()
            self._json({"ok": True})
        else:
            self._json({"error": "not found"}, 404)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--fixed", action="store_true", help="启用修复版")
    parser.add_argument("--capacity", type=int, default=100)
    parser.add_argument("--job-sleep", type=float, default=0.01)
    parser.add_argument("--variant", choices=["none", "timeout"], default="none")
    parser.add_argument("--no-nagle", action="store_true",
                        help="关闭 Nagle，降低单请求往返延迟（对抗复测用）")
    parser.add_argument("--fixed-v1", action="store_true",
                        help="复现第一版修复（只返回 total_len，功能不等价）")
    args = parser.parse_args()

    if args.no_nagle:
        Handler.disable_nagle_algorithm = True

    service = Service(fixed=args.fixed, capacity=args.capacity,
                      job_sleep=args.job_sleep, variant=args.variant,
                      fixed_v1=args.fixed_v1)
    service.started_at = time.time()
    httpd = Server(("127.0.0.1", args.port), Handler)
    httpd.service = service
    print(f"listening 127.0.0.1:{args.port} fixed={args.fixed}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        service.queue.put(None)
        httpd.server_close()


if __name__ == "__main__":
    main()
