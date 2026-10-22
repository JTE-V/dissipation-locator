#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""真实 CVE 复测用的最小 WSGI 服务：解析 multipart，读文件，返回字节数。

Werkzeug 3.0.0 存在 CVE-2023-46136：multipart 中某个文件内容以 CR/LF 开头、
后面是一大段不含 CR/LF 的数据时，解析器逐块向内部 bytearray 追加并重复查找边界，
CPU 随数据量超线性增长。3.0.1 修复。

用法：
  python3 wsgi_app.py --port 18080
"""

import argparse
import time
from wsgiref.simple_server import WSGIRequestHandler, make_server

from werkzeug.wrappers import Request


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


def app(environ, start_response):
    path = environ.get("PATH_INFO", "")
    if path == "/ping":
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]
    if path == "/upload" and environ.get("REQUEST_METHOD") == "POST":
        t0 = time.process_time()
        req = Request(environ)
        total = sum(len(f.read()) for f in req.files.values())
        parse_ms = (time.process_time() - t0) * 1000
        start_response("200 OK", [("Content-Type", "text/plain"),
                                  ("X-Parse-Cpu-Ms", f"{parse_ms:.3f}")])
        return [str(total).encode()]
    start_response("404 Not Found", [("Content-Type", "text/plain")])
    return [b"not found"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    args = ap.parse_args()
    with make_server("127.0.0.1", args.port, app, handler_class=QuietHandler) as srv:
        srv.serve_forever()


if __name__ == "__main__":
    main()
