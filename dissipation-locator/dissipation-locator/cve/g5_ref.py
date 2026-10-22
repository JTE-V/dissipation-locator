#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""G5 负对照：对缺陷版跑 180s，确认「长跑等价短跑」判据能把它筛出来。

用法：
  python3 cve/g5_ref.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attack import OUT, check_short_equals_long, start  # noqa: E402


def main():
    proc, port = start(False)
    try:
        res = check_short_equals_long(port)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    res["label"] = "vuln"
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "g5_vuln.json"
    path.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: res[k] for k in ("criterion", "pass", "last_over_first")},
                     ensure_ascii=False))
    print("blocks:", res["windows_us_per_req"])
    print("written:", path)


if __name__ == "__main__":
    main()
