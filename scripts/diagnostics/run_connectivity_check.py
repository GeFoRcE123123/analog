#!/usr/bin/env python3
"""
Server-side connectivity diagnostics runner.

Run this on Backend VM (10.0.88.20) inside the project directory:
  python3 scripts/diagnostics/run_connectivity_check.py

It will test:
  - backend -> DB (SQL + TCP)
  - backend -> ML API (HTTP)
  - backend -> k8s-worker (SSH)
  - k8s-worker -> DB/back (TCP) via SSH
"""

import json
import os
import sys
from datetime import datetime


def main() -> int:
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, project_root)

    try:
        from services.ml_platform_client import ml_platform_client
        report = ml_platform_client.diagnose_connectivity()
        print(json.dumps({"ts": datetime.now().isoformat(), "report": report}, ensure_ascii=False, indent=2))
        return 0 if report.get("success") else 2
    except Exception as e:
        print(json.dumps({"success": False, "error": str(e)}, ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


