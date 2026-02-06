#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Server-side risk calculation (CVSS + EPSS) for a subset of vulnerabilities.

Usage (inside backend container or host with project env):
  python3 scripts/diagnostics/calc_risk.py --top-epss 10

It prints Risk_s and per-CVE components.
"""

from __future__ import annotations

import argparse
import json
from typing import List

import os
import sys

# Ensure project root is importable when running inside docker container
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from models.database import DatabaseManager
from services.risk_calculator import RiskItem, compute_risk
import requests


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top-epss", type=int, default=10, help="Take top-N by EPSS from DB where EPSS is present")
    ap.add_argument("--fallback-top-cvss", type=int, default=10, help="If EPSS is missing in DB, take top-N by CVSS and fetch EPSS from FIRST")
    ap.add_argument("--update-db", action="store_true", help="Write fetched EPSS back into DB (turn.epss_score, turn.epss_percentile)")
    args = ap.parse_args()

    db = DatabaseManager()

    # legacy schema: turn.cve, turn.cvss, turn.epss_score
    rows = db.execute_query(
        """
        SELECT cve, COALESCE(cvss, 0) as cvss, epss_score
        FROM turn
        WHERE cve IS NOT NULL AND cve != '' AND epss_score IS NOT NULL
        ORDER BY epss_score DESC
        LIMIT %s
        """,
        (args.top_epss,),
    )

    items: List[RiskItem] = []
    for cve, cvss, epss in rows or []:
        items.append(RiskItem(cve_id=str(cve), cvss=float(cvss or 0.0), epss=float(epss or 0.0)))

    # If EPSS is not populated in DB, fetch EPSS for top CVSS CVEs
    if not items:
        rows2 = db.execute_query(
            """
            SELECT cve, COALESCE(cvss, 0) as cvss
            FROM turn
            WHERE cve IS NOT NULL AND cve != ''
            ORDER BY COALESCE(cvss, 0) DESC
            LIMIT %s
            """,
            (args.fallback_top_cvss,),
        )
        cves = [str(r[0]) for r in (rows2 or []) if r and r[0]]
        cvss_map = {str(r[0]): float(r[1] or 0.0) for r in (rows2 or []) if r and r[0]}

        epss_map = {}
        for cve in cves:
            try:
                r = requests.get("https://api.first.org/data/v1/epss", params={"cve": cve}, timeout=15)
                r.raise_for_status()
                data = r.json() or {}
                rows_data = data.get("data") or []
                if not rows_data:
                    continue
                epss = rows_data[0].get("epss")
                pct = rows_data[0].get("percentile")
                if epss is None:
                    continue
                epss_map[cve] = (float(epss), float(pct) if pct is not None else None)
            except Exception:
                continue

        if args.update_db and epss_map:
            for cve, (epss, pct) in epss_map.items():
                try:
                    db.execute_query(
                        "UPDATE turn SET epss_score = %s, epss_percentile = %s WHERE cve = %s",
                        (epss, pct, cve),
                    )
                except Exception:
                    pass

        for cve in cves:
            if cve in epss_map:
                epss, _pct = epss_map[cve]
                items.append(RiskItem(cve_id=cve, cvss=cvss_map.get(cve, 0.0), epss=epss))

    result = compute_risk(items)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())


