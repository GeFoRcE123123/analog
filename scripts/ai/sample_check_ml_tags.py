#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sample-check whether non-AI vulnerabilities still contain the 'ml' tag.
Runs on backend container where /app is project root.
"""

import json
import os
import sys

project_root = os.environ.get("APP_DIR") or "/app"
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from models.database import DatabaseManager


def main() -> int:
    db = DatabaseManager().connection
    cur = db.cursor()

    cur.execute("SELECT cve, etc FROM turn WHERE etc ILIKE %s AND etc ILIKE %s", ('%\"ai_analysis\"%', '%\"tags\"%'))
    rows = cur.fetchmany(5000)

    bad = 0
    bad_samples = []
    for cve, etc_text in rows:
        try:
            etc = json.loads(etc_text) if etc_text else {}
        except Exception:
            continue

        ai = etc.get("ai_analysis") or {}
        if not isinstance(ai, dict):
            continue
        is_ai = bool(ai.get("is_ai_related"))
        tags = etc.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        if not isinstance(tags, list):
            continue
        tags_norm = [str(t).strip().lower() for t in tags if str(t).strip()]

        if (not is_ai) and ("ml" in tags_norm):
            bad += 1
            if len(bad_samples) < 5:
                bad_samples.append((cve, tags_norm, ai.get("categories")))

    print("[sample_check_ml_tags]")
    print("checked_rows:", len(rows))
    print("non_ai_with_ml_tag_in_first_5000:", bad)
    for s in bad_samples:
        print("sample:", s)

    cur.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


