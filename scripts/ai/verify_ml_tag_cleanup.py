#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verify that tag "ml" is only present for AI-related vulnerabilities.
Runs against legacy table `turn` with `etc` as TEXT JSON.
"""

import os
import sys

# Ensure imports work both locally and inside docker container (/app)
project_root = os.environ.get("APP_DIR") or "/app"
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from models.database import DatabaseManager


def main() -> int:
    db = DatabaseManager().connection
    cur = db.cursor()

    cur.execute("SELECT COUNT(1) FROM turn WHERE etc ILIKE %s", ('%\"ai_analysis\"%',))
    rows_with_ai_analysis = cur.fetchone()[0]

    cur.execute("SELECT COUNT(1) FROM turn WHERE etc ILIKE %s", ('%\"is_ai_related\": true%',))
    rows_ai_related_true_like = cur.fetchone()[0]

    cur.execute("SELECT COUNT(1) FROM turn WHERE etc ILIKE %s", ('%\"ml\"%',))
    rows_ml_like = cur.fetchone()[0]

    cur.execute(
        "SELECT COUNT(1) FROM turn WHERE etc ILIKE %s AND etc ILIKE %s",
        ('%\"ml\"%', '%\"is_ai_related\": true%'),
    )
    rows_ml_and_ai_true_like = cur.fetchone()[0]

    cur.execute(
        "SELECT COUNT(1) FROM turn WHERE etc ILIKE %s AND etc ILIKE %s",
        ('%\"ml\"%', '%\"is_ai_related\": false%'),
    )
    rows_ml_and_ai_false_like = cur.fetchone()[0]

    print("[verify_ml_tag_cleanup]")
    print("rows_with_ai_analysis:", rows_with_ai_analysis)
    print("rows_ai_related_true_like:", rows_ai_related_true_like)
    print("rows_ml_like:", rows_ml_like)
    print("rows_ml_and_ai_true_like:", rows_ml_and_ai_true_like)
    print("rows_ml_and_ai_false_like:", rows_ml_and_ai_false_like)

    cur.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


