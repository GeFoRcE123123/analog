#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run full AI analysis for ALL vulnerabilities in legacy DB (turn) using k8s-worker AI service.

Writes results into turn.etc (TEXT JSON string):
  etc.ai_analysis = {is_ai_related, confidence, ml_score, ai_context_score, keyword_hits, negative_hits, reasoning, analyzed_at}
Also maintains etc.tags list: adds 'AI' if ai_related.

This script is designed to run on the server (inside vulnerability-backend container).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import requests


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from models.database import DatabaseManager


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def parse_nvd_description(nvd_descriptions: Any) -> str:
    if not nvd_descriptions:
        return ""
    try:
        data = nvd_descriptions
        if isinstance(nvd_descriptions, str):
            data = json.loads(nvd_descriptions)
        if isinstance(data, list) and data:
            # NVD format: [{lang:'en', value:'...'}]
            first = data[0]
            if isinstance(first, dict):
                return str(first.get("value") or "").strip()
        if isinstance(data, dict):
            # fallback
            return str(data.get("value") or data.get("description") or "").strip()
    except Exception:
        return ""
    return ""


def parse_etc(etc_text: Any) -> Dict[str, Any]:
    if not etc_text:
        return {}
    if isinstance(etc_text, dict):
        return etc_text
    if not isinstance(etc_text, str):
        return {}
    try:
        val = json.loads(etc_text)
        return val if isinstance(val, dict) else {}
    except Exception:
        return {}


def dump_etc(d: Dict[str, Any]) -> str:
    return json.dumps(d, ensure_ascii=False)


def add_ai_tag(etc: Dict[str, Any], tag: str = "AI") -> None:
    tags = etc.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    if not isinstance(tags, list):
        tags = []
    norm = {str(t).strip() for t in tags if str(t).strip()}
    norm.add(tag)
    etc["tags"] = sorted(norm)


def remove_ai_tag(etc: Dict[str, Any], tag: str = "AI") -> None:
    tags = etc.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    if not isinstance(tags, list):
        return
    norm = [str(t).strip() for t in tags if str(t).strip() and str(t).strip().lower() != tag.lower()]
    etc["tags"] = norm


def fetch_batch_ai(ml_url: str, vulns: List[Dict[str, Any]], timeout: int) -> Dict[str, Any]:
    r = requests.post(
        f"{ml_url}/security/ai/batch-analyze",
        json={"vulnerabilities": vulns},
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json() or {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ml-url", default="http://10.0.88.25:8000", help="k8s-worker AI service base URL")
    ap.add_argument("--batch-size", type=int, default=500, help="Batch size")
    ap.add_argument("--timeout", type=int, default=60, help="HTTP timeout for ML calls (seconds)")
    ap.add_argument("--sleep", type=float, default=0.0, help="Sleep between batches (seconds)")
    ap.add_argument("--max", type=int, default=0, help="Max records to process (0 = all)")
    args = ap.parse_args()

    db = DatabaseManager()
    conn = db.connection

    processed = 0
    ai_count = 0
    last_id = 0

    started = time.time()
    print(f"[AI_FULL] start {now_iso()} ml={args.ml_url} batch={args.batch_size}")

    while True:
        if args.max and processed >= args.max:
            break

        limit = args.batch_size
        if args.max:
            limit = min(limit, args.max - processed)

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, cve, name, cvss, etc, nvd_descriptions
                FROM turn
                WHERE cve IS NOT NULL AND cve != '' AND id > %s
                ORDER BY id ASC
                LIMIT %s
                """,
                (last_id, limit),
            )
            rows = cur.fetchall()

        if not rows:
            break

        # build payload
        payload: List[Dict[str, Any]] = []
        id_by_cve: Dict[str, int] = {}
        row_by_id: Dict[int, Tuple[Any, Any]] = {}  # etc, nvd_desc not needed later
        for (rid, cve, name, cvss, etc_text, nvd_desc) in rows:
            cve_id = str(cve).strip()
            title = str(name or cve_id)[:300]
            desc = parse_nvd_description(nvd_desc) or ""
            if not desc:
                etc_dict = parse_etc(etc_text)
                desc = str(etc_dict.get("description") or etc_dict.get("details") or "").strip()
            payload.append({"cve_id": cve_id, "title": title, "description": desc, "cvss_score": float(cvss or 0.0)})
            id_by_cve[cve_id] = int(rid)
            row_by_id[int(rid)] = (etc_text, nvd_desc)

        # call ML
        try:
            resp = fetch_batch_ai(args.ml_url, payload, args.timeout)
        except Exception as e:
            print(f"[AI_FULL] batch error at id>{last_id}: {e}")
            time.sleep(2.0)
            continue

        results = resp.get("results") if isinstance(resp, dict) else None
        if not isinstance(results, list):
            print(f"[AI_FULL] bad response at id>{last_id}: {str(resp)[:200]}")
            time.sleep(1.0)
            continue

        updates: List[Tuple[str, int]] = []
        analyzed_at = now_iso()
        for r in results:
            try:
                cve_id = str((r.get("cve_id") or "")).strip()
                rid = id_by_cve.get(cve_id)
                if not rid:
                    continue
                etc_text, _ = row_by_id[rid]
                etc_dict = parse_etc(etc_text)

                is_ai = bool(r.get("is_ai_related"))
                ai_obj = {
                    "is_ai_related": is_ai,
                    "confidence": float(r.get("confidence") or 0.0),
                    "ml_score": float(r.get("ml_score") or 0.0),
                    "ai_context_score": float(r.get("ai_context_score") or 0.0),
                    "keyword_hits": r.get("keyword_hits") or [],
                    "negative_hits": r.get("negative_hits") or [],
                    "reasoning": r.get("reasoning") or "",
                    "analyzed_at": analyzed_at,
                    "source": "k8s-worker",
                }
                etc_dict["ai_analysis"] = ai_obj
                # Быстрые поля для UI/фильтрации (без JSONB)
                etc_dict["is_ai_related"] = is_ai
                etc_dict["ai_confidence"] = ai_obj.get("confidence", 0.0)
                if is_ai:
                    add_ai_tag(etc_dict, "AI")
                else:
                    remove_ai_tag(etc_dict, "AI")

                updates.append((dump_etc(etc_dict), rid))
                if is_ai:
                    ai_count += 1
            except Exception:
                continue

        if updates:
            with conn.cursor() as cur:
                cur.executemany("UPDATE turn SET etc = %s WHERE id = %s", updates)
            conn.commit()

        processed += len(rows)
        last_id = int(rows[-1][0])
        elapsed = time.time() - started
        rate = processed / elapsed if elapsed > 0 else 0
        print(f"[AI_FULL] processed={processed} ai_related={ai_count} last_id={last_id} rate={rate:.1f}/s")

        if args.sleep:
            time.sleep(args.sleep)

    elapsed = time.time() - started
    print(f"[AI_FULL] done processed={processed} ai_related={ai_count} elapsed={elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


