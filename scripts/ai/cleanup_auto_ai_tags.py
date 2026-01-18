#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cleanup incorrect auto-tags on vulnerabilities:

Problem:
- In older code, tag "ml" was applied to ALL analyzed vulnerabilities, even if is_ai_related=False.

Fix:
- For rows where etc.ai_analysis.is_ai_related is False:
  remove auto AI tags: ml, ai, llm, prompt-injection, data-poisoning, model-extraction, embedding, rag, agent,
  pytorch, tensorflow, onnx, cuda
  (and keep any other tags that user/operators may have set).
"""

import json
import sys
from collections import Counter
from typing import Any, Dict, List


AUTO_TAGS = {
    "ml", "ai", "llm", "prompt-injection", "data-poisoning", "model-extraction",
    "embedding", "rag", "agent", "pytorch", "tensorflow", "onnx", "cuda",
}


def normalize_tags(tags_any: Any) -> List[str]:
    if tags_any is None:
        return []
    if isinstance(tags_any, str):
        tags_any = [t.strip() for t in tags_any.split(",")]
    if not isinstance(tags_any, list):
        return []
    out: List[str] = []
    seen = set()
    for t in tags_any:
        s = str(t).strip()
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s[:40])
    return out


def main() -> int:
    project_root = __file__.split("/scripts/ai/")[0]
    sys.path.insert(0, project_root)

    from models.database import DatabaseManager
    from models.legacy_repositories import LegacyVulnerabilityRepository

    dbm = DatabaseManager()
    repo = LegacyVulnerabilityRepository(dbm.connection)

    cur = dbm.connection.cursor()
    cur.execute("SELECT id, etc FROM turn WHERE etc IS NOT NULL AND etc != '' AND etc ILIKE %s", ('%\"ai_analysis\"%',))

    scanned = 0
    changed = 0
    removed_counter = Counter()

    while True:
        rows = cur.fetchmany(2000)
        if not rows:
            break
        for (vid, etc_text) in rows:
            scanned += 1
            try:
                etc = json.loads(etc_text) if isinstance(etc_text, str) else (etc_text or {})
                if not isinstance(etc, dict):
                    continue
            except Exception:
                continue

            ai = etc.get("ai_analysis")
            if not isinstance(ai, dict):
                continue

            is_ai_related = bool(ai.get("is_ai_related"))
            tags = normalize_tags(etc.get("tags", []))
            if not tags:
                continue

            if is_ai_related:
                continue

            # remove only auto tags, keep others
            kept = []
            for t in tags:
                if t.lower() in AUTO_TAGS:
                    removed_counter[t.lower()] += 1
                else:
                    kept.append(t)

            kept = repo._normalize_tags(kept)
            if kept != tags:
                etc["tags"] = kept
                repo._merge_into_etc(int(vid), {"tags": kept})
                changed += 1

    cur.close()
    print(f"[cleanup_auto_ai_tags] scanned={scanned} changed={changed}")
    if removed_counter:
        print("[cleanup_auto_ai_tags] removed tags (top 20):")
        for t, c in removed_counter.most_common(20):
            print(f"  - {t}: {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


