#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Backfill tags for vulnerabilities based on already stored AI analysis in turn.etc (TEXT JSON).

Goal:
- Ensure every vulnerability that has etc.ai_analysis gets tag "ml" (mandatory)
- Add derived category tags based on ai_analysis.keyword_hits/attack_hits/categories

This is needed when:
- you ran AI analysis before auto-tagging was implemented, so existing rows have ai_analysis but no tags.
"""

import json
import sys
from collections import Counter
from typing import Any, Dict, List


def derive_tags(ai: Dict[str, Any]) -> List[str]:
    # "ml" is ONLY for AI-related vulnerabilities, not for "analyzed by ML".
    if not ai.get("is_ai_related"):
        return []

    tags = ["ml", "ai"]

    # categories
    cats = ai.get("categories") or []
    if isinstance(cats, str):
        cats = [cats]
    for c in cats:
        c = str(c).strip().lower().replace(" ", "-")
        if c:
            tags.append(c[:40])

    hits = ai.get("keyword_hits") or []
    if isinstance(hits, str):
        hits = [hits]
    hit_text = " ".join([str(x).lower() for x in hits])

    if "llm" in hit_text or "gpt" in hit_text or "chatgpt" in hit_text:
        tags.append("llm")
    if "prompt injection" in hit_text or "jailbreak" in hit_text:
        tags.append("prompt-injection")
    if "poison" in hit_text or "data poisoning" in hit_text or "backdoor" in hit_text:
        tags.append("data-poisoning")
    if "model extraction" in hit_text or "model stealing" in hit_text:
        tags.append("model-extraction")
    if "embedding" in hit_text:
        tags.append("embedding")
    if "rag" in hit_text or "retrieval" in hit_text:
        tags.append("rag")
    if "agent" in hit_text:
        tags.append("agent")
    if "pytorch" in hit_text:
        tags.append("pytorch")
    if "tensorflow" in hit_text:
        tags.append("tensorflow")
    if "onnx" in hit_text:
        tags.append("onnx")
    if "cuda" in hit_text:
        tags.append("cuda")

    return tags


def main() -> int:
    project_root = __file__.split("/scripts/ai/")[0]
    sys.path.insert(0, project_root)

    from models.database import DatabaseManager
    from models.legacy_repositories import LegacyVulnerabilityRepository

    dbm = DatabaseManager()
    repo = LegacyVulnerabilityRepository(dbm.connection)

    cur = dbm.connection.cursor()
    cur.execute("SELECT id, etc FROM turn WHERE etc IS NOT NULL AND etc != ''")

    updated = 0
    scanned = 0
    tag_counts = Counter()

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

            existing = repo._normalize_tags(etc.get("tags", []))
            derived = repo._normalize_tags(derive_tags(ai))
            merged = repo._normalize_tags(existing + derived)

            if merged != existing:
                etc["tags"] = merged
                repo._merge_into_etc(int(vid), {"tags": merged})
                updated += 1
                for t in merged:
                    tag_counts[t.lower()] += 1

    cur.close()
    print(f"[backfill] scanned={scanned} updated={updated}")
    print("[backfill] top tags:")
    for t, c in tag_counts.most_common(20):
        print(f"  - {t}: {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


