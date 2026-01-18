"""
Risk calculator using CVSS + EPSS formulas (based on provided methodology).

We implement:
  (2)  P(CVE_i) = EPSS(CVE_i) * Π_{k<i} (1 - EPSS(CVE_k))   (ordering by EPSS desc)
  (1)  P̄(CVE_i) = P(CVE_i) / Σ_j P(CVE_j)
  (3)  Ū(CVE_i) = (CVSS/EPSS) / max_j(CVSS/EPSS)

Project does not model tactics/scenarios explicitly, so scenario damage is taken as:
  Ū_s = mean_i Ū(CVE_i)

And scenario risk:
  Risk_s = Π_i P̄(CVE_i) × Ū_s
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

import math

import requests


@dataclass
class RiskItem:
    cve_id: str
    cvss: float
    epss: float


def fetch_epss_scores(cve_ids: Sequence[str], timeout: int = 20) -> Dict[str, float]:
    """
    Fetch EPSS scores from FIRST EPSS API.
    Returns mapping cve_id -> epss (0..1) for those found.
    """
    out: Dict[str, float] = {}
    for cve in cve_ids:
        if not cve:
            continue
        try:
            r = requests.get("https://api.first.org/data/v1/epss", params={"cve": cve}, timeout=timeout)
            r.raise_for_status()
            data = r.json() or {}
            rows = data.get("data") or []
            if rows:
                epss = rows[0].get("epss")
                if epss is not None:
                    out[cve] = float(epss)
        except Exception:
            # best-effort; skip unreachable/unknown
            continue
    return out


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return default
        return float(v)
    except Exception:
        return default


def compute_probability_chain(items: List[RiskItem]) -> List[Tuple[RiskItem, float]]:
    """
    Compute P(CVE_i) with ordering by EPSS desc.
    """
    ordered = sorted(items, key=lambda x: x.epss, reverse=True)
    prob_chain: List[Tuple[RiskItem, float]] = []
    prev_prod = 1.0
    for it in ordered:
        p = max(0.0, min(1.0, it.epss)) * prev_prod
        prob_chain.append((it, p))
        prev_prod *= max(0.0, 1.0 - max(0.0, min(1.0, it.epss)))
    return prob_chain


def compute_risk(items: List[RiskItem]) -> Dict[str, Any]:
    """
    Compute risk details for the given CVEs.
    """
    # filter invalid epss
    clean: List[RiskItem] = []
    for it in items:
        if not it.cve_id:
            continue
        if it.epss is None:
            continue
        epss = float(it.epss)
        if epss <= 0:
            continue
        clean.append(RiskItem(cve_id=it.cve_id, cvss=float(it.cvss), epss=epss))

    if not clean:
        return {
            "success": False,
            "error": "No items with EPSS>0 to compute risk.",
            "items": [],
        }

    # (2)
    chain = compute_probability_chain(clean)
    total_p = sum(p for _, p in chain) or 1.0

    # (3)
    ratios = [(it, (it.cvss / it.epss) if it.epss > 0 else 0.0) for it, _ in chain]
    max_ratio = max(r for _, r in ratios) or 1.0

    details: List[Dict[str, Any]] = []
    for (it, p), (_, ratio) in zip(chain, ratios):
        p_bar = p / total_p  # (1)
        u_bar = ratio / max_ratio  # (3)
        details.append(
            {
                "cve_id": it.cve_id,
                "cvss": it.cvss,
                "epss": it.epss,
                "p": p,
                "p_bar": p_bar,
                "u_bar": u_bar,
                "ratio": ratio,
            }
        )

    # scenario damage (practical adaptation)
    u_s = sum(d["u_bar"] for d in details) / len(details)

    # Risk_s (avoid underflow via log)
    log_prod = 0.0
    for d in details:
        p_bar = max(d["p_bar"], 1e-12)
        log_prod += math.log(p_bar)
    p_prod = math.exp(log_prod)
    risk_s = p_prod * u_s

    return {
        "success": True,
        "count": len(details),
        "u_s": u_s,
        "p_prod": p_prod,
        "risk_s": risk_s,
        "items": details,
    }


