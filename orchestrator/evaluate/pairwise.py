"""Head-to-head evidence: when tools A and B both reported an attribute of the same asset and
disagreed, which one was right?  This is the most direct evidence for the question 2CBOM asks when
it settles a conflict, so the reconciliation API consults it first.
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Optional

from .scoring import row_matches


def _norm_value(v) -> str:
    if isinstance(v, list):
        return json.dumps(sorted(str(x).lower() for x in v))
    if isinstance(v, dict):
        return json.dumps(v, sort_keys=True)
    return str(v).strip().lower()


def _empty() -> dict:
    return {"aWins": 0, "bWins": 0, "bothWrong": 0, "agree": 0, "agreeWrong": 0, "aOnly": 0, "bOnly": 0, "bothMissed": 0,
            "compared": 0}


def head_to_head(rows_a: list, rows_b: list, facets: Optional[dict] = None) -> dict:
    """Return ``{attribute: counts}`` for all attributes plus the ``"*"`` aggregate.

    ``rows_a`` / ``rows_b`` are ground-truth ledger rows of the two tools.  Rows are joined on
    (case, assetId); only rows that were scored on both sides take part.
    """
    facets = facets or {}
    index_b = {(r["case"], r["assetId"]): r for r in rows_b if r.get("kind") == "gt" and r.get("scored")}
    out: dict[str, dict] = defaultdict(_empty)
    for ra in rows_a:
        if ra.get("kind") != "gt" or not ra.get("scored"):
            continue
        if facets and not row_matches(ra, facets):
            continue
        rb = index_b.get((ra["case"], ra["assetId"]))
        if rb is None:
            continue
        da, db = bool(ra.get("detected")), bool(rb.get("detected"))
        agg = out["*"]
        agg["compared"] += 1
        if da and not db:
            agg["aOnly"] += 1
        elif db and not da:
            agg["bOnly"] += 1
        elif not da and not db:
            agg["bothMissed"] += 1
        if not (da and db):
            continue
        attrs_a = ra.get("attributes") or {}
        attrs_b = rb.get("attributes") or {}
        for name in sorted(set(attrs_a) | set(attrs_b)):
            xa, xb = attrs_a.get(name), attrs_b.get(name)
            if not xa or not xb:
                continue
            ra_rep = xa.get("reported") not in (None, "", [], {})
            rb_rep = xb.get("reported") not in (None, "", [], {})
            st = out[name]
            st["compared"] += 1
            if ra_rep and not rb_rep:
                st["aOnly"] += 1
                continue
            if rb_rep and not ra_rep:
                st["bOnly"] += 1
                continue
            if not ra_rep and not rb_rep:
                st["bothMissed"] += 1
                continue
            ca, cb = float(xa.get("correct") or 0.0), float(xb.get("correct") or 0.0)
            if _norm_value(xa["reported"]) == _norm_value(xb["reported"]):
                st["agree"] += 1
                if ca < 0.999:
                    st["agreeWrong"] += 1
                continue
            if ca > cb + 1e-9:
                st["aWins"] += 1
            elif cb > ca + 1e-9:
                st["bWins"] += 1
            else:
                st["bothWrong"] += 1
    # aggregate attribute disagreements into "*"
    agg = out["*"]
    for name, st in out.items():
        if name == "*":
            continue
        for k in ("aWins", "bWins", "bothWrong", "agree", "agreeWrong"):
            agg[k] += st[k]
    return dict(out)


def pair_key(tool_a: str, tool_b: str) -> tuple[str, bool]:
    """Canonical ordering so that (A,B) and (B,A) share one record; the flag says whether to swap."""
    if tool_a <= tool_b:
        return f"{tool_a}|{tool_b}", False
    return f"{tool_b}|{tool_a}", True


def swap_counts(counts: dict) -> dict:
    return {**counts, "aWins": counts["bWins"], "bWins": counts["aWins"], "aOnly": counts["bOnly"], "bOnly": counts["aOnly"]}
