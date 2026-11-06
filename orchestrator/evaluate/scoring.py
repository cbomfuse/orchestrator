"""Aggregate ledger rows into category scores.

A *category* is a dictionary of facets, e.g. ``{"language": "Java", "subtype": "hash"}``.  Facets:

===========  ===========================================================================
language     the corpus language (``Python``, ``Java``, ``Go``, ``TypeScript``, ``C#``)
case         the corpus directory (``CSharp``), when it differs from the language
assetType    algorithm | related-crypto-material | certificate | protocol | library
subtype      algorithm primitive (hash, kdf, ae, ...), material type, protocol type, "library"
family       lexicon family (aes, rsa, sha2, ml-kem, ...) -- for materials, the family of the
             algorithm they belong to
scenario     corpus scenario id (S01..S24); an asset belongs to every scenario it occurs in
library      corpus library id (lib.pyca, ...); an asset belongs to every library that uses it
implicit     true for runtime-implied assets without a source occurrence
pqc          true for post-quantum families
===========  ===========================================================================

Precision is computed from the tool's false positives whose *reported* facets fall in the category;
false positives carry no scenario, library, implicit or PQC facet, so those facets only narrow the
recall/quality side.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Optional

from .stats import posterior, prob_above_half, shrink, wilson_interval

METRICS = ("recall", "precision", "completeness", "correctness", "locality")
ROW_FACETS = ("language", "case", "assetType", "subtype", "family", "implicit", "pqc")
LIST_FACETS = {"scenario": "scenarios", "library": "libraries"}
FP_FACETS = ("language", "case", "assetType", "subtype", "family")

# Category combinations precomputed into the scorecard (the API can score any other combination).
FACET_COMBOS: tuple[tuple[str, ...], ...] = (
    (), ("language",), ("assetType",), ("subtype",), ("family",), ("scenario",), ("library",), ("implicit",), ("pqc",),
    ("language", "assetType"), ("language", "subtype"), ("language", "family"), ("assetType", "subtype"),
    ("language", "assetType", "subtype"), ("language", "scenario"), ("language", "pqc"),
)


def category_key(facets: dict) -> str:
    if not facets:
        return "*"
    return ";".join(f"{k}={facets[k]}" for k in sorted(facets))


def parse_category(text: str) -> dict:
    """``language=Java;subtype=hash`` -> dict (``*`` or empty -> {})."""
    out: dict = {}
    if not text or text.strip() in ("*", ""):
        return out
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"category facet {part!r} must look like name=value")
        k, v = part.split("=", 1)
        k, v = k.strip(), v.strip()
        if k in ("implicit", "pqc"):
            v = v.lower() in ("1", "true", "yes")
        out[k] = v
    return out


def row_matches(row: dict, facets: dict) -> bool:
    for k, v in facets.items():
        if k in LIST_FACETS:
            if v not in (row.get(LIST_FACETS[k]) or []):
                return False
        elif k == "tool":
            if row.get("tool") != v:
                return False
        else:
            if row.get(k) != v:
                return False
    return True


def fp_matches(row: dict, facets: dict) -> bool:
    for k, v in facets.items():
        if k in ("tool",):
            if row.get("tool") != v:
                return False
        elif k in FP_FACETS:
            if row.get(k) != v:
                return False
        # scenario / library / implicit / pqc are not defined for false positives
    return True


def _mean(values: Iterable[Optional[float]]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    return sum(vals) / len(vals) if vals else None


def aggregate(gt_rows: list, fp_rows: list, weights: dict, *, prior_score: Optional[float] = None,
              shrinkage_k: float = 5.0, include_unscored: bool = False) -> dict:
    """Score one category for one tool from its ledger rows."""
    rows = [r for r in gt_rows if r.get("scored") or include_unscored]
    support = len(rows)
    detected_rows = [r for r in rows if r.get("detected")]
    detected = len(detected_rows)
    recall = detected / support if support else None
    tp_refs = set()
    for r in detected_rows:
        for ref in r.get("detectionRefs") or ([r["bestDetection"]["ref"]] if r.get("bestDetection") else []):
            tp_refs.add((r["case"], ref))
    tp = len(tp_refs)
    fp = len(fp_rows)
    precision = tp / (tp + fp) if (tp + fp) else None
    completeness = _mean(r.get("completeness") for r in detected_rows)
    correctness = _mean(r.get("correctness") for r in detected_rows)
    loc_vals = []
    for r in detected_rows:
        loc = r.get("locations")
        if loc and loc.get("expected"):
            loc_vals.append(loc["matched"] / loc["expected"])
    locality = _mean(loc_vals)
    identity = _mean(r.get("identityScore") for r in detected_rows)
    exact = sum(1 for r in detected_rows if r.get("matchLevel") in ("exact", "oid"))
    lexical = sum(1 for r in fp_rows if r.get("lexical"))

    metrics = {"recall": recall, "precision": precision, "completeness": completeness, "correctness": correctness,
               "locality": locality}
    total_w = sum(weights.get(m, 0.0) for m in METRICS if metrics[m] is not None)
    score = None
    if total_w > 0:
        score = sum(weights.get(m, 0.0) * metrics[m] for m in METRICS if metrics[m] is not None) / total_w
    lo, hi = wilson_interval(detected, support) if support else (0.0, 1.0)

    # per-attribute completeness / correctness
    attrs: dict[str, dict] = defaultdict(lambda: {"expected": 0, "reported": 0, "correct": 0.0})
    for r in detected_rows:
        for name, a in (r.get("attributes") or {}).items():
            st = attrs[name]
            st["expected"] += 1
            if a.get("reported") not in (None, "", [], {}):
                st["reported"] += 1
                st["correct"] += float(a.get("correct") or 0.0)
    attr_out = {}
    for name, st in sorted(attrs.items()):
        attr_out[name] = {
            "expected": st["expected"], "reported": st["reported"], "correct": round(st["correct"], 4),
            "completeness": round(st["reported"] / st["expected"], 4) if st["expected"] else None,
            "correctness": round(st["correct"] / st["reported"], 4) if st["reported"] else None,
        }

    return {
        "support": support, "detected": detected, "exact": exact, "truePositives": tp, "falsePositives": fp,
        "lexicalFalsePositives": lexical, "identity": round(identity, 4) if identity is not None else None,
        "recall": _r(recall), "recallInterval": [round(lo, 4), round(hi, 4)],
        "precision": _r(precision), "completeness": _r(completeness), "correctness": _r(correctness),
        "locality": _r(locality), "score": _r(score),
        "scoreShrunk": _r(shrink(score, support, prior_score, shrinkage_k)) if prior_score is not None else _r(score),
        "attributes": attr_out,
    }


def _r(v: Optional[float]) -> Optional[float]:
    return round(v, 4) if v is not None else None


def attribute_evidence(gt_rows: list, attribute: str) -> tuple[float, int]:
    """(sum of correct, number reported) for an attribute over detected, scored rows."""
    correct = 0.0
    n = 0
    for r in gt_rows:
        if not r.get("scored") or not r.get("detected"):
            continue
        a = (r.get("attributes") or {}).get(attribute)
        if not a or a.get("reported") in (None, "", [], {}):
            continue
        n += 1
        correct += float(a.get("correct") or 0.0)
    return correct, n


def strengths(agg: dict, threshold: float, min_support: int) -> list:
    """Attributes the tool reports reliably in this category (feeds 2CBOM's ``strengths``)."""
    out = []
    for name, st in (agg.get("attributes") or {}).items():
        if name == "identity":
            continue
        if st["reported"] >= min_support and st["correctness"] is not None and st["correctness"] >= threshold \
                and (st["completeness"] or 0) >= 0.5:
            out.append(name)
    return out


def rate_posterior(correct: float, n: int) -> tuple[float, float]:
    return posterior(correct, n)


def detection_rate_confidence(detected: int, support: int) -> float:
    """P(recall > 0.5) -- a quick 'is this tool better than a coin flip here' indicator."""
    a, b = posterior(detected, support)
    return prob_above_half(a, b)
