"""Turn one (tool, case) scan into ledger rows -- the unit of aggregation for every score.

One row per ground-truth asset (``kind: gt``) records whether the tool found it, how precisely, and
how its attributes compared; one row per unmatched tool detection (``kind: fp``) records a false
positive together with whether it was *lexical* (triggered by a comment or string the corpus marks as
a non-asset mention).  Rows carry the category facets (language, asset type, subtype, family,
scenario, library, implicit, PQC) so that any category can be scored by filtering rows.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..baseline import GroundTruth, match_file
from ..normalize.model import Detection, NormalizedCBOM
from . import attributes as attrmod
from .matcher import MatchResult, Pair, is_lexical, match_case


@dataclass
class CaseEvaluation:
    tool: str
    case: str
    language: str
    rows: list = field(default_factory=list)
    fp_rows: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    pairs: list = field(default_factory=list)


def _norm(s: Optional[str]) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _location_stats(asset, pairs: list, tolerance: int) -> dict:
    spans = asset.locations()
    distinct = {(f, s, e) for f, s, e in spans}
    matched: set = set()
    reported = 0
    reported_matched = 0
    for p in pairs:
        for occ in p.detection.occurrences:
            if occ.line is None:
                continue
            reported += 1
            lo, hi = occ.line, occ.end_line or occ.line
            hit = False
            for f, s, e in distinct:
                if occ.file and not match_file(occ.file, f):
                    continue
                if lo <= e + tolerance and hi >= s - tolerance:
                    matched.add((f, s, e))
                    hit = True
            if hit:
                reported_matched += 1
    return {"expected": len(distinct), "matched": len(matched), "reported": reported, "reportedMatched": reported_matched}


def _facets(asset) -> dict:
    return {"assetType": asset.asset_type, "subtype": asset.subtype, "family": asset.family,
            "scenarios": list(asset.scenarios), "libraries": list(asset.libraries), "implicit": asset.implicit,
            "pqc": asset.pqc}


def _fp_facets(det: Detection) -> dict:
    d = det.descriptor
    if det.asset_type == "algorithm":
        subtype = (d.primitive if d else None) or det.attrs.get("primitive")
        family = d.family if d else None
    elif det.asset_type == "related-crypto-material":
        subtype, family = det.attrs.get("type"), None
    elif det.asset_type == "protocol":
        subtype, family = det.attrs.get("type"), None
    elif det.asset_type == "library":
        subtype, family = "library", _norm(det.name)
    else:
        subtype, family = det.asset_type, None
    return {"assetType": det.asset_type, "subtype": subtype, "family": family}


def evaluate_case(gt: GroundTruth, cbom: Optional[NormalizedCBOM], tool: str, tool_version: Optional[str],
                  *, status: str = "ok", tolerance: int = 1, treat_failed_as_zero: bool = False) -> CaseEvaluation:
    ev = CaseEvaluation(tool=tool, case=gt.case_id, language=gt.language)
    detections = cbom.detections if cbom else []
    scored = cbom is not None and status in ("ok", "empty") or (treat_failed_as_zero and status in ("failed", "timeout"))
    match = match_case(gt, detections, tolerance) if scored else MatchResult()
    ev.pairs = [p.to_dict() for p in match.pairs]
    pairs_by_asset: dict[str, list[Pair]] = {}
    for p in match.pairs:
        pairs_by_asset.setdefault(p.asset.id, []).append(p)

    for asset in gt.assets:
        pairs = pairs_by_asset.get(asset.id, [])
        best = match.best_pair(asset.id)
        row = {
            "tool": tool, "toolVersion": tool_version, "case": gt.case_id, "language": gt.language, "kind": "gt",
            "assetId": asset.id, "name": asset.name, **_facets(asset), "scored": scored,
            "detected": bool(pairs), "matchLevel": best.level if best else None,
            "identityScore": round(best.identity_score, 4) if best else 0.0,
            "located": any(p.located for p in pairs), "ambiguous": bool(best and best.ambiguous),
            "detections": len(pairs), "detectionRefs": sorted({p.detection.ref for p in pairs}),
            "attributes": {}, "completeness": None, "correctness": None,
            "locations": _location_stats(asset, pairs, tolerance) if not asset.implicit and asset.asset_type != "library" else None,
            "bestDetection": {"ref": best.detection.ref, "name": best.detection.name} if best else None,
        }
        if best is not None:
            outcomes = attrmod.compare(gt, asset, best.detection, best)
            row["attributes"] = {k: v.to_dict() for k, v in outcomes.items()}
            real = [v for k, v in outcomes.items() if k != "identity"]
            if real:
                reported = [v for v in real if v.is_reported]
                row["completeness"] = round(len(reported) / len(real), 4)
                row["correctness"] = round(sum(v.correct for v in reported) / len(reported), 4) if reported else None
        ev.rows.append(row)

    for det in match.unmatched:
        ev.fp_rows.append({
            "tool": tool, "toolVersion": tool_version, "case": gt.case_id, "language": gt.language, "kind": "fp",
            "assetId": None, "name": det.name, "ref": det.ref, **_fp_facets(det), "scored": True,
            "lexical": is_lexical(det, gt),
            "lines": sorted({o.line for o in det.occurrences if o.line is not None})[:20],
            "files": sorted({o.file for o in det.occurrences if o.file})[:5],
            "descriptor": det.descriptor.to_dict() if det.descriptor else None,
        })

    ev.stats = {
        "status": status, "scored": scored, "detections": len(detections), "matchedDetections": len(match.matched_detection_refs()),
        "pairs": len(match.pairs), "unmatched": len(match.unmatched), "unscored": len(match.unscored),
        "assets": len(gt.assets), "detectedAssets": sum(1 for r in ev.rows if r["detected"]),
        "format": cbom.format if cbom else None, "specVersion": cbom.metadata.spec_version if cbom else None,
        "reportedTool": {"name": cbom.metadata.tool_name, "version": cbom.metadata.tool_version} if cbom else None,
        "warnings": list(cbom.warnings) if cbom else [],
    }
    return ev
