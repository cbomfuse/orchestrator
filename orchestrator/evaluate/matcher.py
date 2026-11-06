"""Assign tool detections to ground-truth assets.

A detection is matched to a ground-truth asset of the same asset type when it is *compatible*
(same algorithm family, same material type, ...).  Among compatible assets the ones whose source
occurrences overlap the detection's reported locations win ("located" matches; a detection whose
occurrences span several assets credits each of them).  A detection without usable locations is
assigned to the single most similar asset.  Every pair records an *identity score* in [0, 1]
(matched slots minus conflicting slots over the asset's discriminating slots) so that a tool that
reports ``AES`` where the truth is ``AES-256-GCM`` is credited with a partial detection rather than
a miss plus a false positive.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..baseline import GTAsset, GroundTruth, match_file, purl_key
from ..normalize.lexicon import EC_FAMILIES, hash_equal, padding_equal, param_equal, parse_name
from ..normalize.model import Detection

MATERIAL_KEY_TYPES = {"private-key", "public-key", "secret-key", "key"}


@dataclass
class Pair:
    detection: Detection
    asset: GTAsset
    identity_score: float
    slots: dict                      # slot -> match | conflict | missing
    overlap: int                     # detection occurrences that hit an asset span
    located: bool
    level: str                       # oid | exact | partial | family | type | name
    ambiguous: bool = False

    def to_dict(self) -> dict:
        return {"detection": self.detection.ref, "asset": self.asset.id, "identityScore": round(self.identity_score, 4),
                "slots": self.slots, "overlap": self.overlap, "located": self.located, "level": self.level,
                "ambiguous": self.ambiguous}


@dataclass
class MatchResult:
    pairs: list = field(default_factory=list)                # list[Pair]
    unmatched: list = field(default_factory=list)            # list[Detection]
    unscored: list = field(default_factory=list)             # detections with an unknown asset type

    def pairs_for_asset(self, asset_id: str) -> list:
        return [p for p in self.pairs if p.asset.id == asset_id]

    def best_pair(self, asset_id: str) -> Optional[Pair]:
        ps = self.pairs_for_asset(asset_id)
        if not ps:
            return None
        return max(ps, key=lambda p: (p.identity_score, p.overlap, len([v for v in p.detection.attrs.values() if v is not None])))

    def matched_detection_refs(self) -> set:
        return {p.detection.ref for p in self.pairs}


# ----------------------------------------------------------------------------- locations
def overlap_count(det: Detection, asset: GTAsset, tolerance: int) -> int:
    spans = asset.locations()
    if not spans:
        return 0
    n = 0
    for occ in det.occurrences:
        if occ.line is None:
            continue
        lo = occ.line
        hi = occ.end_line or occ.line
        for f, s, e in spans:
            if occ.file and not match_file(occ.file, f):
                continue
            if lo <= e + tolerance and hi >= s - tolerance:
                n += 1
                break
    return n


def has_locations(det: Detection) -> bool:
    return any(o.line is not None for o in det.occurrences)


# ----------------------------------------------------------------------------- lexical false positives
def is_lexical(det: Detection, gt: GroundTruth) -> bool:
    """True when the detection sits on a line the corpus marks as a non-asset mention of the same name."""
    mentions = gt.mention_lines()
    if not mentions:
        return False
    dn = _norm_name(det.name)
    fam = det.descriptor.family if det.descriptor else None
    for occ in det.occurrences:
        if occ.line is None or occ.line not in mentions:
            continue
        if occ.file and gt.file and not match_file(occ.file, gt.file):
            continue
        for m in mentions[occ.line]:
            mt = _norm_name(m.text)
            if mt and dn and (mt in dn or dn in mt):
                return True
            if fam and parse_name(m.text).family == fam:
                return True
    return False


# ----------------------------------------------------------------------------- algorithms
def family_compat(tool_family: Optional[str], gt_family: Optional[str]) -> Optional[float]:
    """1.0 same family, 0.5 generic EC vs a concrete EC family, None incompatible."""
    if not tool_family or not gt_family:
        return None
    if tool_family == gt_family:
        return 1.0
    if tool_family == "ec" and gt_family in EC_FAMILIES:
        return 0.5
    if gt_family == "ec" and tool_family in EC_FAMILIES:
        return 0.5
    return None


def slot_compare(det: Detection, asset: GTAsset) -> tuple[Optional[float], dict]:
    """Return (identity score, slot verdicts) or (None, {}) when the families are incompatible."""
    slots = asset.identity_slots
    d = det.descriptor
    if not slots or d is None:
        return None, {}
    fc = family_compat(d.family, slots.get("family"))
    if fc is None:
        return None, {}
    verdict = {"family": "match" if fc == 1.0 else "generic"}
    score = fc
    n = len(slots)
    for slot, expected in slots.items():
        if slot == "family":
            continue
        got = getattr(d, slot)
        if got in (None, ""):
            verdict[slot] = "missing"
            continue
        if slot == "param":
            ok = param_equal(got, expected)
        elif slot == "padding":
            ok = padding_equal(got, expected)
        elif slot == "hash":
            ok = hash_equal(got, expected)
        else:
            ok = str(got).lower() == str(expected).lower()
        if ok:
            verdict[slot] = "match"
            score += 1
        else:
            verdict[slot] = "conflict"
            score -= 1
    return max(0.0, score / n), verdict


def _level(score: float, verdict: dict, oid: bool) -> str:
    if oid:
        return "oid"
    if score >= 0.999:
        return "exact"
    if all(v == "match" for k, v in verdict.items() if k != "family") and verdict.get("family") == "match":
        return "exact"
    if len(verdict) == 1 or all(v == "missing" for k, v in verdict.items() if k != "family"):
        return "family"
    return "partial"


def _norm_name(s: Optional[str]) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def match_algorithms(gt: GroundTruth, detections: list, tolerance: int) -> tuple[list, list]:
    assets = gt.assets_of_type("algorithm")
    oid_index: dict[str, list] = {}
    for a in assets:
        oid = a.props.get("oid")
        if oid:
            oid_index.setdefault(str(oid), []).append(a)
    pairs: list[Pair] = []
    unmatched: list[Detection] = []
    for det in detections:
        cands: list[tuple[GTAsset, float, dict, bool]] = []
        oid_hits = oid_index.get(det.oid or "", [])
        for a in assets:
            score, verdict = slot_compare(det, a)
            is_oid = a in oid_hits
            if is_oid:
                # the OID identifies the asset even if the name parses differently
                score = max(score if score is not None else 0.0, 1.0)
                verdict = verdict or {"family": "match"}
                verdict = {**verdict, "oid": "match"}
            if score is None:
                # last resort: the plain name equals the ground-truth name or id
                if det.descriptor is None or det.descriptor.family is None:
                    if _norm_name(det.name) and _norm_name(det.name) in (_norm_name(a.name), _norm_name(a.id)):
                        score, verdict = 1.0, {"name": "match"}
                if score is None:
                    continue
            cands.append((a, score, verdict, is_oid))
        if not cands:
            unmatched.append(det)
            continue
        located = []
        if has_locations(det):
            for a, score, verdict, is_oid in cands:
                ov = overlap_count(det, a, tolerance)
                if ov > 0:
                    located.append((a, score, verdict, is_oid, ov))
        if located:
            for a, score, verdict, is_oid, ov in located:
                pairs.append(Pair(det, a, score, verdict, ov, True, _level(score, verdict, is_oid)))
            continue
        if has_locations(det) and is_lexical(det, gt):
            # located on a comment/string the corpus marks as a non-asset mention: a false positive
            unmatched.append(det)
            continue
        # no located match: single best candidate by identity, prefer explicit (non-implicit) assets
        ranked = sorted(cands, key=lambda c: (c[1], c[3], not c[0].implicit, -len(c[0].identity_slots)), reverse=True)
        best = ranked[0]
        ambiguous = len(ranked) > 1 and (ranked[1][1], ranked[1][3], not ranked[1][0].implicit) == \
            (best[1], best[3], not best[0].implicit)
        if best[1] <= 0.0:
            unmatched.append(det)
            continue
        pairs.append(Pair(det, best[0], best[1], best[2], 0, False, _level(best[1], best[2], best[3]), ambiguous))
    return pairs, unmatched


# ----------------------------------------------------------------------------- materials
def _material_descriptor(det: Detection):
    ref = det.attrs.get("algorithmRef")
    props = det.attrs.get("algorithmRefProps")
    if not ref and not props:
        return None
    from ..normalize.lexicon import descriptor_from_fields
    return descriptor_from_fields(ref, props or {})


def referenced_algorithm_score(desc, gt_asset: Optional[GTAsset]) -> tuple[Optional[float], str]:
    """Score a referenced algorithm descriptor against the ground-truth algorithm asset it should name."""
    if desc is None or gt_asset is None:
        return None, "missing"
    fc = family_compat(desc.family, gt_asset.family)
    if fc is None:
        return None, "conflict"
    slots = gt_asset.identity_slots
    score = fc
    for slot, expected in slots.items():
        if slot == "family":
            continue
        got = getattr(desc, slot)
        if got in (None, ""):
            continue
        if slot == "param":
            ok = param_equal(got, expected)
        elif slot == "padding":
            ok = padding_equal(got, expected)
        elif slot == "hash":
            ok = hash_equal(got, expected)
        else:
            ok = str(got).lower() == str(expected).lower()
        score += 1 if ok else -1
    return max(0.0, min(1.0, score / max(1, len(slots)))), ("match" if fc == 1.0 else "generic")


def material_compat(det: Detection, asset: GTAsset) -> Optional[float]:
    t = det.attrs.get("type")
    g = asset.subtype
    if t is None or t in ("unknown", "other"):
        return 0.25 if g else None
    if t == g:
        return 1.0
    if t == "key" and g in MATERIAL_KEY_TYPES:
        return 0.75
    if {t, g} <= {"nonce", "initialization-vector"}:
        return 0.75
    if {t, g} <= {"salt", "seed"} or {t, g} <= {"password", "credential"}:
        return 0.5
    return None


def match_materials(gt: GroundTruth, detections: list, tolerance: int) -> tuple[list, list]:
    assets = gt.assets_of_type("related-crypto-material")
    pairs: list[Pair] = []
    unmatched: list[Detection] = []
    for det in detections:
        ref_desc = _material_descriptor(det)
        cands = []
        for a in assets:
            tc = material_compat(det, a)
            if tc is None:
                continue
            verdict = {"type": "match" if tc == 1.0 else ("generic" if tc >= 0.5 else "missing")}
            score = tc
            n = 1
            if a.family:
                n += 1
                if ref_desc is None:
                    verdict["algorithm"] = "missing"
                else:
                    alg_score, alg_verdict = referenced_algorithm_score(ref_desc, gt.asset_by_id.get(a.algorithm_ref or ""))
                    if alg_score is None:
                        verdict["algorithm"] = "conflict"
                        score -= 1
                    else:
                        verdict["algorithm"] = alg_verdict
                        score += alg_score
            size = a.props.get("size")
            if size:
                n += 1
                got = det.attrs.get("size")
                if got is None:
                    verdict["size"] = "missing"
                elif int(got) == int(size) or int(got) * 8 == int(size):
                    verdict["size"] = "match"
                    score += 1
                else:
                    verdict["size"] = "conflict"
                    score -= 1
            cands.append((a, max(0.0, score / n), verdict))
        if not cands:
            unmatched.append(det)
            continue
        located = []
        if has_locations(det):
            for a, score, verdict in cands:
                ov = overlap_count(det, a, tolerance)
                if ov > 0:
                    located.append((a, score, verdict, ov))
        if located:
            # several candidates of the same type on the same lines: keep the best-scoring ones only
            top = max(l[1] for l in located)
            for a, score, verdict, ov in located:
                if score >= top - 1e-9:
                    pairs.append(Pair(det, a, score, verdict, ov, True,
                                      "exact" if score >= 0.999 else "partial"))
            continue
        ranked = sorted(cands, key=lambda c: c[1], reverse=True)
        best = ranked[0]
        if best[1] <= 0.0:
            unmatched.append(det)
            continue
        ambiguous = len(ranked) > 1 and abs(ranked[1][1] - best[1]) < 1e-9
        pairs.append(Pair(det, best[0], best[1], best[2], 0, False, "exact" if best[1] >= 0.999 else "partial", ambiguous))
    return pairs, unmatched


# ----------------------------------------------------------------------------- certificates / protocols
def match_simple(gt: GroundTruth, detections: list, asset_type: str, tolerance: int) -> tuple[list, list]:
    assets = gt.assets_of_type(asset_type)
    pairs: list[Pair] = []
    unmatched: list[Detection] = []
    for det in detections:
        cands = []
        for a in assets:
            if asset_type == "protocol":
                t = det.attrs.get("type")
                if t and a.subtype and t != a.subtype:
                    continue
                score = 1.0 if t else 0.5
                verdict = {"type": "match" if t else "missing"}
                v = det.attrs.get("version")
                gv = a.props.get("version")
                if gv:
                    if v is None:
                        verdict["version"] = "missing"
                        score = score / 2
                    elif _version_equal(v, gv):
                        verdict["version"] = "match"
                    else:
                        verdict["version"] = "conflict"
                        score = max(0.0, score - 0.5)
            else:
                score, verdict = 1.0, {"type": "match"}
            cands.append((a, score, verdict))
        if not cands:
            unmatched.append(det)
            continue
        located = [(a, s, v, overlap_count(det, a, tolerance)) for a, s, v in cands]
        located = [l for l in located if l[3] > 0] if has_locations(det) else []
        if located:
            for a, s, v, ov in located:
                pairs.append(Pair(det, a, s, v, ov, True, "exact" if s >= 0.999 else "partial"))
            continue
        a, s, v = max(cands, key=lambda c: c[1])
        pairs.append(Pair(det, a, s, v, 0, False, "exact" if s >= 0.999 else "partial", len(cands) > 1))
    return pairs, unmatched


def _version_equal(a: str, b: str) -> bool:
    ra = re.search(r"\d+(\.\d+)*", str(a))
    rb = re.search(r"\d+(\.\d+)*", str(b))
    if not ra or not rb:
        return str(a).strip().lower() == str(b).strip().lower()
    return ra.group(0) == rb.group(0)


# ----------------------------------------------------------------------------- libraries
def _lib_names(asset: GTAsset) -> set[str]:
    names = {_norm_name(asset.name), _norm_name(asset.id.split(".", 1)[-1])}
    pk = purl_key(asset.props.get("purl"))
    if pk:
        names.add(_norm_name(pk.split("/")[-1]))
        names.add(_norm_name(pk))
    # "cryptography (pyca)" -> cryptography
    names.add(_norm_name(re.sub(r"\(.*?\)", "", asset.name)))
    return {n for n in names if n}


def match_libraries(gt: GroundTruth, detections: list, tolerance: int) -> tuple[list, list]:
    assets = gt.assets_of_type("library")
    pairs: list[Pair] = []
    unmatched: list[Detection] = []
    for det in detections:
        pk = purl_key(det.attrs.get("purl"))
        dn = _norm_name(det.name)
        dgn = _norm_name(f"{det.attrs.get('group') or ''}/{det.name}") if det.attrs.get("group") else None
        best = None
        for a in assets:
            apk = purl_key(a.props.get("purl"))
            score = 0.0
            if pk and apk and pk == apk:
                score = 1.0
            elif pk and apk and pk.split("/")[-1] == apk.split("/")[-1]:
                score = 0.9
            elif dn and dn in _lib_names(a):
                score = 0.8
            elif dgn and dgn in _lib_names(a):
                score = 0.8
            if score and (best is None or score > best[1]):
                best = (a, score)
        if best is None:
            unmatched.append(det)
            continue
        pairs.append(Pair(det, best[0], best[1], {"purl": "match" if best[1] == 1.0 else "name"}, 0, False,
                          "exact" if best[1] >= 0.999 else "name"))
    return pairs, unmatched


# ----------------------------------------------------------------------------- driver
def match_case(gt: GroundTruth, detections: list, tolerance: int = 1) -> MatchResult:
    result = MatchResult()
    by_type: dict[str, list] = {}
    for d in detections:
        by_type.setdefault(d.asset_type, []).append(d)
    for asset_type, dets in by_type.items():
        if asset_type == "algorithm":
            pairs, un = match_algorithms(gt, dets, tolerance)
        elif asset_type == "related-crypto-material":
            pairs, un = match_materials(gt, dets, tolerance)
        elif asset_type in ("certificate", "protocol"):
            pairs, un = match_simple(gt, dets, asset_type, tolerance)
        elif asset_type == "library":
            pairs, un = match_libraries(gt, dets, tolerance)
        else:
            result.unscored.extend(dets)
            continue
        result.pairs.extend(pairs)
        result.unmatched.extend(un)
    return result
