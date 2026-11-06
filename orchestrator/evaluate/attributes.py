"""Attribute-level comparison: did the tool report the attribute, and was it right?

Every attribute outcome carries ``expected`` (the ground-truth value), ``reported`` (what the tool
said, normalised) and ``correct`` in [0, 1].  Set-valued attributes (``cryptoFunctions``,
``cipherSuites``) score the Jaccard index so a tool that lists two of three functions gets partial
credit.  Attribute names follow CycloneDX 1.6 so that 2CBOM can look them up directly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

from ..baseline import GTAsset, GroundTruth, purl_key
from ..normalize.lexicon import (CURVE_ALIASES, descriptor_from_fields, normalize_curve, normalize_mode,
                                 normalize_padding, normalize_primitive, padding_equal, parse_name)
from ..normalize.model import Detection
from .matcher import Pair, _version_equal, family_compat

ALGORITHM_ATTRIBUTES = ("primitive", "parameterSetIdentifier", "mode", "padding", "curve", "cryptoFunctions", "oid",
                        "classicalSecurityLevel", "nistQuantumSecurityLevel")
MATERIAL_ATTRIBUTES = ("type", "size", "algorithmRef")
CERTIFICATE_ATTRIBUTES = ("subjectName", "issuerName", "signatureAlgorithmRef", "subjectPublicKeyRef", "certificateFormat",
                          "notValidBefore", "notValidAfter")
PROTOCOL_ATTRIBUTES = ("type", "version", "cipherSuites")
LIBRARY_ATTRIBUTES = ("purl", "version")

ATTRIBUTES_BY_TYPE = {
    "algorithm": ALGORITHM_ATTRIBUTES,
    "related-crypto-material": MATERIAL_ATTRIBUTES,
    "certificate": CERTIFICATE_ATTRIBUTES,
    "protocol": PROTOCOL_ATTRIBUTES,
    "library": LIBRARY_ATTRIBUTES,
}


@dataclass
class AttrOutcome:
    name: str
    expected: Any
    reported: Any
    correct: float          # 0..1 (fractional for set-valued attributes)

    @property
    def is_reported(self) -> bool:
        return self.reported not in (None, "", [], {})

    def to_dict(self) -> dict:
        return {"expected": self.expected, "reported": self.reported, "correct": round(self.correct, 4)}


def _jaccard(a: list, b: list) -> float:
    sa = {str(x).lower() for x in a}
    sb = {str(x).lower() for x in b}
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _suite_norm(s: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(s).upper())


def _dn_norm(s: Optional[str]) -> str:
    return re.sub(r"\s+", "", (s or "")).lower()


def _alg_ref_correct(reported: Optional[str], reported_props: Optional[dict], gt: GroundTruth,
                     gt_ref: Optional[str]) -> float:
    """How well a referenced algorithm (by name) matches the ground-truth algorithm asset ``gt_ref``."""
    if not reported or not gt_ref:
        return 0.0
    target = gt.asset_by_id.get(gt_ref)
    if target is None or target.descriptor is None:
        return 0.0
    d = descriptor_from_fields(reported, reported_props or {})
    fc = family_compat(d.family, target.family)
    if fc is None:
        return 0.0
    slots = target.identity_slots
    score = fc
    for slot, expected in slots.items():
        if slot == "family":
            continue
        got = getattr(d, slot)
        if got is None:
            continue
        if slot == "padding":
            ok = padding_equal(got, expected)
        else:
            ok = str(got).lower() == str(expected).lower()
        score += 1 if ok else -1
    return max(0.0, min(1.0, score / max(1, len(slots))))


def _param_correct(expected: str, reported: Optional[str]) -> float:
    if reported is None:
        return 0.0
    e, r = str(expected).strip().lower(), str(reported).strip().lower()
    if e == r:
        return 1.0
    ce, cr = normalize_curve(e), normalize_curve(r)
    size_to_curve = {"256": "p256", "384": "p384", "521": "p521", "224": "p224", "192": "p192"}
    if ce in CURVE_ALIASES.values():
        if cr == ce or size_to_curve.get(r) == ce:
            return 1.0
        if ce == "curve25519" and r in ("255", "256", "x25519"):
            return 1.0
        if ce == "edwards25519" and r in ("255", "256", "ed25519"):
            return 1.0
    # parameter strings naming a hash ("SHA-256" vs "sha256")
    de, dr = parse_name(e), parse_name(r)
    if de.family and de.family == dr.family and (de.param or "") == (dr.param or ""):
        return 1.0
    norm = lambda s: re.sub(r"[^a-z0-9=,./]", "", s)  # noqa: E731
    return 1.0 if norm(e) == norm(r) else 0.0


def compare_algorithm(gt: GroundTruth, asset: GTAsset, det: Detection, pair: Pair) -> dict:
    p = asset.props
    out: dict[str, AttrOutcome] = {}
    attrs = det.attrs
    if p.get("primitive"):
        got = normalize_primitive(attrs.get("primitive"))
        out["primitive"] = AttrOutcome("primitive", p["primitive"], got, 1.0 if got == p["primitive"] else 0.0)
    desc = det.descriptor
    # a value encoded in the name ("AES-256-GCM") counts as reported: 2CBOM derives the same slots from the name
    if p.get("parameterSetIdentifier"):
        got = attrs.get("parameterSetIdentifier") or (desc.param if desc else None)
        if got is None and desc and desc.curve and "curve-from-size" not in desc.notes and \
                normalize_curve(str(p["parameterSetIdentifier"]).lower()) in CURVE_ALIASES.values():
            got = desc.curve
        out["parameterSetIdentifier"] = AttrOutcome("parameterSetIdentifier", p["parameterSetIdentifier"], got,
                                                    _param_correct(p["parameterSetIdentifier"], got))
    if p.get("mode"):
        got = normalize_mode(attrs.get("mode")) or (desc.mode if desc else None)
        exp = normalize_mode(p["mode"]) or p["mode"]
        out["mode"] = AttrOutcome("mode", p["mode"], got, 1.0 if got == exp else 0.0)
    if p.get("padding"):
        got = normalize_padding(attrs.get("padding")) or (desc.padding if desc else None)
        exp = normalize_padding(p["padding"]) or p["padding"]
        # ground truth uses "other" for PSS; accept the precise name from the tool
        if exp == "other" and asset.descriptor and asset.descriptor.padding:
            exp = asset.descriptor.padding
        out["padding"] = AttrOutcome("padding", p["padding"], got, 1.0 if got and padding_equal(got, exp) else 0.0)
    if p.get("curve"):
        got = normalize_curve(attrs.get("curve"))
        exp = normalize_curve(p["curve"])
        if got is None and desc and desc.curve and "curve-from-size" not in desc.notes:
            got = desc.curve
        out["curve"] = AttrOutcome("curve", p["curve"], got, 1.0 if got == exp else 0.0)
    if asset.functions:
        got = attrs.get("cryptoFunctions") or []
        out["cryptoFunctions"] = AttrOutcome("cryptoFunctions", asset.functions, got or None, _jaccard(asset.functions, got))
    if p.get("oid"):
        got = attrs.get("oid")
        out["oid"] = AttrOutcome("oid", p["oid"], got, 1.0 if got == p["oid"] else 0.0)
    for level in ("classicalSecurityLevel", "nistQuantumSecurityLevel"):
        if p.get(level) is not None:
            got = attrs.get(level)
            out[level] = AttrOutcome(level, p[level], got, 1.0 if got is not None and int(got) == int(p[level]) else 0.0)
    return out


def compare_material(gt: GroundTruth, asset: GTAsset, det: Detection, pair: Pair) -> dict:
    p = asset.props
    attrs = det.attrs
    out: dict[str, AttrOutcome] = {}
    if asset.subtype:
        got = attrs.get("type")
        out["type"] = AttrOutcome("type", asset.subtype, got, 1.0 if got == asset.subtype else (0.5 if pair.slots.get("type") == "generic" else 0.0))
    if p.get("size"):
        got = attrs.get("size")
        ok = got is not None and (int(got) == int(p["size"]) or int(got) * 8 == int(p["size"]))
        out["size"] = AttrOutcome("size", p["size"], got, 1.0 if ok else 0.0)
    if asset.algorithm_ref:
        got = attrs.get("algorithmRef")
        out["algorithmRef"] = AttrOutcome("algorithmRef", asset.algorithm_ref, got,
                                          _alg_ref_correct(got, attrs.get("algorithmRefProps"), gt, asset.algorithm_ref))
    return out


def compare_certificate(gt: GroundTruth, asset: GTAsset, det: Detection, pair: Pair) -> dict:
    p = asset.props
    attrs = det.attrs
    out: dict[str, AttrOutcome] = {}
    for name in ("subjectName", "issuerName"):
        if p.get(name) and not str(p[name]).startswith("runtime:"):
            got = attrs.get(name)
            out[name] = AttrOutcome(name, p[name], got, 1.0 if _dn_norm(got) == _dn_norm(p[name]) else 0.0)
    for name in ("notValidBefore", "notValidAfter"):
        if p.get(name) and not str(p[name]).startswith("runtime:"):
            got = attrs.get(name)
            out[name] = AttrOutcome(name, p[name], got, 1.0 if got and str(got).strip() == str(p[name]).strip() else 0.0)
    if p.get("signatureAlgorithmRef"):
        got = attrs.get("signatureAlgorithmRef")
        out["signatureAlgorithmRef"] = AttrOutcome("signatureAlgorithmRef", p["signatureAlgorithmRef"], got,
                                                   _alg_ref_correct(got, None, gt, p["signatureAlgorithmRef"]))
    if p.get("subjectPublicKeyRef"):
        got = attrs.get("subjectPublicKeyRef")
        key = gt.asset_by_id.get(p["subjectPublicKeyRef"])
        target = key.algorithm_ref if key else None
        corr = 0.0
        if got and target:
            d = descriptor_from_fields(got, {})
            tgt = gt.asset_by_id.get(target)
            fc = family_compat(d.family, tgt.family) if tgt else None
            corr = fc or 0.0
            if fc and tgt and tgt.descriptor and tgt.descriptor.curve and d.curve:
                corr = 1.0 if d.curve == tgt.descriptor.curve else 0.5
        out["subjectPublicKeyRef"] = AttrOutcome("subjectPublicKeyRef", p["subjectPublicKeyRef"], got, corr)
    if p.get("certificateFormat"):
        got = attrs.get("certificateFormat")
        out["certificateFormat"] = AttrOutcome("certificateFormat", p["certificateFormat"], got,
                                               1.0 if got and got.replace(" ", "").lower() == str(p["certificateFormat"]).replace(" ", "").lower() else 0.0)
    return out


def compare_protocol(gt: GroundTruth, asset: GTAsset, det: Detection, pair: Pair) -> dict:
    p = asset.props
    attrs = det.attrs
    out: dict[str, AttrOutcome] = {}
    if p.get("type"):
        got = attrs.get("type")
        out["type"] = AttrOutcome("type", p["type"], got, 1.0 if got == str(p["type"]).lower() else 0.0)
    if p.get("version"):
        got = attrs.get("version")
        out["version"] = AttrOutcome("version", p["version"], got, 1.0 if got and _version_equal(got, p["version"]) else 0.0)
    suites = [cs.get("name") for cs in (p.get("cipherSuites") or []) if isinstance(cs, dict) and cs.get("name")]
    if suites:
        got = attrs.get("cipherSuites") or []
        out["cipherSuites"] = AttrOutcome("cipherSuites", suites, got or None,
                                          _jaccard([_suite_norm(s) for s in suites], [_suite_norm(s) for s in got]))
    return out


def compare_library(gt: GroundTruth, asset: GTAsset, det: Detection, pair: Pair) -> dict:
    p = asset.props
    attrs = det.attrs
    out: dict[str, AttrOutcome] = {}
    if p.get("purl"):
        got = attrs.get("purl")
        out["purl"] = AttrOutcome("purl", p["purl"], got, 1.0 if got and purl_key(got) == purl_key(p["purl"]) else 0.0)
    if p.get("version"):
        got = attrs.get("version")
        out["version"] = AttrOutcome("version", p["version"], got, 1.0 if got and str(got).strip() == str(p["version"]).strip() else 0.0)
    return out


def compare(gt: GroundTruth, asset: GTAsset, det: Detection, pair: Pair) -> dict:
    fn = {"algorithm": compare_algorithm, "related-crypto-material": compare_material, "certificate": compare_certificate,
          "protocol": compare_protocol, "library": compare_library}.get(asset.asset_type)
    outcomes = fn(gt, asset, det, pair) if fn else {}
    # the identity pseudo-attribute lets 2CBOM ask "whose *identity* claim do I trust"
    ident = AttrOutcome("identity", asset.descriptor.canonical() if asset.descriptor else asset.name,
                        det.descriptor.canonical() if det.descriptor else det.name, pair.identity_score)
    outcomes["identity"] = ident
    return outcomes
