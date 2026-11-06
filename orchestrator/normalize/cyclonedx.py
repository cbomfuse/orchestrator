"""Lift CycloneDX 1.5/1.6/1.7 documents (``cryptographic-asset`` components) to the detection model."""
from __future__ import annotations

import re
from typing import Any, Optional

from .lexicon import (descriptor_from_fields, normalize_curve, normalize_functions, normalize_material_type,
                      normalize_mode, normalize_padding, normalize_primitive)
from .model import Detection, NormalizedCBOM, Occurrence, ToolMetadata

_OID_RE = re.compile(r"^\d+(\.\d+)+$")


def _to_int(v: Any) -> Optional[int]:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return None


def _str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def extract_tools(metadata: dict) -> ToolMetadata:
    meta = ToolMetadata(bom_format=None, spec_version=None, timestamp=_str((metadata or {}).get("timestamp")))
    tools = (metadata or {}).get("tools")
    found: list[dict] = []
    if isinstance(tools, dict):
        for c in tools.get("components") or []:
            if isinstance(c, dict):
                name = c.get("name") or "unknown"
                group = c.get("group")
                if group and group not in name:
                    name = f"{group}/{name}"
                found.append({"name": name, "version": _str(c.get("version")) or "", "purl": c.get("purl")})
        for s in tools.get("services") or []:
            if isinstance(s, dict):
                found.append({"name": s.get("name") or "unknown", "version": _str(s.get("version")) or ""})
    elif isinstance(tools, list):
        for t in tools:
            if isinstance(t, dict):
                name = t.get("name") or "unknown"
                vendor = t.get("vendor")
                if vendor and vendor.lower() not in name.lower():
                    name = f"{vendor} {name}"
                found.append({"name": name, "version": _str(t.get("version")) or ""})
    meta.tools = found
    if found:
        meta.tool_name, meta.tool_version = found[0]["name"], found[0]["version"] or None
    return meta


def _occurrences(component: dict) -> list[Occurrence]:
    out: list[Occurrence] = []
    ev = component.get("evidence") or {}
    for occ in ev.get("occurrences") or []:
        if not isinstance(occ, dict):
            continue
        line = _to_int(occ.get("line"))
        out.append(Occurrence(file=_str(occ.get("location")), line=line, end_line=None,
                              offset=_to_int(occ.get("offset")), symbol=_str(occ.get("symbol")),
                              context=_str(occ.get("additionalContext"))))
    # IBM-style detectionContext inside a CycloneDX document (emitted by some early tools)
    cp = component.get("cryptoProperties") or {}
    for dc in cp.get("detectionContext") or []:
        if not isinstance(dc, dict):
            continue
        lines = [n for n in (_to_int(x) for x in (dc.get("lineNumbers") or [])) if n is not None]
        offsets = [n for n in (_to_int(x) for x in (dc.get("offsets") or [])) if n is not None]
        out.append(Occurrence(file=_str(dc.get("filePath")), line=min(lines) if lines else None,
                              end_line=max(lines) if lines else None, offset=offsets[0] if offsets else None,
                              symbol=", ".join(dc.get("keywords") or []) or None,
                              context=_str(dc.get("additionalContext"))))
    return out


def _props_list(component: dict) -> dict:
    out = {}
    for p in component.get("properties") or []:
        if isinstance(p, dict) and p.get("name"):
            out[str(p["name"])] = p.get("value")
    return out


def _walk(components: list, depth: int = 0):
    for c in components or []:
        if not isinstance(c, dict):
            continue
        yield c, depth
        yield from _walk(c.get("components") or [], depth + 1)


class _RefIndex:
    """bom-ref -> component, so that algorithmRef / signatureAlgorithmRef can be resolved to names."""

    def __init__(self, doc: dict):
        self.by_ref: dict[str, dict] = {}
        root = (doc.get("metadata") or {}).get("component")
        if isinstance(root, dict) and root.get("bom-ref"):
            self.by_ref[root["bom-ref"]] = root
        for c, _ in _walk(doc.get("components") or []):
            ref = c.get("bom-ref")
            if ref:
                self.by_ref[str(ref)] = c

    def name(self, ref: Any) -> Optional[str]:
        if ref is None:
            return None
        ref = str(ref)
        c = self.by_ref.get(ref)
        if c is None:
            # the reference itself may carry the algorithm name (e.g. "crypto/algorithm/sha-256")
            tail = ref.rsplit("/", 1)[-1].split("@", 1)[0]
            return tail or ref
        return c.get("name") or ref

    def algorithm_props(self, ref: Any) -> Optional[dict]:
        c = self.by_ref.get(str(ref)) if ref is not None else None
        if c is None:
            return None
        return ((c.get("cryptoProperties") or {}).get("algorithmProperties")) or None


def _algorithm_attrs(cp: dict, name: str) -> tuple[dict, Any]:
    ap = cp.get("algorithmProperties") or {}
    attrs = {
        "primitive": normalize_primitive(ap.get("primitive")),
        "parameterSetIdentifier": _str(ap.get("parameterSetIdentifier")),
        "mode": normalize_mode(ap.get("mode")),
        "padding": normalize_padding(ap.get("padding")),
        "curve": normalize_curve(ap.get("curve")),
        "cryptoFunctions": normalize_functions(ap.get("cryptoFunctions")) or None,
        "classicalSecurityLevel": _to_int(ap.get("classicalSecurityLevel")),
        "nistQuantumSecurityLevel": _to_int(ap.get("nistQuantumSecurityLevel")),
        "executionEnvironment": _str(ap.get("executionEnvironment") or ap.get("implementationLevel")),
        "implementationPlatform": _str(ap.get("implementationPlatform")),
        "certificationLevel": sorted(str(x) for x in (ap.get("certificationLevel") or []) if x) or None,
    }
    if ap.get("variant"):
        attrs["variant"] = _str(ap.get("variant"))
    oid = _str(cp.get("oid"))
    attrs["oid"] = oid if oid and _OID_RE.match(oid) else None
    desc = descriptor_from_fields(name, {**ap, "curve": attrs["curve"], "mode": attrs["mode"],
                                         "padding": attrs["padding"], "primitive": attrs["primitive"]})
    return attrs, desc


def _material_attrs(cp: dict, idx: _RefIndex) -> dict:
    mp = cp.get("relatedCryptoMaterialProperties") or {}
    ref = mp.get("algorithmRef")
    return {
        "type": normalize_material_type(mp.get("type")),
        "size": _to_int(mp.get("size")),
        "algorithmRef": idx.name(ref),
        "algorithmRefProps": idx.algorithm_props(ref),
        "format": _str(mp.get("format")),
        "state": _str(mp.get("state")),
        "id": _str(mp.get("id")),
        "value": _str(mp.get("value")),
    }


def _certificate_attrs(cp: dict, idx: _RefIndex) -> dict:
    cpp = cp.get("certificateProperties") or {}
    sig = cpp.get("signatureAlgorithmRef")
    key = cpp.get("subjectPublicKeyRef")
    return {
        "subjectName": _str(cpp.get("subjectName")),
        "issuerName": _str(cpp.get("issuerName")),
        "notValidBefore": _str(cpp.get("notValidBefore")),
        "notValidAfter": _str(cpp.get("notValidAfter")),
        "signatureAlgorithmRef": idx.name(sig) if sig else _str(cpp.get("signatureAlgorithm")),
        "subjectPublicKeyRef": idx.name(key) if key else _str(cpp.get("subjectPublicKeyAlgorithm")),
        "certificateFormat": _str(cpp.get("certificateFormat")),
        "certificateExtension": _str(cpp.get("certificateExtension") or cpp.get("certificateFileExtension")),
    }


def _protocol_attrs(cp: dict, idx: _RefIndex) -> dict:
    pp = cp.get("protocolProperties") or {}
    suites = []
    suite_algs = []
    for cs in pp.get("cipherSuites") or []:
        if not isinstance(cs, dict):
            continue
        if cs.get("name"):
            suites.append(str(cs["name"]))
        for a in cs.get("algorithms") or []:
            n = idx.name(a)
            if n:
                suite_algs.append(n)
    return {
        "type": _str(pp.get("type")).lower() if pp.get("type") else None,
        "version": _str(pp.get("version")),
        "cipherSuites": sorted(set(suites)) or None,
        "cipherSuiteAlgorithms": sorted(set(suite_algs)) or None,
    }


def read_cyclonedx(doc: dict, path: str = "<memory>") -> NormalizedCBOM:
    meta = extract_tools(doc.get("metadata") or {})
    meta.bom_format = doc.get("bomFormat")
    meta.spec_version = _str(doc.get("specVersion"))
    idx = _RefIndex(doc)
    detections: list[Detection] = []
    warnings: list[str] = []
    root_ref = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    for comp, depth in _walk(doc.get("components") or []):
        ctype = str(comp.get("type") or "").lower()
        ref = str(comp.get("bom-ref") or f"anon-{len(detections)}")
        name = _str(comp.get("name")) or ""
        cp = comp.get("cryptoProperties")
        if ctype in ("cryptographic-asset", "crypto-asset") or isinstance(cp, dict):
            cp = cp or {}
            asset_type = str(cp.get("assetType") or "").lower().replace("_", "-")
            asset_type = {"relatedcryptomaterial": "related-crypto-material", "related_crypto_material":
                          "related-crypto-material", "crypto-material": "related-crypto-material"}.get(asset_type, asset_type)
            if asset_type not in ("algorithm", "related-crypto-material", "certificate", "protocol"):
                if "algorithmProperties" in cp:
                    asset_type = "algorithm"
                elif "relatedCryptoMaterialProperties" in cp:
                    asset_type = "related-crypto-material"
                elif "certificateProperties" in cp:
                    asset_type = "certificate"
                elif "protocolProperties" in cp:
                    asset_type = "protocol"
                else:
                    warnings.append(f"{ref}: unknown assetType {asset_type!r}")
                    asset_type = "unknown"
            desc = None
            if asset_type == "algorithm":
                attrs, desc = _algorithm_attrs(cp, name)
            elif asset_type == "related-crypto-material":
                attrs = _material_attrs(cp, idx)
            elif asset_type == "certificate":
                attrs = _certificate_attrs(cp, idx)
            elif asset_type == "protocol":
                attrs = _protocol_attrs(cp, idx)
            else:
                attrs = {}
            conf = cp.get("confidenceLevel")
            det = Detection(ref=ref, asset_type=asset_type, name=name, attrs=attrs,
                            oid=attrs.get("oid") if asset_type == "algorithm" else _str(cp.get("oid")),
                            occurrences=_occurrences(comp), confidence=float(conf) if conf is not None else None,
                            descriptor=desc, extra={"properties": _props_list(comp), "depth": depth})
            detections.append(det)
        elif ctype in ("library", "framework", "application", "container", "operating-system", "platform"):
            if ref == root_ref:
                continue
            detections.append(Detection(ref=ref, asset_type="library", name=name, attrs={
                "purl": _str(comp.get("purl")), "name": name, "version": _str(comp.get("version")),
                "group": _str(comp.get("group")), "componentType": ctype,
            }, occurrences=_occurrences(comp), extra={"depth": depth}))
    return NormalizedCBOM(path=path, format="cyclonedx", metadata=meta, detections=detections, warnings=warnings)
