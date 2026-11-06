"""IBM pre-standard CBOM (``bomFormat: CBOM``, ``specVersion: 1.4-cbom-1.0``) support.

cryptobom-forge emits this dialect.  Rather than maintaining a second reader, the document is
rewritten into the CycloneDX 1.6 vocabulary (key names and enumerations) and handed to
:func:`read_cyclonedx`.  The translation table mirrors the one in 2CBOM's ``ingest/ibmcbom.py``.
"""
from __future__ import annotations

import copy
import re
from typing import Any

from .cyclonedx import read_cyclonedx
from .model import NormalizedCBOM

_CAMEL_RE = re.compile(r"(?<=[a-z0-9])([A-Z])")


def _kebab(v: Any) -> Any:
    if not isinstance(v, str):
        return v
    return _CAMEL_RE.sub(r"-\1", v).lower()


def is_ibm_cbom(doc: dict) -> bool:
    if str(doc.get("bomFormat", "")).upper() == "CBOM":
        return True
    spec = str(doc.get("specVersion", ""))
    if "cbom" in spec.lower():
        return True
    for c in doc.get("components") or []:
        if isinstance(c, dict) and c.get("type") == "crypto-asset":
            return True
    return False


def _translate_component(c: dict) -> dict:
    out = copy.deepcopy(c)
    if out.get("type") == "crypto-asset":
        out["type"] = "cryptographic-asset"
    cp = out.get("cryptoProperties")
    if not isinstance(cp, dict):
        return out
    at = cp.get("assetType")
    if isinstance(at, str):
        cp["assetType"] = {"relatedCryptoMaterial": "related-crypto-material"}.get(at, _kebab(at))
    ap = cp.get("algorithmProperties")
    if isinstance(ap, dict):
        for k in ("primitive", "mode", "padding"):
            if isinstance(ap.get(k), str):
                ap[k] = _kebab(ap[k])
        if "implementationLevel" in ap and "executionEnvironment" not in ap:
            ap["executionEnvironment"] = _kebab(ap.pop("implementationLevel"))
        if isinstance(ap.get("cryptoFunctions"), list):
            ap["cryptoFunctions"] = [_kebab(f) if isinstance(f, str) else f for f in ap["cryptoFunctions"]]
        if "parameterSetIdentifier" not in ap and ap.get("variant"):
            # keep the variant; the lexicon extracts the parameter set from it when needed
            pass
    mp = cp.get("relatedCryptoMaterialProperties")
    if isinstance(mp, dict):
        if "relatedCryptoMaterialType" in mp and "type" not in mp:
            mp["type"] = _kebab(mp.pop("relatedCryptoMaterialType"))
        elif isinstance(mp.get("type"), str):
            mp["type"] = _kebab(mp["type"])
    cert = cp.get("certificateProperties")
    if isinstance(cert, dict):
        if "certificateSignatureAlgorithm" in cert and "signatureAlgorithmRef" not in cert:
            cert["signatureAlgorithmRef"] = cert.pop("certificateSignatureAlgorithm")
        if "certificateAlgorithm" in cert and "subjectPublicKeyRef" not in cert:
            cert["subjectPublicKeyRef"] = cert.pop("certificateAlgorithm")
    pp = cp.get("protocolProperties")
    if isinstance(pp, dict):
        if "tlsVersion" in pp:
            pp.setdefault("type", "tls")
            pp.setdefault("version", pp.pop("tlsVersion"))
        if isinstance(pp.get("type"), str):
            pp["type"] = _kebab(pp["type"])
    if isinstance(out.get("components"), list):
        out["components"] = [_translate_component(x) for x in out["components"] if isinstance(x, dict)]
    return out


def translate_ibm(doc: dict) -> dict:
    out = copy.deepcopy(doc)
    out["components"] = [_translate_component(c) for c in (doc.get("components") or []) if isinstance(c, dict)]
    return out


def read_ibm_cbom(doc: dict, path: str = "<memory>") -> NormalizedCBOM:
    norm = read_cyclonedx(translate_ibm(doc), path)
    norm.format = "ibm-cbom"
    norm.metadata.bom_format = doc.get("bomFormat")
    norm.metadata.spec_version = str(doc.get("specVersion") or "")
    return norm
