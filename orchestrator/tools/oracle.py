"""An adapter that replays the corpus' own reference CBOM, optionally degraded.

It exists to exercise the whole pipeline (run -> normalise -> match -> score -> export -> reconcile)
without Docker, CodeQL or network access, and to produce *known* imperfections so the scoring model
can be checked: a tool that drops every ``parameterSetIdentifier`` must score 0 on that attribute's
completeness and nothing else.

Spec options::

    options:
      degrade:
        seed: 1
        drop_assets: 0.25            # fraction of assets omitted (recall loss)
        drop_asset_types: [protocol] # whole asset types omitted
        drop_attributes: [parameterSetIdentifier, oid]
        wrong_attributes: {mode: 0.5}   # fraction of values replaced by a wrong one (correctness loss)
        drop_locations: 0.5          # fraction of occurrences removed (locality loss)
        family_only: 0.3             # fraction of algorithms renamed to their bare family ("AES")
        false_positives: 3           # synthetic unmatched assets added per case
        lexical_false_positives: 2   # false positives placed on non-asset mention lines
        strip_tool_metadata: false
"""
from __future__ import annotations

import copy
import json
import random
import shutil
from pathlib import Path
from typing import Optional

from ..baseline import Case
from ..github import now_iso
from ..normalize.lexicon import parse_name
from .base import ToolAdapter, ToolRunResult, ToolVersion

WRONG_VALUES = {
    "mode": ["cbc", "ecb", "gcm", "ctr"],
    "padding": ["pkcs7", "oaep", "pkcs1v15", "pss"],
    "primitive": ["hash", "block-cipher", "signature", "kdf"],
    "parameterSetIdentifier": ["128", "192", "2048", "4096"],
    "curve": ["secp384r1", "secp521r1", "curve25519"],
    "classicalSecurityLevel": [80, 112, 256],
    "nistQuantumSecurityLevel": [0, 1, 5],
    "oid": ["1.2.3.4.5"],
    "size": [64, 1024, 4096],
    "type": ["secret-key", "nonce", "salt"],
    "version": ["1.2", "1.1"],
}


class OracleAdapter(ToolAdapter):
    def __init__(self, spec, config, docker=None):
        super().__init__(spec, config, docker)
        self.launcher = "local"
        self.degrade: dict = dict((spec.options or {}).get("degrade") or {})

    def resolve(self, pin: Optional[str] = None) -> ToolVersion:
        label = pin or ("degraded" if self.degrade else "reference")
        return ToolVersion.fixed(self.spec.id, self.spec.name, label, launcher="local", source="corpus",
                                 notes=["replays the ground-truth CBOM of each case"] +
                                       ([f"degradation: {json.dumps(self.degrade, sort_keys=True)}"] if self.degrade else []))

    def install(self, version: ToolVersion, log_path: Optional[Path] = None) -> None:
        return None

    def run(self, case: Case, workdir: Path, version: ToolVersion, out_dir: Path, log_path: Path) -> ToolRunResult:
        if not self.supports(case):
            return ToolRunResult("unsupported", notes=[f"no language entry for {case.language}"])
        if case.reference_cbom is None or not case.reference_cbom.exists():
            return ToolRunResult("failed", notes=["case has no reference cbom.cdx.json"])
        with open(case.reference_cbom, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        if self.degrade:
            doc = self._degrade(doc, case)
        doc["metadata"] = doc.get("metadata") or {}
        if not self.degrade.get("strip_tool_metadata"):
            doc["metadata"]["tools"] = {"components": [{"type": "application", "name": self.spec.name,
                                                         "version": version.version}]}
        doc["metadata"]["timestamp"] = now_iso()
        out_dir.mkdir(parents=True, exist_ok=True)
        dest = out_dir / "cbom.json"
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(f"oracle: copied {case.reference_cbom} -> {dest} (degrade={json.dumps(self.degrade)})\n")
        return ToolRunResult("ok" if doc.get("components") else "empty", dest, 0, 0.0, log_path, ["oracle", case.id])

    # ------------------------------------------------------------------ degradation
    def _degrade(self, doc: dict, case: Case) -> dict:
        d = self.degrade
        rng = random.Random(f"{d.get('seed', 1)}:{case.id}")
        doc = copy.deepcopy(doc)
        comps = doc.get("components") or []
        drop_types = set(d.get("drop_asset_types") or [])
        kept = []
        for c in comps:
            cp = c.get("cryptoProperties") or {}
            atype = cp.get("assetType") or ("library" if c.get("type") == "library" else None)
            if atype in drop_types:
                continue
            if d.get("drop_assets") and rng.random() < float(d["drop_assets"]):
                continue
            kept.append(c)
        drop_attrs = set(d.get("drop_attributes") or [])
        wrong = d.get("wrong_attributes") or {}
        for c in kept:
            cp = c.get("cryptoProperties")
            if not isinstance(cp, dict):
                continue
            holders = [cp.get("algorithmProperties"), cp.get("relatedCryptoMaterialProperties"),
                       cp.get("certificateProperties"), cp.get("protocolProperties")]
            for holder in holders:
                if not isinstance(holder, dict):
                    continue
                for name in list(holder):
                    if name in drop_attrs:
                        holder.pop(name)
                    elif name in wrong and rng.random() < float(wrong[name]):
                        options = [v for v in WRONG_VALUES.get(name, ["wrong"]) if v != holder[name]]
                        holder[name] = rng.choice(options) if options else "wrong"
            if "oid" in drop_attrs:
                cp.pop("oid", None)
            elif "oid" in wrong and cp.get("oid") and rng.random() < float(wrong["oid"]):
                cp["oid"] = "1.2.3.4.5"
            if d.get("family_only") and cp.get("assetType") == "algorithm" and rng.random() < float(d["family_only"]):
                fam = parse_name(c.get("name")).family
                if fam:
                    c["name"] = fam.upper()
                    ap = cp.get("algorithmProperties") or {}
                    for k in ("parameterSetIdentifier", "mode", "padding", "curve"):
                        ap.pop(k, None)
                    cp.pop("oid", None)
            if d.get("drop_locations"):
                ev = c.get("evidence") or {}
                occ = ev.get("occurrences") or []
                ev["occurrences"] = [o for o in occ if rng.random() >= float(d["drop_locations"])]
        doc["components"] = kept
        # synthetic false positives
        n_fp = int(d.get("false_positives") or 0)
        n_lex = int(d.get("lexical_false_positives") or 0)
        mention_lines = []
        if n_lex and case.ground_truth.exists():
            with open(case.ground_truth, "r", encoding="utf-8") as fh:
                gt = json.load(fh)
            mention_lines = [(m["line"], m["text"]) for m in gt.get("nonAssetMentions") or [] if m.get("line")]
        for i in range(n_fp):
            kept.append({"type": "cryptographic-asset", "bom-ref": f"oracle-fp-{i}", "name": rng.choice(["Camellia-256", "RC4", "SEED", "DES"]),
                         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "block-cipher"}},
                         "evidence": {"occurrences": [{"location": case.source_file or "x", "line": 1}]}})
        for i in range(min(n_lex, len(mention_lines))):
            line, text = rng.choice(mention_lines)
            kept.append({"type": "cryptographic-asset", "bom-ref": f"oracle-lexfp-{i}", "name": text,
                         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {}},
                         "evidence": {"occurrences": [{"location": case.source_file or "x", "line": line}]}})
        doc["components"] = kept
        return doc
