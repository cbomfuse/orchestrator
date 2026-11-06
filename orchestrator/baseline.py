"""The ground-truth corpus: checkout, case discovery and the typed ground-truth model.

A *case* is any top-level directory of the corpus that contains a ``ground-truth.json`` (and
usually a reference ``cbom.cdx.json``).  Cases are discovered at run time, so adding or removing a
language directory in ``cbomfuse/baseline`` is picked up automatically; nothing here hard-codes the
five current languages.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import Config
from .normalize.lexicon import (Descriptor, HASH_FAMILIES, PQC_FAMILIES, descriptor_from_fields, normalize_family,
                                normalize_functions, normalize_material_type)
from .process import run_command

log = logging.getLogger("orchestrator.baseline")


# ----------------------------------------------------------------------------- checkout
@dataclass
class BaselineCheckout:
    path: Path
    repo: str
    ref: str
    commit: Optional[str]
    describe: Optional[str]
    synced: bool
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"repo": self.repo, "ref": self.ref, "commit": self.commit, "describe": self.describe,
                "path": str(self.path), "synced": self.synced, "notes": self.notes}


def _git(path: Path, *args: str, timeout: float = 600):
    return run_command(["git", "-C", str(path), *args], timeout=timeout)


def _head_info(path: Path) -> tuple[Optional[str], Optional[str]]:
    if not (path / ".git").exists() and not (path / "HEAD").exists():
        return None, None
    rev = _git(path, "rev-parse", "HEAD")
    desc = _git(path, "describe", "--tags", "--always", "--dirty")
    return (rev.stdout.strip() or None) if rev.ok else None, (desc.stdout.strip() or None) if desc.ok else None


def sync_baseline(config: Config, offline: bool = False) -> BaselineCheckout:
    repo = str(config.get("baseline", "repo"))
    ref = str(config.get("baseline", "ref") or "main")
    local_source = Path(repo).expanduser()
    if local_source.is_dir() and not repo.startswith(("http://", "https://", "git@", "ssh://")):
        commit, desc = _head_info(local_source)
        return BaselineCheckout(local_source.resolve(), repo, ref, commit, desc, False, ["local directory, not synced"])

    path = config.path("baseline", "path")
    notes: list[str] = []
    synced = False
    if offline:
        if not path.exists():
            raise RuntimeError(f"baseline checkout {path} does not exist and offline mode was requested")
        notes.append("offline: using existing checkout")
    else:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            res = run_command(["git", "clone", "--quiet", repo, str(path)], timeout=900)
            if not res.ok:
                raise RuntimeError(f"git clone {repo} failed: {res.stderr.strip()[-400:]}")
            synced = True
        else:
            res = _git(path, "fetch", "--quiet", "--all", "--tags", "--prune")
            if not res.ok:
                notes.append(f"fetch failed, using existing checkout: {res.stderr.strip()[-200:]}")
            else:
                synced = True
        if synced:
            co = _git(path, "checkout", "--quiet", ref)
            if not co.ok:
                co = _git(path, "checkout", "--quiet", f"origin/{ref}")
            if not co.ok:
                raise RuntimeError(f"git checkout {ref} failed in {path}: {co.stderr.strip()[-300:]}")
            # fast-forward when ref is a branch
            branch = _git(path, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
            if branch and branch != "HEAD":
                up = _git(path, "reset", "--quiet", "--hard", f"origin/{branch}")
                if not up.ok:
                    notes.append(f"could not fast-forward {branch}: {up.stderr.strip()[-200:]}")
    commit, desc = _head_info(path)
    return BaselineCheckout(path.resolve(), repo, ref, commit, desc, synced, notes)


# ----------------------------------------------------------------------------- cases
@dataclass
class Case:
    id: str
    language: str
    dir: Path
    ground_truth: Path
    reference_cbom: Optional[Path]
    source_file: Optional[str]

    def to_dict(self) -> dict:
        return {"id": self.id, "language": self.language, "dir": str(self.dir), "groundTruth": str(self.ground_truth),
                "referenceCbom": str(self.reference_cbom) if self.reference_cbom else None, "sourceFile": self.source_file}


def discover_cases(root: Path, config: Optional[Config] = None) -> list[Case]:
    cfg = config or Config.defaults()
    gt_name = cfg.get("baseline", "ground_truth_file", default="ground-truth.json")
    cbom_name = cfg.get("baseline", "reference_cbom_file", default="cbom.cdx.json")
    excluded = set(cfg.get("baseline", "exclude_dirs", default=["_tooling"]) or [])
    include = set(cfg.get("baseline", "include_cases", default=[]) or [])
    exclude = set(cfg.get("baseline", "exclude_cases", default=[]) or [])
    cases: list[Case] = []
    for d in sorted(p for p in Path(root).iterdir() if p.is_dir()):
        if d.name.startswith(".") or d.name in excluded:
            continue
        gt = d / gt_name
        if not gt.is_file():
            continue
        try:
            with open(gt, "r", encoding="utf-8") as fh:
                head = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("skipping %s: unreadable ground truth (%s)", d, exc)
            continue
        language = str(head.get("language") or d.name)
        cid = d.name
        if include and cid not in include and language not in include:
            continue
        if cid in exclude or language in exclude:
            continue
        cbom = d / cbom_name
        cases.append(Case(cid, language, d.resolve(), gt.resolve(), cbom.resolve() if cbom.is_file() else None,
                          head.get("file")))
    return cases


# ----------------------------------------------------------------------------- ground truth model
@dataclass
class GTOccurrence:
    id: str
    file: Optional[str]
    line: Optional[int]
    end_line: Optional[int]
    column: Optional[int]
    role: str
    kind: str
    relation: str
    scenario: Optional[str]
    scope: Optional[str]
    library: Optional[str]
    symbol: Optional[str]
    evidence: Optional[str]


@dataclass
class GTAsset:
    id: str
    asset_type: str
    name: str
    bom_ref: Optional[str]
    implicit: bool
    functions: list
    props: dict
    occurrences: list
    family: Optional[str]
    subtype: Optional[str]
    descriptor: Optional[Descriptor]
    scenarios: list
    libraries: list
    pqc: bool
    algorithm_ref: Optional[str] = None     # for materials / certificates: the GT algorithm asset id

    @property
    def identity_slots(self) -> dict:
        """The descriptor slots that discriminate this asset from its siblings (None values dropped)."""
        if not self.descriptor:
            return {}
        d = self.descriptor
        slots = {"family": d.family}
        if d.param:
            slots["param"] = d.param
        if d.mode and d.mode != "other":
            slots["mode"] = d.mode
        if d.padding and d.padding != "other":
            slots["padding"] = d.padding
        if d.curve:
            slots["curve"] = d.curve
        if d.hash:
            slots["hash"] = d.hash
        return slots

    def locations(self) -> list[tuple[str, int, int]]:
        out = []
        for o in self.occurrences:
            if o.file and o.line:
                out.append((o.file, o.line, o.end_line or o.line))
        return out

    def to_dict(self) -> dict:
        return {"id": self.id, "assetType": self.asset_type, "name": self.name, "implicit": self.implicit,
                "family": self.family, "subtype": self.subtype, "scenarios": self.scenarios,
                "libraries": self.libraries, "pqc": self.pqc, "occurrences": len(self.occurrences),
                "descriptor": self.descriptor.to_dict() if self.descriptor else None}


@dataclass
class GTLibrary:
    id: str
    name: str
    version: Optional[str]
    purl: Optional[str]
    scope: Optional[str]

    @property
    def purl_key(self) -> Optional[str]:
        return purl_key(self.purl)


@dataclass
class NonAssetMention:
    id: str
    line: int
    text: str
    context: str
    reason: str


def purl_key(purl: Optional[str]) -> Optional[str]:
    """``pkg:pypi/cryptography@50.0.2`` -> ``pypi/cryptography`` (type + namespace/name, no version)."""
    if not purl:
        return None
    s = purl.strip()
    s = s[4:] if s.startswith("pkg:") else s
    s = s.split("?", 1)[0].split("#", 1)[0]
    name_part = s.rsplit("@", 1)[0] if "@" in s.rsplit("/", 1)[-1] else s
    return name_part.lower()


def _opt_int(v) -> Optional[int]:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


class GroundTruth:
    """Typed view over one ``ground-truth.json``."""

    def __init__(self, doc: dict, case_id: str, path: Optional[Path] = None):
        self.doc = doc
        self.case_id = case_id
        self.path = path
        self.language: str = str(doc.get("language") or case_id)
        self.file: Optional[str] = doc.get("file")
        self.generated: Optional[str] = doc.get("generated")
        self.conventions: dict = doc.get("conventions") or {}
        self.libraries: list[GTLibrary] = [
            GTLibrary(str(l.get("id")), str(l.get("name") or l.get("id")), l.get("version"), l.get("purl"), l.get("scope"))
            for l in doc.get("libraries") or [] if isinstance(l, dict) and l.get("id")
        ]
        self.library_by_id = {l.id: l for l in self.libraries}
        self.occurrences: dict[str, GTOccurrence] = {}
        for o in doc.get("occurrences") or []:
            if not isinstance(o, dict) or not o.get("id"):
                continue
            start = o.get("start") or {}
            end = o.get("end") or {}
            self.occurrences[str(o["id"])] = GTOccurrence(
                id=str(o["id"]), file=o.get("file") or self.file, line=_opt_int(start.get("line")),
                end_line=_opt_int(end.get("line")), column=_opt_int(start.get("column")),
                role=str(o.get("role") or ""), kind=str(o.get("kind") or ""), relation="direct",
                scenario=o.get("scenario") if o.get("scenario") not in (None, "-") else None, scope=o.get("scope"),
                library=o.get("library"), symbol=o.get("symbol"), evidence=o.get("evidence"))
        self.non_asset_mentions: list[NonAssetMention] = [
            NonAssetMention(str(m.get("id")), int(m.get("line") or 0), str(m.get("text") or ""),
                            str(m.get("context") or ""), str(m.get("reason") or ""))
            for m in doc.get("nonAssetMentions") or [] if isinstance(m, dict) and m.get("line")
        ]
        self.assets: list[GTAsset] = []
        raw_assets = [a for a in doc.get("assets") or [] if isinstance(a, dict) and a.get("id")]
        by_id: dict[str, dict] = {str(a["id"]): a for a in raw_assets}
        algo_family: dict[str, Optional[str]] = {}
        for a in raw_assets:
            if a.get("kind") == "algorithm":
                algo_family[str(a["id"])] = normalize_family((a.get("properties") or {}).get("family")) or \
                    descriptor_from_fields((a.get("properties") or {}).get("name"), a.get("properties")).family
        for a in raw_assets:
            self.assets.append(self._build_asset(a, by_id, algo_family))
        # library assets, so that library detection is scored like any other category
        for lib in self.libraries:
            occs = [self._occ_copy(o, "direct") for o in self.occurrences.values() if o.kind == "imp" and o.library == lib.id]
            scen = sorted({o.scenario for o in self.occurrences.values() if o.library == lib.id and o.scenario})
            self.assets.append(GTAsset(id=lib.id, asset_type="library", name=lib.name, bom_ref=None, implicit=False,
                                       functions=[], props={"purl": lib.purl, "version": lib.version, "name": lib.name,
                                                            "scope": lib.scope},
                                       occurrences=occs, family=lib.purl_key or lib.name.lower(), subtype="library",
                                       descriptor=None, scenarios=scen, libraries=[lib.id], pqc=False))
        self.asset_by_id = {a.id: a for a in self.assets}

    def _occ_copy(self, o: GTOccurrence, relation: str) -> GTOccurrence:
        return GTOccurrence(o.id, o.file, o.line, o.end_line, o.column, o.role, o.kind, relation, o.scenario, o.scope,
                            o.library, o.symbol, o.evidence)

    def _build_asset(self, a: dict, by_id: dict, algo_family: dict) -> GTAsset:
        kind = str(a.get("kind") or "algorithm")
        asset_type = {"related-crypto-material": "related-crypto-material", "algorithm": "algorithm",
                      "certificate": "certificate", "protocol": "protocol"}.get(kind, kind)
        props = dict(a.get("properties") or {})
        name = str(props.get("name") or a["id"])
        occs: list[GTOccurrence] = []
        for ref in a.get("occurrences") or []:
            if isinstance(ref, dict) and ref.get("id") in self.occurrences:
                occs.append(self._occ_copy(self.occurrences[ref["id"]], str(ref.get("relation") or "direct")))
        scenarios = sorted({o.scenario for o in occs if o.scenario} | ({props["scenario"]} if props.get("scenario") else set()))
        libraries = sorted({o.library for o in occs if o.library})
        descriptor = None
        family = None
        subtype = None
        algorithm_ref = None
        pqc = False
        if asset_type == "algorithm":
            hints = {"parameterSetIdentifier": props.get("parameterSetIdentifier"), "mode": props.get("mode"),
                     "padding": props.get("padding"), "curve": props.get("curve"), "primitive": props.get("primitive")}
            descriptor = descriptor_from_fields(name, hints)
            family = normalize_family(props.get("family")) or descriptor.family
            if family and descriptor.family != family:
                if descriptor.family in HASH_FAMILIES and family not in HASH_FAMILIES:
                    # e.g. "BC DigestRandomGenerator (SHA-256)", family "Hash-based PRNG": the hash is a parameter
                    descriptor.hash = descriptor.hash or (f"{descriptor.family}-{descriptor.param}" if descriptor.param else descriptor.family)
                    descriptor.param = None
                descriptor.family = family
            subtype = str(props.get("primitive") or descriptor.primitive or "unknown")
            pqc = family in PQC_FAMILIES
        elif asset_type == "related-crypto-material":
            algorithm_ref = props.get("algorithmRef")
            family = algo_family.get(algorithm_ref) if algorithm_ref else None
            subtype = normalize_material_type(props.get("type")) or "unknown"
            pqc = family in PQC_FAMILIES
        elif asset_type == "certificate":
            algorithm_ref = props.get("signatureAlgorithmRef")
            family = algo_family.get(algorithm_ref) if algorithm_ref else None
            subtype = str(props.get("certificateFormat") or "x.509").lower()
        elif asset_type == "protocol":
            subtype = str(props.get("type") or "unknown").lower()
            family = f"{subtype}-{props.get('version')}" if props.get("version") else subtype
        return GTAsset(id=str(a["id"]), asset_type=asset_type, name=name, bom_ref=a.get("bomRef"),
                       implicit=bool(a.get("implicit")), functions=normalize_functions(a.get("functions")),
                       props=props, occurrences=occs, family=family, subtype=subtype, descriptor=descriptor,
                       scenarios=scenarios, libraries=libraries, pqc=pqc, algorithm_ref=algorithm_ref)

    # -- helpers ---------------------------------------------------------------
    def assets_of_type(self, asset_type: str) -> list[GTAsset]:
        return [a for a in self.assets if a.asset_type == asset_type]

    def mention_lines(self) -> dict[int, list[NonAssetMention]]:
        out: dict[int, list[NonAssetMention]] = {}
        for m in self.non_asset_mentions:
            out.setdefault(m.line, []).append(m)
        return out

    def stats(self) -> dict:
        by_type: dict[str, int] = {}
        for a in self.assets:
            by_type[a.asset_type] = by_type.get(a.asset_type, 0) + 1
        return {"language": self.language, "file": self.file, "assets": len(self.assets), "byType": by_type,
                "occurrences": len(self.occurrences), "nonAssetMentions": len(self.non_asset_mentions),
                "generated": self.generated}

    @classmethod
    def load(cls, path: Path, case_id: Optional[str] = None) -> "GroundTruth":
        path = Path(path)
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        return cls(doc, case_id or path.parent.name, path)


def match_file(reported: Optional[str], expected: Optional[str]) -> bool:
    """Compare a tool-reported path with the ground-truth path by suffix (tools prefix mount points)."""
    if not reported or not expected:
        return False
    r = reported.replace("\\", "/").strip()
    e = expected.replace("\\", "/").strip()
    r = re.sub(r"^(\./|/)+", "", r)
    e = re.sub(r"^(\./|/)+", "", e)
    if r == e:
        return True
    return r.endswith("/" + e) or e.endswith("/" + r) or Path(r).name == Path(e).name and (
        r.endswith(e) or e.endswith(r))
