"""Evaluate a run directory: normalise every raw CBOM, match it to the ground truth, build the ledger
and aggregate it into the scorecard document.  Re-running this on an old run directory against a
newer baseline checkout re-scores the stored raw outputs without re-running the tools."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from .. import SCORECARD_SCHEMA_VERSION, SCORING_MODEL_VERSION, __version__
from ..baseline import GroundTruth, _head_info
from ..config import Config
from ..github import now_iso
from ..normalize import read_cbom_file
from .ledger import evaluate_case
from .pairwise import head_to_head, pair_key
from .scoring import FACET_COMBOS, category_key, parse_category, strengths

log = logging.getLogger("orchestrator.evaluate")

PAIRWISE_COMBOS = ((), ("language",), ("assetType",), ("subtype",), ("family",), ("language", "subtype"),
                   ("language", "assetType"), ("pqc",))


def _load_ground_truths(manifest: dict, baseline_override: Optional[Path]) -> tuple[dict, dict]:
    base_path = Path(baseline_override) if baseline_override else Path(manifest["baseline"]["path"])
    gts: dict[str, GroundTruth] = {}
    for c in manifest["baseline"]["cases"]:
        gt_path = Path(c["groundTruth"])
        if baseline_override:
            gt_path = base_path / c["id"] / gt_path.name
        if not gt_path.exists():
            log.warning("ground truth for case %s missing at %s; skipping", c["id"], gt_path)
            continue
        gts[c["id"]] = GroundTruth.load(gt_path, c["id"])
    commit, describe = _head_info(base_path)
    info = {**manifest["baseline"], "path": str(base_path), "evaluatedCommit": commit, "evaluatedDescribe": describe,
            "evaluatedAt": now_iso()}
    return gts, info


def evaluate_run(run_dir: Path, config: Optional[Config] = None, baseline_override: Optional[Path] = None) -> dict:
    from ..reconcile import Scorecard
    from ..runner import load_manifest

    run_dir = Path(run_dir)
    manifest = load_manifest(run_dir)
    cfg = config or Config(manifest.get("config") or {}, run_dir)
    scoring = {**Config.defaults().get("scoring"), **(cfg.get("scoring") or {})}
    tolerance = int(scoring.get("line_tolerance", 1))
    failed_zero = bool(scoring.get("treat_failed_as_zero", False))

    gts, baseline_info = _load_ground_truths(manifest, baseline_override)
    ledger: list = []
    runs_out: list = []
    tools: dict = {tid: dict(t) for tid, t in (manifest.get("tools") or {}).items()}
    for t in tools.values():
        spec = t.pop("spec", None) or {}
        t["twocbom"] = spec.get("twocbom") or {}
        t["description"] = spec.get("description")
        t["languages"] = sorted((spec.get("languages") or {}).keys())
    coverage: dict[str, dict] = {}
    for rec in manifest.get("runs") or []:
        tool, case_id = rec["tool"], rec["case"]
        gt = gts.get(case_id)
        if gt is None:
            continue
        status = rec.get("status", "failed")
        cbom = None
        if rec.get("output") and status in ("ok", "empty", "failed", "timeout"):
            path = run_dir / rec["output"]
            if path.exists():
                try:
                    cbom = read_cbom_file(path)
                except Exception as exc:  # noqa: BLE001
                    log.warning("%s/%s: cannot read %s: %s", tool, case_id, path, exc)
                    status = "failed"
                    rec = {**rec, "notes": list(rec.get("notes") or []) + [f"unreadable output: {exc}"]}
        ev = evaluate_case(gt, cbom, tool, rec.get("toolVersion"), status=status, tolerance=tolerance,
                           treat_failed_as_zero=failed_zero)
        ledger.extend(ev.rows)
        ledger.extend(ev.fp_rows)
        coverage.setdefault(tool, {})[gt.language] = status
        runs_out.append({**{k: v for k, v in rec.items() if k != "command"}, "evaluation": ev.stats})
        if cbom is not None and cbom.metadata.tool_name and tool in tools and not tools[tool].get("reported"):
            tools[tool]["reported"] = {"name": cbom.metadata.tool_name, "version": cbom.metadata.tool_version,
                                      "format": cbom.format, "specVersion": cbom.metadata.spec_version,
                                      "allTools": cbom.metadata.tools}

    doc = {
        "schemaVersion": SCORECARD_SCHEMA_VERSION, "scoringModelVersion": SCORING_MODEL_VERSION,
        "orchestrator": {"version": __version__},
        "run": {"id": manifest.get("runId"), "startedAt": manifest.get("startedAt"), "finishedAt": manifest.get("finishedAt"),
                "host": manifest.get("host"), "config": {"scoring": scoring}},
        "baseline": {k: v for k, v in baseline_info.items() if k != "cases"},
        "cases": [{**c, "stats": gts[c["id"]].stats()} for c in manifest["baseline"]["cases"] if c["id"] in gts],
        "tools": tools, "runs": runs_out, "coverage": coverage, "scores": {}, "pairwise": {}, "ledger": ledger,
    }
    sc = Scorecard(doc)
    for tool in sorted(tools):
        overall = sc.overall(tool) or {}
        by_cat = sc.all_category_scores(tool, FACET_COMBOS)
        doc["scores"][tool] = {
            "overall": overall,
            "byCategory": by_cat,
            "strengths": strengths(overall, float(scoring.get("strength_threshold", 0.8)),
                                   int(scoring.get("strength_min_support", 5))),
            "coverage": coverage.get(tool, {}),
        }
    tool_ids = sorted(tools)
    for i, a in enumerate(tool_ids):
        for b in tool_ids[i + 1:]:
            key, _ = pair_key(a, b)
            table: dict = {}
            cats = {"*"} | ({k for k in doc["scores"][a]["byCategory"] if _combo_of(k) in PAIRWISE_COMBOS}
                            & {k for k in doc["scores"][b]["byCategory"] if _combo_of(k) in PAIRWISE_COMBOS})
            for cat in sorted(cats):
                h2h = head_to_head(sc.gt_rows(a), sc.gt_rows(b), parse_category(cat))
                if h2h:
                    table[cat] = h2h
            doc["pairwise"][key] = table
    doc["summary"] = {tool: {k: doc["scores"][tool]["overall"].get(k) for k in
                             ("support", "detected", "recall", "precision", "completeness", "correctness", "locality",
                              "score", "falsePositives", "lexicalFalsePositives")} for tool in tool_ids}
    return doc


def _combo_of(key: str) -> tuple:
    if key == "*":
        return ()
    return tuple(kv.split("=", 1)[0] for kv in key.split(";"))
