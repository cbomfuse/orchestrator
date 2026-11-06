"""Writers for the scorecard, the compact priors file, the Markdown report and the 2CBOM knowledge files."""
from __future__ import annotations

import json
from pathlib import Path

from .report import render_report
from .twocbom import build_priors, build_tools_json

__all__ = ["write_outputs", "render_report", "build_tools_json", "build_priors"]


def write_outputs(doc: dict, run_dir: Path, config=None) -> dict:
    """Write every export for a scorecard document into ``run_dir``; returns the paths written."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    paths = {}
    p = run_dir / "scorecard.json"
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
    paths["scorecard"] = p
    priors = build_priors(doc)
    p = run_dir / "priors.json"
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(priors, fh, indent=1)
    paths["priors"] = p
    tw = run_dir / "twocbom"
    tw.mkdir(exist_ok=True)
    export_cfg = (config.get("export", "twocbom", default={}) if config is not None else {}) or {}
    p = tw / "tools.json"
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(build_tools_json(doc, **export_cfg), fh, indent=2)
    paths["twocbom_tools"] = p
    p = tw / "priors.json"
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(priors, fh, indent=1)
    paths["twocbom_priors"] = p
    p = run_dir / "report.md"
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(render_report(doc))
    paths["report"] = p
    return paths
