"""End-to-end: run the oracle tools on the vendored mini corpus through the real Runner, evaluate, export."""
import json
import shutil
from pathlib import Path

import yaml

from orchestrator.config import Config
from orchestrator.evaluate import evaluate_run
from orchestrator.export import write_outputs
from orchestrator.reconcile import Scorecard
from orchestrator.runner import Runner


def _project(tmp_path: Path, fixtures: Path) -> Config:
    corpus = tmp_path / "corpus"
    shutil.copytree(fixtures / "baseline-mini", corpus)
    cfg = {"baseline": {"repo": str(corpus)}, "results": {"dir": str(tmp_path / "results"), "latest_symlink": False},
           "tools": {"enabled": ["oracle", "oracle-noisy"], "cache_dir": str(tmp_path / "cache"), "dir": str(tmp_path / "tools.d")}}
    (tmp_path / "orchestrator.yaml").write_text(yaml.safe_dump(cfg))
    return Config.load(tmp_path / "orchestrator.yaml")


def test_full_pipeline(tmp_path, fixtures):
    config = _project(tmp_path, fixtures)
    run_dir = Runner(config, run_id="t1").execute()
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert {r["tool"] for r in manifest["runs"]} == {"oracle", "oracle-noisy"}
    assert manifest["baseline"]["commit"] is None or isinstance(manifest["baseline"]["commit"], str)
    assert manifest["tools"]["oracle"]["version"] == "reference"
    doc = evaluate_run(run_dir, config)
    paths = write_outputs(doc, run_dir, config)
    assert all(p.exists() for p in paths.values())
    assert doc["summary"]["oracle"]["score"] == 1.0
    assert doc["summary"]["oracle-noisy"]["score"] < 1.0
    assert doc["tools"]["oracle"]["reported"]["name"].startswith("oracle")
    tools_json = json.loads((run_dir / "twocbom" / "tools.json").read_text())
    assert tools_json["tools"]["oracle"]["trust"] == 95          # ceiling
    assert tools_json["tools"]["oracle"]["benchmark"]["version"] == "reference"
    assert "oracle" in tools_json["tools"]["oracle"]["aliases"]
    sc = Scorecard.load(run_dir)
    r = sc.reconcile("oracle-noisy", "oracle", "subtype=hash", "parameterSetIdentifier")
    assert r.preferred == "oracle"
    report = (run_dir / "report.md").read_text()
    assert "## Tool versions" in report and "oracle-noisy" in report
    # re-evaluation against the same corpus is idempotent
    doc2 = evaluate_run(run_dir, config)
    assert doc2["summary"] == doc["summary"]


def test_user_tool_spec_overrides_builtin(tmp_path, fixtures):
    config = _project(tmp_path, fixtures)
    tools_d = tmp_path / "tools.d"
    tools_d.mkdir()
    (tools_d / "oracle.yaml").write_text(yaml.safe_dump({
        "id": "oracle", "name": "oracle-override", "adapter": "orchestrator.tools.oracle:OracleAdapter",
        "languages": {"Python": "python"}, "options": {"degrade": {"drop_assets": 0.5, "seed": 3}}}))
    from orchestrator.tools import load_specs
    specs = load_specs(config)
    assert specs["oracle"].name == "oracle-override" and specs["oracle"].source.startswith("tools.d")
