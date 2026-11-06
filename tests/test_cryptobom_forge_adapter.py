"""Control flow of the cryptobom-forge pipeline with stubbed `codeql` and `cryptobom` executables."""
import json
import os
import stat
import sys
from pathlib import Path

from orchestrator.baseline import Case
from orchestrator.config import Config
from orchestrator.tools import load_specs, make_adapter
from orchestrator.tools.base import ToolVersion

CODEQL_STUB = '''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if args[:1] == ["version"]:
    print(json.dumps({"version": "2.27.4"})); sys.exit(0)
if args[:2] == ["database", "create"]:
    os.makedirs(args[2], exist_ok=True); print("created", args); sys.exit(0)
if args[:2] == ["database", "analyze"]:
    out = next(a.split("=", 1)[1] for a in args if a.startswith("--output="))
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "organization": "GitHub", "semanticVersion": "2.27.4"}},
             "results": [{"ruleId": "py/crypto", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "crypto_showcase.py"},
             "region": {"startLine": 86, "endLine": 86, "startColumn": 27, "endColumn": 51},
             "contextRegion": {"startLine": 84, "endLine": 88, "snippet": {"text": "x\\ny\\nhashlib.sha256(MESSAGE).digest()\\nz\\nw"}}}}]}]}]}
    json.dump(sarif, open(out, "w")); sys.exit(0)
sys.exit(2)
'''

FORGE_STUB = '''#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
if args == ["--version"]:
    print("cryptobom, version 1.1.0"); sys.exit(0)
out = args[args.index("-o") + 1]
doc = {"bomFormat": "CBOM", "specVersion": "1.4-cbom-1.0", "metadata": {"tools": [{"name": "CodeQL", "vendor": "GitHub", "version": "2.27.4"}]},
       "components": [{"type": "crypto-asset", "bom-ref": "algorithm:sha256", "name": "SHA256",
                       "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash", "variant": "SHA256"},
                                            "detectionContext": [{"filePath": "crypto_showcase.py", "lineNumbers": [84, 85, 86, 87, 88]}]}}]}
json.dump(doc, open(out, "w")); sys.exit(0)
'''


def _executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_pipeline_with_stubs(tmp_path, fixtures):
    config = Config.defaults(tmp_path)
    config.data["tools"]["cache_dir"] = str(tmp_path / "cache")
    adapter = make_adapter(load_specs(config)["cryptobom-forge"], config)
    version = ToolVersion.fixed("cryptobom-forge", "cryptobom-forge", "1.1.0", tag="1.1.0", launcher="local")
    version.components["codeql"] = {"source": "bundle", "repo": "https://github.com/github/codeql-action",
                                    "tag": "codeql-bundle-v2.27.4", "version": "2.27.4"}
    # pre-place a fake bundle and a fake venv so install() skips downloads and pip
    root = adapter.codeql_root("2.27.4") / "codeql"
    _executable(root / "codeql", CODEQL_STUB)
    (root / "qlpacks" / "codeql" / "python-queries" / "1.6.1" / "experimental" / "cryptography" / "inventory" / "new_models").mkdir(parents=True)
    _executable(adapter.venv_bin(version, "cryptobom"), FORGE_STUB)
    adapter.install(version, tmp_path / "install.log")
    assert version.components["codeql"]["cliVersion"] == "2.27.4"
    assert version.components["queryPacks"] == {"python-queries": "1.6.1"}
    assert "1.1.0" in version.components["forge"]["reportedVersion"]

    case_dir = fixtures / "baseline-mini" / "Python"
    case = Case("Python", "Python", case_dir, case_dir / "ground-truth.json", case_dir / "cbom.cdx.json", "crypto_showcase.py")
    work = tmp_path / "work" / "Python"
    work.mkdir(parents=True)
    res = adapter.run(case, work, version, tmp_path / "raw", tmp_path / "run.log")
    assert res.status == "ok", res.notes
    assert res.output_path.name == "cbom.json" and (tmp_path / "raw" / "crypto.sarif").exists()
    assert res.extra["codeqlLanguage"] == "python" and res.extra["queries"][0].endswith("new_models")
    assert len(res.command) == 3
    # a language without inventory queries is reported as unsupported, not failed
    go = Case("Go", "Go", case_dir, case.ground_truth, None, "main.go")
    assert adapter.run(go, work, version, tmp_path / "raw-go", tmp_path / "run.log").status == "unsupported"
    # and the produced IBM-dialect CBOM scores against the ground truth
    from orchestrator.baseline import GroundTruth
    from orchestrator.evaluate.ledger import evaluate_case
    from orchestrator.normalize import read_cbom_file
    ev = evaluate_case(GroundTruth.load(case.ground_truth, "Python"), read_cbom_file(res.output_path), "cryptobom-forge", "1.1.0")
    row = next(r for r in ev.rows if r["assetId"] == "sha-256")
    assert row["detected"] and row["located"]
