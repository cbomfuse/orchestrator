"""Control flow of the cryptobom-forge pipeline with stubbed `codeql` and `cryptobom` executables."""
import json
import os
import stat
import sys
from pathlib import Path

from orchestrator.baseline import Case
from orchestrator.config import Config
from orchestrator.process import CommandResult, run_command
from orchestrator.tools import load_specs, make_adapter
from orchestrator.tools import cryptobom_forge
from orchestrator.tools.base import ToolVersion

CODEQL_STUB = '''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if args[:1] == ["version"]:
    print(json.dumps({"version": "2.27.4"})); sys.exit(0)
if args[:2] == ["database", "create"]:
    os.makedirs(args[2], exist_ok=True); print("created", args); sys.exit(0)
if args[:2] == ["database", "run-queries"]:
    db = args[args.index("--") + 1]
    for query in args[args.index("--") + 2:]:
        sources = []
        if os.path.isdir(query):
            for root, _, files in os.walk(query):
                sources.extend(os.path.join(root, name) for name in files if name.endswith(".ql"))
        elif query.endswith(".ql"):
            sources.append(query)
        for source in sources:
            name = os.path.splitext(os.path.basename(source))[0]
            result = os.path.join(db, "results", name + ".bqrs")
            os.makedirs(os.path.dirname(result), exist_ok=True)
            open(result, "w").close()
    sys.exit(0)
if args[:2] == ["bqrs", "info"]:
    columns = [{"name": "op", "kind": "e"}] if args[-1].endswith("SingleColumn.bqrs") else [
        {"name": "op", "kind": "e"}, {"name": "algorithm", "kind": "s"}]
    print(json.dumps({"result-sets": [{"name": "#select", "rows": 1, "columns": columns}]}))
    sys.exit(0)
if args[:2] == ["bqrs", "decode"]:
    out = next(a.split("=", 1)[1] for a in args if a.startswith("--output="))
    decoded = {"#select": {"tuples": [[{"id": 1, "label": "Operation", "url": {
        "uri": "CryptoShowcase.java", "startLine": 3, "startColumn": 5, "endLine": 3, "endColumn": 17}}]]}}
    json.dump(decoded, open(out, "w")); sys.exit(0)
if args[:2] == ["bqrs", "interpret"]:
    if args[2].endswith("SingleColumn.bqrs"):
        print("Expected result pattern(s) are not present for problem query: Expected at least 2 columns.", file=sys.stderr)
        sys.exit(2)
    out = next(a.split("=", 1)[1] for a in args if a.startswith("--output="))
    query_id = next(a.split("=", 1)[1] for a in args if a.startswith("-t=id="))
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "organization": "GitHub",
             "semanticVersion": "2.27.4"}}, "results": [{"ruleId": query_id, "message": {"text": "SHA-256"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "CryptoShowcase.java"},
             "region": {"startLine": 3, "startColumn": 5, "endColumn": 17}}}]}]}]}
    json.dump(sarif, open(out, "w")); sys.exit(0)
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


def test_pipeline_with_stubs(tmp_path, fixtures, monkeypatch):
    def run_stub(argv, **kwargs):
        if os.name == "nt" and Path(argv[0]).suffix.lower() == ".exe":
            argv = [sys.executable, *argv]
        return run_command(argv, **kwargs)

    monkeypatch.setattr(cryptobom_forge, "run_command", run_stub)
    config = Config.defaults(tmp_path)
    config.data["tools"]["cache_dir"] = str(tmp_path / "cache")
    adapter = make_adapter(load_specs(config)["cryptobom-forge"], config)
    version = ToolVersion.fixed("cryptobom-forge", "cryptobom-forge", "1.1.0", tag="1.1.0", launcher="local")
    version.components["codeql"] = {"source": "bundle", "repo": "https://github.com/github/codeql-action",
                                    "tag": "codeql-bundle-v2.27.4", "version": "2.27.4"}
    # pre-place a fake bundle and a fake venv so install() skips downloads and pip
    root = adapter.codeql_root("2.27.4") / "codeql"
    _executable(root / ("codeql.exe" if os.name == "nt" else "codeql"), CODEQL_STUB)
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


def test_install_forge_uses_python_module_for_pip(tmp_path, monkeypatch):
    config = Config.defaults(tmp_path)
    config.data["tools"]["cache_dir"] = str(tmp_path / "cache")
    adapter = make_adapter(load_specs(config)["cryptobom-forge"], config)
    version = ToolVersion.fixed("cryptobom-forge", "cryptobom-forge", "1.1.0", tag="1.1.0", launcher="local")
    commands = []

    def run_install_command(argv, **kwargs):
        commands.append(argv)
        return CommandResult(list(argv), 0, "cryptobom, version 1.1.0" if argv[-1] == "--version" else "",
                             "", 0.0)

    monkeypatch.setattr(cryptobom_forge, "run_command", run_install_command)
    adapter._install_forge(version, None)

    python = str(adapter.venv_bin(version, "python"))
    pip_commands = [argv for argv in commands if argv[1:3] == ["-m", "pip"]]
    assert len(pip_commands) == 3
    assert all(argv[:3] == [python, "-m", "pip"] for argv in pip_commands)
    assert version.components["forge"]["reportedVersion"] == "cryptobom, version 1.1.0"


def test_java_table_queries_are_converted_to_forge_sarif(tmp_path, fixtures, monkeypatch):
    def run_stub(argv, **kwargs):
        if os.name == "nt" and Path(argv[0]).suffix.lower() == ".exe":
            argv = [sys.executable, *argv]
        return run_command(argv, **kwargs)

    monkeypatch.setattr(cryptobom_forge, "run_command", run_stub)
    config = Config.defaults(tmp_path)
    config.data["tools"]["cache_dir"] = str(tmp_path / "cache")
    adapter = make_adapter(load_specs(config)["cryptobom-forge"], config)
    version = ToolVersion.fixed("cryptobom-forge", "cryptobom-forge", "1.1.0", tag="1.1.0", launcher="local")
    version.components["codeql"] = {"version": "2.27.4"}

    root = adapter.codeql_root("2.27.4") / "codeql"
    _executable(root / ("codeql.exe" if os.name == "nt" else "codeql"), CODEQL_STUB)
    query_dir = root / "qlpacks" / "codeql" / "java-queries" / "1.12.0" / "experimental" / "quantum" / "InventorySlices"
    (query_dir / "TableQuery.ql").parent.mkdir(parents=True)
    (query_dir / "TableQuery.ql").write_text(
        "/**\n * @name Test table query\n * @description Finds a Java algorithm.\n"
        " * @id java/test/table-query\n * @kind table\n */\nselect 1, \"SHA-256\"\n",
        encoding="utf-8",
    )
    (query_dir / "SingleColumn.ql").write_text(
        "/**\n * @name Test single-column query\n * @description Finds operations.\n"
        " * @id java/test/single-column\n * @kind table\n */\nselect 1\n",
        encoding="utf-8",
    )
    _executable(adapter.venv_bin(version, "cryptobom"), FORGE_STUB)

    case_dir = tmp_path / "Java"
    case_dir.mkdir()
    case = Case("Java", "Java", case_dir, case_dir / "ground-truth.json", None, "CryptoShowcase.java")
    work = tmp_path / "work" / "Java"
    work.mkdir(parents=True)
    (work / "CryptoShowcase.java").write_text("class CryptoShowcase {\n  void f() {\n    Cipher.getInstance(\"SHA-256\");\n  }\n}\n",
                                              encoding="utf-8")
    raw = tmp_path / "raw"
    result = adapter.run(case, work, version, raw, tmp_path / "run.log")

    assert result.status == "ok"
    assert result.output_path and result.output_path.exists()
    assert (raw / "crypto.sarif").exists()
    sarif = json.loads((raw / "crypto.sarif").read_text(encoding="utf-8"))
    assert len(sarif["runs"]) == 2
    operation = next(run for run in sarif["runs"] if run["tool"]["driver"]["rules"][0]["id"] ==
                     "java/test/single-column")
    assert operation["results"][0]["locations"][0]["physicalLocation"]["contextRegion"]["snippet"]["text"]


def test_add_sarif_context_reads_bounded_source_lines(tmp_path):
    from orchestrator.tools.cryptobom_forge import _add_sarif_context

    source = tmp_path / "CryptoShowcase.java"
    source.write_text("one\ntwo\nthree\nfour\nfive\nsix\n", encoding="utf-8")
    sarif = tmp_path / "query.sarif"
    sarif.write_text(json.dumps({"version": "2.1.0", "runs": [{"results": [{"locations": [
        {"physicalLocation": {"artifactLocation": {"uri": source.name},
                              "region": {"startLine": 4, "startColumn": 1, "endColumn": 5}}}
    ]}]}]}), encoding="utf-8")

    _add_sarif_context(sarif, tmp_path)

    physical = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["contextRegion"]["startLine"] == 2
    assert physical["contextRegion"]["endLine"] == 6
    assert physical["contextRegion"]["snippet"]["text"] == "two\nthree\nfour\nfive\nsix\n"
