"""The YAML-driven adapter renders commands without running anything (no Docker in CI)."""
from pathlib import Path

from orchestrator.baseline import Case
from orchestrator.config import Config
from orchestrator.tools import load_specs, make_adapter
from orchestrator.tools.base import ToolVersion, render


def test_builtin_specs_load():
    specs = load_specs(Config.defaults())
    assert {"cbomkit", "cdxgen", "cryptobom-forge", "oracle"} <= set(specs)
    assert specs["cbomkit"].supports(Case("Java", "Java", Path("."), Path("gt"), None, "X.java"))
    assert not specs["cbomkit"].supports(Case("TypeScript", "TypeScript", Path("."), Path("gt"), None, "x.ts"))
    assert specs["cdxgen"].language_entry(Case("CSharp", "C#", Path("."), Path("gt"), None, "P.cs")) == {"value": "dotnet"}


def test_placeholders_render(tmp_path):
    config = Config.defaults(tmp_path)
    spec = load_specs(config)["cdxgen"]
    adapter = make_adapter(spec, config)
    version = ToolVersion.fixed("cdxgen", "cdxgen", "13.6.0", tag="v13.6.0", launcher="docker")
    case = Case("Python", "Python", tmp_path, tmp_path / "gt.json", None, "crypto_showcase.py")
    variables = adapter.variables(version, case, tmp_path / "work", {"mount": "/app", "output_container": "/app/out.json"})
    args = render(spec.docker["args"], variables)
    assert args[:2] == ["-t", "python"] and "--include-crypto" in args and args[-1] == "/app"
    assert render(spec.docker["image"], variables) == "ghcr.io/cyclonedx/cdxgen:v13.6.0"
    cb = load_specs(config)["cbomkit"]
    assert render(cb.docker["image"], adapter.variables(ToolVersion.fixed("cbomkit", "x", "2.3.0", tag="v2.3.0"))) == \
        "ghcr.io/cbomkit/cbomkit-action:2.3.0"


def test_unsupported_language_short_circuits(tmp_path):
    config = Config.defaults(tmp_path)
    adapter = make_adapter(load_specs(config)["cbomkit"], config)
    case = Case("TypeScript", "TypeScript", tmp_path, tmp_path / "gt.json", None, "x.ts")
    res = adapter.run(case, tmp_path / "w", ToolVersion.fixed("cbomkit", "x", "2.3.0"), tmp_path / "o", tmp_path / "l.log")
    assert res.status == "unsupported"


def test_local_launcher_end_to_end(tmp_path, fixtures):
    """A fake local tool (a Python one-liner) proves the local launcher, output lookup and status rules."""
    import json
    import sys
    import yaml
    from orchestrator.tools import load_specs, make_adapter
    tools_d = tmp_path / "tools.d"
    tools_d.mkdir()
    script = tmp_path / "faketool.py"
    script.write_text(
        "import json, sys\n"
        "out, lang = sys.argv[1], sys.argv[2]\n"
        "doc = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'metadata': {'tools': {'components': [{'name': 'faketool', 'version': '9.9'}]}},\n"
        "       'components': [] if lang == 'empty' else [{'type': 'cryptographic-asset', 'bom-ref': 'x', 'name': 'SHA-256',\n"
        "       'cryptoProperties': {'assetType': 'algorithm', 'algorithmProperties': {'primitive': 'hash'}}}]}\n"
        "json.dump(doc, open(out, 'w'))\n")
    (tools_d / "faketool.yaml").write_text(yaml.safe_dump({
        "id": "faketool", "name": "Fake", "repo": None, "launcher": "local",
        "local": {"command": [sys.executable, str(script), "{output}", "{language}"]},
        "output": "out/fake.json", "languages": {"Python": "python", "Go": "empty"}}))
    config = Config.defaults(tmp_path)
    config.data["tools"]["dir"] = str(tools_d)
    config.data["tools"]["cache_dir"] = str(tmp_path / "cache")
    adapter = make_adapter(load_specs(config)["faketool"], config)
    version = adapter.resolve()
    assert version.version == "unversioned" and version.launcher == "local"
    case = Case("Python", "Python", fixtures / "baseline-mini" / "Python", fixtures / "baseline-mini" / "Python" / "ground-truth.json", None, "crypto_showcase.py")
    work = tmp_path / "work"
    work.mkdir()
    (work / "out").mkdir()
    res = adapter.run(case, work, version, tmp_path / "raw", tmp_path / "log.txt")
    assert res.status == "ok" and res.output_path and res.output_path.exists()
    assert json.load(open(res.output_path))["components"]
    empty_case = Case("Go", "Go", case.dir, case.ground_truth, None, "main.go")
    res2 = adapter.run(empty_case, work, version, tmp_path / "raw2", tmp_path / "log.txt")
    assert res2.status == "empty"
    assert "faketool" in (tmp_path / "log.txt").read_text()
