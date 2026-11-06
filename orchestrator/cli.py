"""``orchestrator`` command-line interface."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .config import Config, default_config_yaml

log = logging.getLogger("orchestrator")


def _config(args) -> Config:
    overrides = {}
    if getattr(args, "results_dir", None):
        overrides["results"] = {"dir": args.results_dir}
    if getattr(args, "baseline_ref", None):
        overrides["baseline"] = {"ref": args.baseline_ref}
    if getattr(args, "baseline_repo", None):
        overrides.setdefault("baseline", {})["repo"] = args.baseline_repo
    return Config.load(getattr(args, "config", None), overrides)


def _parse_pins(values: Optional[list]) -> dict:
    pins = {}
    for v in values or []:
        if "=" not in v:
            raise SystemExit(f"--pin expects tool=version, got {v!r}")
        k, ver = v.split("=", 1)
        pins[k.strip()] = ver.strip()
    return pins


def _run_dir(config: Config, value: str) -> Path:
    p = Path(value)
    if p.exists():
        return p
    cand = config.path("results", "dir") / value
    if cand.exists():
        return cand
    raise SystemExit(f"run directory not found: {value}")


def _print_json(data) -> None:
    print(json.dumps(data, indent=2, default=str))


# ----------------------------------------------------------------------------- commands
def cmd_init(args) -> int:
    target = Path(args.path or "orchestrator.yaml")
    if target.exists() and not args.force:
        print(f"{target} exists (use --force to overwrite)")
        return 1
    target.write_text(default_config_yaml(), encoding="utf-8")
    tools_d = target.parent / "tools.d"
    tools_d.mkdir(exist_ok=True)
    print(f"wrote {target}; add tool specs to {tools_d}/")
    return 0


def cmd_baseline(args) -> int:
    from .baseline import GroundTruth, discover_cases, sync_baseline
    config = _config(args)
    if args.baseline_cmd == "sync":
        co = sync_baseline(config, offline=False)
        print(f"{co.repo} @ {co.ref} -> {co.commit} ({co.describe}) in {co.path}")
        for n in co.notes:
            print(f"  note: {n}")
        return 0
    co = sync_baseline(config, offline=not args.sync)
    cases = discover_cases(co.path, config)
    if args.baseline_cmd == "cases":
        for c in cases:
            print(f"{c.id:12} {c.language:12} {c.source_file}")
        return 0
    info = {"checkout": co.to_dict(), "cases": []}
    for c in cases:
        gt = GroundTruth.load(c.ground_truth, c.id)
        info["cases"].append({**c.to_dict(), "stats": gt.stats()})
    _print_json(info)
    return 0


def cmd_tools(args) -> int:
    from .docker import Docker
    from .tools import load_adapters, load_specs
    config = _config(args)
    if args.tools_cmd == "list":
        specs = load_specs(config)
        enabled = set(config.get("tools", "enabled", default=[]) or [])
        for tid, spec in sorted(specs.items()):
            flag = "*" if tid in enabled else " "
            print(f"{flag} {tid:18} {spec.launcher:7} {', '.join(sorted(spec.languages)):40} {spec.repo or '-'}  [{spec.source}]")
        print("\n* = enabled in configuration")
        return 0
    if args.tools_cmd == "show":
        specs = load_specs(config)
        if args.tool not in specs:
            raise SystemExit(f"unknown tool {args.tool}")
        _print_json(specs[args.tool].to_dict())
        return 0
    docker = Docker(str(config.get("docker", "binary")), str(config.get("docker", "pull_policy")),
                    str(config.get("docker", "user")))
    if args.launcher:
        config.data.setdefault("tools", {})["default_launcher"] = args.launcher
    adapters = load_adapters(config, args.tool or None, docker)
    pins = _parse_pins(args.pin)
    results = {}
    for tid, adapter in adapters.items():
        try:
            version = adapter.resolve(pins.get(tid))
            if args.tools_cmd == "install":
                adapter.install(version, config.path("tools", "cache_dir") / tid / "install.log")
            results[tid] = version.to_dict()
            if not args.json:
                print(f"{tid:18} {version.version:14} tag={version.tag} commit={(version.commit or '')[:12]} "
                      f"launcher={version.launcher} source={version.source}")
                for n in version.notes:
                    print(f"    note: {n}")
        except Exception as exc:  # noqa: BLE001
            if not args.json:
                print(f"{tid:18} ERROR: {exc}")
            results[tid] = {"error": str(exc)}
    if args.json:
        _print_json(results)
    return 0 if all("error" not in r for r in results.values()) else 1


def cmd_run(args) -> int:
    from .evaluate import evaluate_run
    from .export import write_outputs
    from .runner import Runner
    config = _config(args)
    runner = Runner(config, tools=args.tool or None, cases=args.case or None, pins=_parse_pins(args.pin),
                    launcher=args.launcher, offline=args.offline, run_id=args.run_id, skip_install=args.skip_install,
                    keep_going=None if not args.fail_fast else False)
    run_dir = runner.execute()
    print(f"run directory: {run_dir}")
    if args.no_evaluate:
        return 0
    doc = evaluate_run(run_dir, config)
    paths = write_outputs(doc, run_dir, config)
    _print_summary(doc)
    for k, p in paths.items():
        print(f"  {k:16} {p}")
    return 0


def cmd_evaluate(args) -> int:
    from .evaluate import evaluate_run
    from .export import write_outputs
    config = _config(args)
    run_dir = _run_dir(config, args.run)
    doc = evaluate_run(run_dir, config, baseline_override=Path(args.baseline) if args.baseline else None)
    paths = write_outputs(doc, run_dir, config)
    _print_summary(doc)
    for k, p in paths.items():
        print(f"  {k:16} {p}")
    return 0


def _print_summary(doc: dict) -> None:
    print()
    print(f"{'tool':18} {'version':14} {'score':>6} {'recall':>7} {'prec':>6} {'compl':>6} {'corr':>6} {'loc':>6}  FPs")
    for tool, s in sorted((doc.get("summary") or {}).items()):
        ver = (doc.get("tools", {}).get(tool) or {}).get("version") or "?"
        fmt = lambda v: "   –" if v is None else f"{100 * v:5.0f}%"  # noqa: E731
        print(f"{tool:18} {str(ver)[:14]:14} {('%.3f' % s['score']) if s.get('score') is not None else '    –':>6} "
              f"{fmt(s.get('recall')):>7} {fmt(s.get('precision')):>6} {fmt(s.get('completeness')):>6} "
              f"{fmt(s.get('correctness')):>6} {fmt(s.get('locality')):>6}  {s.get('falsePositives')}")
    print()


def cmd_report(args) -> int:
    from .export.report import render_report
    from .reconcile import Scorecard
    config = _config(args)
    run_dir = _run_dir(config, args.run)
    sc = Scorecard.load(run_dir)
    if args.format == "json":
        _print_json({"summary": sc.doc.get("summary"), "tools": sc.tools, "baseline": sc.baseline})
    else:
        print(render_report(sc.doc))
    return 0


def cmd_export(args) -> int:
    from .export import build_priors, build_tools_json
    from .reconcile import Scorecard
    config = _config(args)
    run_dir = _run_dir(config, args.run)
    sc = Scorecard.load(run_dir)
    if args.what == "twocbom":
        data = build_tools_json(sc.doc, **(config.get("export", "twocbom", default={}) or {}),
                                include_tools=args.tool or None)
    else:
        data = build_priors(sc.doc)
    text = json.dumps(data, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


def cmd_reconcile(args) -> int:
    from .reconcile import Scorecard
    config = _config(args)
    sc = Scorecard.load(_run_dir(config, args.run))
    for tool in (args.tool_a, args.tool_b):
        if tool not in sc.tool_ids():
            raise SystemExit(f"unknown tool {tool!r}; scorecard has: {', '.join(sc.tool_ids())}")
    result = sc.reconcile(args.tool_a, args.tool_b, args.category, args.attribute, args.value_a, args.value_b)
    if args.json:
        _print_json(result.to_dict())
    else:
        d = result.to_dict()
        print(f"{args.tool_a} ({d['toolVersions'].get(args.tool_a)}) vs {args.tool_b} ({d['toolVersions'].get(args.tool_b)})"
              f"  attribute={d['attribute'] or '*'}  category={args.category or '*'}")
        print(f"decision: {d['decision']}  preferred: {d['preferred']}  confidence: {d['confidence']:.3f}  "
              f"weights: {d['weights']}")
        print(f"evidence tier: {d['tier']}  category used: {d['categoryUsed'] or '*'}  backoff steps: {d['backoffSteps']}")
        for e in d["explanation"]:
            print(f"  - {e}")
        if d.get("valueEvidence"):
            print(f"  value evidence: {json.dumps(d['valueEvidence'])}")
    return 0


def cmd_runs(args) -> int:
    from .runner import load_manifest
    config = _config(args)
    root = config.path("results", "dir")
    if args.runs_cmd == "list":
        if not root.exists():
            print("no runs")
            return 0
        for d in sorted(p for p in root.iterdir() if p.is_dir() and not p.is_symlink() and (p / "manifest.json").exists()):
            m = load_manifest(d)
            tools = ", ".join(f"{t}@{v.get('version')}" for t, v in (m.get("tools") or {}).items())
            print(f"{d.name:24} {m.get('finishedAt') or 'running':22} baseline={str(m.get('baseline', {}).get('commit'))[:10]} "
                  f"{tools}")
        return 0
    from .reconcile import Scorecard
    a = Scorecard.load(_run_dir(config, args.run_a))
    b = Scorecard.load(_run_dir(config, args.run_b))
    print(f"{'tool':18} {'run A version':16} {'run B version':16} {'score A':>8} {'score B':>8} {'delta':>7}")
    for tool in sorted(set(a.tool_ids()) | set(b.tool_ids())):
        sa, sb = (a.overall(tool) or {}).get("score"), (b.overall(tool) or {}).get("score")
        delta = "" if sa is None or sb is None else f"{sb - sa:+.3f}"
        print(f"{tool:18} {str(a.version_of(tool) or '–')[:16]:16} {str(b.version_of(tool) or '–')[:16]:16} "
              f"{('%.3f' % sa) if sa is not None else '–':>8} {('%.3f' % sb) if sb is not None else '–':>8} {delta:>7}")
    return 0


def cmd_normalize(args) -> int:
    from .normalize import read_cbom_file
    norm = read_cbom_file(args.file)
    data = norm.summary()
    if args.verbose:
        data["detections"] = [d.to_dict() for d in norm.detections]
        data["warnings"] = norm.warnings
    _print_json(data)
    return 0


# ----------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="orchestrator", description="Benchmark CBOM generators against cbomfuse/baseline "
                                "and produce per-category reliability priors for 2CBOM.")
    p.add_argument("--version", action="version", version=f"cbom-orchestrator {__version__}")
    p.add_argument("-c", "--config", help="path to orchestrator.yaml (default: ./orchestrator.yaml)")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v for info, -vv for debug")
    p.add_argument("--results-dir", help="override results.dir")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="write a default orchestrator.yaml")
    s.add_argument("path", nargs="?")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("baseline", help="manage the ground-truth corpus checkout")
    bs = s.add_subparsers(dest="baseline_cmd", required=True)
    for name, help_ in (("sync", "clone or update the corpus"), ("cases", "list discovered cases"), ("info", "corpus statistics")):
        sp = bs.add_parser(name, help=help_)
        sp.add_argument("--sync", action="store_true", help="fetch before listing")
        sp.add_argument("--baseline-ref", help="override baseline.ref")
        sp.add_argument("--baseline-repo", help="override baseline.repo (URL or local path)")
    s.set_defaults(func=cmd_baseline)

    s = sub.add_parser("tools", help="list, resolve or install tool adapters")
    ts = s.add_subparsers(dest="tools_cmd", required=True)
    sp = ts.add_parser("list", help="list known tool specs")
    sp = ts.add_parser("show", help="print one tool spec")
    sp.add_argument("tool")
    for name, help_ in (("resolve", "resolve the newest version of each tool"), ("install", "resolve and install")):
        sp = ts.add_parser(name, help=help_)
        sp.add_argument("tool", nargs="*")
        sp.add_argument("--pin", action="append", help="tool=version")
        sp.add_argument("--launcher", choices=["docker", "local"])
        sp.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_tools)

    s = sub.add_parser("run", help="run the benchmark (sync baseline, resolve/install tools, scan, evaluate)")
    s.add_argument("--tool", action="append", help="tool id (repeatable; default: tools.enabled)")
    s.add_argument("--case", action="append", help="case id or language (repeatable; default: all)")
    s.add_argument("--pin", action="append", help="tool=version (repeatable)")
    s.add_argument("--launcher", choices=["docker", "local"])
    s.add_argument("--offline", action="store_true", help="do not fetch the baseline")
    s.add_argument("--skip-install", action="store_true", help="assume tools are installed/pulled")
    s.add_argument("--run-id", help="name of the run directory")
    s.add_argument("--fail-fast", action="store_true")
    s.add_argument("--no-evaluate", action="store_true")
    s.add_argument("--baseline-ref", help="override baseline.ref")
    s.add_argument("--baseline-repo", help="override baseline.repo (URL or local path)")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("evaluate", help="(re)score an existing run directory")
    s.add_argument("run", help="run directory or run id")
    s.add_argument("--baseline", help="score against this baseline checkout instead of the recorded one")
    s.set_defaults(func=cmd_evaluate)

    s = sub.add_parser("report", help="print the Markdown report of a run")
    s.add_argument("run")
    s.add_argument("--format", choices=["md", "json"], default="md")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("export", help="export 2CBOM knowledge files")
    s.add_argument("what", choices=["twocbom", "priors"])
    s.add_argument("run")
    s.add_argument("--out", help="output file (default: stdout)")
    s.add_argument("--tool", action="append")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("reconcile", help="which of two tools to trust for a category/attribute, with confidence")
    s.add_argument("run", help="run directory, run id, scorecard.json or priors.json")
    s.add_argument("--tool-a", required=True)
    s.add_argument("--tool-b", required=True)
    s.add_argument("--category", default="", help="facets, e.g. 'language=Java;subtype=hash'")
    s.add_argument("--attribute", help="e.g. mode, parameterSetIdentifier, cryptoFunctions, identity")
    s.add_argument("--value-a", help="the value tool A asserted (optional)")
    s.add_argument("--value-b", help="the value tool B asserted (optional)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_reconcile)

    s = sub.add_parser("runs", help="list or compare runs")
    rs = s.add_subparsers(dest="runs_cmd", required=True)
    rs.add_parser("list")
    sp = rs.add_parser("diff", help="compare overall scores of two runs")
    sp.add_argument("run_a")
    sp.add_argument("run_b")
    s.set_defaults(func=cmd_runs)

    s = sub.add_parser("normalize", help="show how a CBOM file is lifted to the detection model")
    s.add_argument("file")
    s.add_argument("--verbose", action="store_true", dest="verbose_norm")
    s.set_defaults(func=cmd_normalize)
    return p


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    level = logging.WARNING - 10 * min(int(args.verbose or 0), 2)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    if args.command == "normalize":
        args.verbose = args.verbose_norm
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
