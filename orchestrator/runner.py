"""Execute the benchmark: resolve tool versions, install them, scan every case, record everything.

Layout of a run directory (``results/<run-id>/``)::

    manifest.json               what ran: baseline commit, tool versions, per-(tool, case) status
    raw/<tool>/<case>/          the CBOM the tool produced (and SARIF for cryptobom-forge)
    logs/<tool>/<case>.log      full command lines, stdout and stderr
    logs/<tool>/install.log
    work/<tool>/<case>/         scan workspaces (deleted unless results.keep_workspaces)
    scorecard.json, priors.json, report.md, twocbom/tools.json   (written by `evaluate`)
"""
from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import __version__
from .baseline import Case, discover_cases, sync_baseline
from .config import Config
from .docker import Docker
from .github import now_iso
from .tools import ToolAdapter, ToolRunResult, ToolVersion, load_adapters

log = logging.getLogger("orchestrator.runner")


def make_run_id(suffix: Optional[str] = None) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{suffix}" if suffix else stamp


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=False)
    tmp.replace(path)


def host_info() -> dict:
    return {"hostname": socket.gethostname(), "platform": platform.platform(), "python": sys.version.split()[0],
            "orchestrator": __version__}


def copy_case(case: Case, workdir: Path) -> None:
    if workdir.exists():
        shutil.rmtree(workdir)
    shutil.copytree(case.dir, workdir, ignore=shutil.ignore_patterns(".git", "node_modules", "target", "bin", "obj",
                                                                    "__pycache__", "cbom", "*.cdx.json", "ground-truth.json"))
    # keep the reference CBOM out of the workspace so tools cannot "find" it; ground-truth.json is
    # excluded above for the same reason


class Runner:
    def __init__(self, config: Config, *, tools: Optional[list] = None, cases: Optional[list] = None,
                 pins: Optional[dict] = None, launcher: Optional[str] = None, offline: bool = False,
                 run_id: Optional[str] = None, skip_install: bool = False, keep_going: Optional[bool] = None):
        self.config = config
        if pins:
            config.data.setdefault("tools", {}).setdefault("pins", {}).update(pins)
        if launcher:
            config.data.setdefault("tools", {})["default_launcher"] = launcher
        self.tool_filter = tools
        self.case_filter = cases
        self.offline = offline
        self.run_id = run_id or make_run_id()
        self.skip_install = skip_install
        self.keep_going = config.get("run", "keep_going", default=True) if keep_going is None else keep_going
        self.docker = Docker(str(config.get("docker", "binary")), str(config.get("docker", "pull_policy")),
                             str(config.get("docker", "user")), config.get("docker", "extra_args") or [])
        self.run_dir = config.path("results", "dir") / self.run_id
        self.manifest: dict = {}

    # ------------------------------------------------------------------ steps
    def prepare(self) -> tuple[list, dict]:
        checkout = sync_baseline(self.config, offline=self.offline)
        cases = discover_cases(checkout.path, self.config)
        if self.case_filter:
            wanted = set(self.case_filter)
            cases = [c for c in cases if c.id in wanted or c.language in wanted]
        if not cases:
            raise RuntimeError("no baseline cases selected")
        adapters = load_adapters(self.config, self.tool_filter, self.docker)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.manifest = {
            "runId": self.run_id, "startedAt": now_iso(), "finishedAt": None, "host": host_info(),
            "config": self.config.to_dict(), "baseline": {**checkout.to_dict(), "cases": [c.to_dict() for c in cases]},
            "tools": {}, "runs": [],
        }
        self._save()
        return cases, adapters

    def resolve_and_install(self, adapters: dict) -> dict:
        versions: dict[str, ToolVersion] = {}
        for tool_id, adapter in adapters.items():
            log_path = self.run_dir / "logs" / tool_id / "install.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                pin = (self.config.get("tools", "pins", default={}) or {}).get(tool_id)
                version = adapter.resolve(pin)
                log.info("%s -> %s (%s, %s)", tool_id, version.version, version.strategy, version.source)
            except Exception as exc:  # noqa: BLE001 - every failure must be recorded, not raised
                log.error("%s: version resolution failed: %s", tool_id, exc)
                version = ToolVersion.fixed(tool_id, adapter.spec.name, "unresolved", launcher=adapter.launcher,
                                            source="error", notes=[f"resolution failed: {exc}"])
                version.components["error"] = "resolve"
            if "error" not in version.components and not self.skip_install:
                try:
                    adapter.install(version, log_path)
                except Exception as exc:  # noqa: BLE001
                    log.error("%s: install failed: %s", tool_id, exc)
                    version.notes.append(f"install failed: {exc}")
                    version.components["error"] = "install"
            versions[tool_id] = version
            self.manifest["tools"][tool_id] = {**version.to_dict(), "spec": adapter.spec.to_dict()}
            self._save()
        return versions

    def run_all(self, cases: list, adapters: dict, versions: dict) -> None:
        keep = bool(self.config.get("results", "keep_workspaces"))
        for tool_id, adapter in adapters.items():
            version = versions[tool_id]
            for case in cases:
                record = {"tool": tool_id, "toolVersion": version.version, "case": case.id, "language": case.language,
                          "startedAt": now_iso()}
                out_dir = self.run_dir / "raw" / tool_id / case.id
                log_path = self.run_dir / "logs" / tool_id / f"{case.id}.log"
                log_path.parent.mkdir(parents=True, exist_ok=True)
                if "error" in version.components:
                    result = ToolRunResult("install-failed", notes=version.notes[-1:])
                elif not adapter.supports(case):
                    result = ToolRunResult("unsupported", notes=[f"{tool_id} does not support {case.language}"])
                else:
                    workdir = self.run_dir / "work" / tool_id / case.id
                    try:
                        copy_case(case, workdir)
                        log.info("running %s on %s", tool_id, case.id)
                        result = adapter.run(case, workdir, version, out_dir, log_path)
                    except Exception as exc:  # noqa: BLE001
                        log.exception("%s on %s crashed", tool_id, case.id)
                        result = ToolRunResult("failed", notes=[f"adapter crashed: {exc}"], log_path=log_path)
                        if not self.keep_going:
                            record.update(result.to_dict())
                            self.manifest["runs"].append(record)
                            self._save()
                            raise
                    finally:
                        if not keep:
                            shutil.rmtree(workdir, ignore_errors=True)
                            shutil.rmtree(workdir.parent / f"{workdir.name}.codeql", ignore_errors=True)
                record.update(result.to_dict())
                record["finishedAt"] = now_iso()
                if result.output_path:
                    record["output"] = os.path.relpath(result.output_path, self.run_dir)
                if result.log_path:
                    record["log"] = os.path.relpath(result.log_path, self.run_dir)
                log.info("%s on %s: %s (%.1fs)", tool_id, case.id, result.status, result.duration_seconds)
                self.manifest["runs"].append(record)
                self._save()
        self.manifest["finishedAt"] = now_iso()
        self._save()
        if not keep:
            shutil.rmtree(self.run_dir / "work", ignore_errors=True)

    def _save(self) -> None:
        _write_json(self.run_dir / "manifest.json", self.manifest)

    # ------------------------------------------------------------------ driver
    def execute(self) -> Path:
        cases, adapters = self.prepare()
        versions = self.resolve_and_install(adapters)
        self.run_all(cases, adapters, versions)
        latest = self.config.path("results", "dir") / "latest"
        if self.config.get("results", "latest_symlink", default=True):
            try:
                if latest.is_symlink() or latest.exists():
                    latest.unlink()
                latest.symlink_to(self.run_dir.name)
            except OSError:
                pass
        return self.run_dir


def load_manifest(run_dir: Path) -> dict:
    with open(Path(run_dir) / "manifest.json", "r", encoding="utf-8") as fh:
        return json.load(fh)
