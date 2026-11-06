"""The generic tool interface.

A *tool spec* (YAML) says what a CBOM generator is, where its GitHub repository lives, how to pick
its newest version, how to launch it (Docker image or local install) and which corpus languages it
supports.  An *adapter* turns the spec into actions: ``resolve`` the version, ``install`` it, ``run``
it on one case.  Most tools need no code at all -- the :class:`~orchestrator.tools.generic.CommandToolAdapter`
executes the spec -- and tools with a multi-step pipeline (cryptobom-forge needs CodeQL first)
subclass :class:`ToolAdapter`.
"""
from __future__ import annotations

import os
import platform
import shlex
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..baseline import Case
from ..config import Config
from ..github import ResolvedVersion, now_iso

STATUSES = ("ok", "empty", "failed", "timeout", "unsupported", "skipped", "install-failed")


@dataclass
class ToolSpec:
    id: str
    name: str
    repo: Optional[str]
    description: str = ""
    adapter: str = "orchestrator.tools.generic:CommandToolAdapter"
    versioning: dict = field(default_factory=lambda: {"strategy": "release", "branch": "main"})
    launcher: str = "docker"
    docker: dict = field(default_factory=dict)
    local: dict = field(default_factory=dict)
    languages: dict = field(default_factory=dict)
    output: str = "cbom.json"
    format: str = "auto"
    timeout_seconds: Optional[int] = None
    twocbom: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)
    source: Optional[str] = None
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict, source: Optional[str] = None) -> "ToolSpec":
        if not isinstance(data, dict) or not data.get("id"):
            raise ValueError(f"{source or 'tool spec'}: missing 'id'")
        known = {f for f in cls.__dataclass_fields__ if f not in ("raw", "source")}
        kwargs = {k: v for k, v in data.items() if k in known}
        kwargs.setdefault("name", data["id"])
        kwargs.setdefault("repo", None)
        if "twocbom" in kwargs and kwargs["twocbom"] is None:
            kwargs["twocbom"] = {}
        spec = cls(**kwargs)
        spec.raw = data
        spec.source = source
        for k in ("versioning", "docker", "local", "languages", "twocbom", "options"):
            if getattr(spec, k) is None:
                setattr(spec, k, {})
        return spec

    def language_entry(self, case: Case) -> Optional[dict]:
        """The per-language configuration for a case (by corpus language or by case directory name)."""
        for key in (case.language, case.id, case.language.lower(), case.id.lower()):
            if key in self.languages:
                entry = self.languages[key]
                if entry is None:
                    return {}
                if isinstance(entry, str):
                    return {"value": entry}
                return dict(entry)
        return None

    def supports(self, case: Case) -> bool:
        entry = self.language_entry(case)
        return entry is not None and not entry.get("unsupported")

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw", None)
        return d


@dataclass
class ToolVersion:
    """Everything that identifies *which* build of a tool was run."""
    tool: str
    name: str
    repo: Optional[str]
    strategy: str
    tag: Optional[str]
    version: str
    commit: Optional[str]
    resolved_at: str
    source: str
    url: Optional[str] = None
    launcher: str = "docker"
    image: Optional[str] = None
    image_digest: Optional[str] = None
    image_id: Optional[str] = None
    reported: Optional[dict] = None          # the name/version the tool wrote into its own CBOMs
    components: dict = field(default_factory=dict)   # sub-tool versions (CodeQL bundle, query packs ...)
    notes: list = field(default_factory=list)

    @classmethod
    def from_resolved(cls, tool: str, name: str, rv: ResolvedVersion, launcher: str) -> "ToolVersion":
        return cls(tool=tool, name=name, repo=rv.repo, strategy=rv.strategy, tag=rv.tag, version=rv.version,
                   commit=rv.commit, resolved_at=rv.resolved_at, source=rv.source, url=rv.url, launcher=launcher,
                   notes=list(rv.notes))

    @classmethod
    def fixed(cls, tool: str, name: str, version: str, launcher: str = "local", **kw) -> "ToolVersion":
        return cls(tool=tool, name=name, repo=kw.get("repo"), strategy="fixed", tag=kw.get("tag"), version=version,
                   commit=kw.get("commit"), resolved_at=now_iso(), source=kw.get("source", "fixed"), launcher=launcher,
                   notes=kw.get("notes", []))

    @property
    def label(self) -> str:
        return f"{self.tool}@{self.version}"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ToolVersion":
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class ToolRunResult:
    status: str
    output_path: Optional[Path] = None
    exit_code: Optional[int] = None
    duration_seconds: float = 0.0
    log_path: Optional[Path] = None
    command: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"status": self.status, "output": str(self.output_path) if self.output_path else None,
                "exitCode": self.exit_code, "durationSeconds": round(self.duration_seconds, 2),
                "log": str(self.log_path) if self.log_path else None,
                "command": [str(c) for c in self.command], "notes": self.notes, "extra": self.extra}


def host_platform() -> str:
    sysname = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "64"
    if sysname == "darwin":
        return f"osx{arch}" if arch == "64" else "osx-arm64"
    if sysname == "windows":
        return "win64"
    return f"linux{arch}" if arch == "64" else "linux-arm64"


def render(template: Any, variables: dict) -> Any:
    """Substitute ``{name}`` placeholders in strings, lists and dicts (unknown names are left intact)."""
    if isinstance(template, str):
        out = template
        for k, v in variables.items():
            out = out.replace("{" + k + "}", "" if v is None else str(v))
        return out
    if isinstance(template, list):
        return [render(x, variables) for x in template]
    if isinstance(template, dict):
        return {k: render(v, variables) for k, v in template.items()}
    return template


def as_argv(cmd: Any) -> list[str]:
    if cmd is None:
        return []
    if isinstance(cmd, str):
        return shlex.split(cmd)
    return [str(c) for c in cmd]


class ToolAdapter(ABC):
    """Base class.  Subclasses implement ``resolve``, ``install`` and ``run``."""

    def __init__(self, spec: ToolSpec, config: Config, docker=None):
        self.spec = spec
        self.config = config
        self.docker = docker
        self.cache_dir = config.path("tools", "cache_dir") / spec.id
        self.launcher = self._pick_launcher()

    def _pick_launcher(self) -> str:
        forced = self.config.get("tools", "default_launcher")
        if forced:
            return str(forced)
        return self.spec.launcher or "docker"

    @property
    def id(self) -> str:
        return self.spec.id

    def supports(self, case: Case) -> bool:
        return self.spec.supports(case)

    def timeout(self) -> int:
        return int(self.spec.timeout_seconds or self.config.get("run", "timeout_seconds", default=1800))

    def variables(self, version: Optional[ToolVersion] = None, case: Optional[Case] = None, workdir: Optional[Path] = None,
                  extra: Optional[dict] = None) -> dict:
        v = {
            "tool": self.spec.id, "cache": str(self.cache_dir), "home": str(Path.home()),
            "platform": host_platform(), "uid": getattr(os, "getuid", lambda: 0)(), "gid": getattr(os, "getgid", lambda: 0)(),
        }
        if version is not None:
            v.update({"version": version.version, "tag": version.tag or version.version, "commit": version.commit or ""})
        if case is not None:
            v.update({"case": case.id, "language_name": case.language, "source_file": case.source_file or ""})
            entry = self.spec.language_entry(case) or {}
            v["language"] = entry.get("value", "")
            for k, val in entry.items():
                if k != "value":
                    v[f"language_{k}"] = val
        if workdir is not None:
            v["workdir"] = str(workdir)
        if extra:
            v.update(extra)
        return v

    @abstractmethod
    def resolve(self, pin: Optional[str] = None) -> ToolVersion: ...

    @abstractmethod
    def install(self, version: ToolVersion, log_path: Optional[Path] = None) -> None: ...

    @abstractmethod
    def run(self, case: Case, workdir: Path, version: ToolVersion, out_dir: Path, log_path: Path) -> ToolRunResult: ...

    def describe(self) -> dict:
        return {"id": self.spec.id, "name": self.spec.name, "repo": self.spec.repo, "launcher": self.launcher,
                "languages": sorted(self.spec.languages), "adapter": self.spec.adapter, "source": self.spec.source}
