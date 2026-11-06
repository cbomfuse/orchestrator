"""Tool registry.

Specs are YAML files.  Built-ins ship inside the package (``orchestrator/data/tools``); the project's
``tools.d/`` directory (``tools.dir`` in the configuration) adds new tools or overrides a built-in with
the same ``id``.  ``adapter:`` names the Python class that runs the spec; it defaults to the generic
command adapter, so a new tool is usually one YAML file.
"""
from __future__ import annotations

import importlib
import logging
from importlib import resources
from pathlib import Path
from typing import Optional

import yaml

from ..config import Config
from .base import ToolAdapter, ToolRunResult, ToolSpec, ToolVersion

log = logging.getLogger("orchestrator.tools")

__all__ = ["ToolAdapter", "ToolRunResult", "ToolSpec", "ToolVersion", "load_specs", "make_adapter", "load_adapters"]


def builtin_spec_dir() -> Path:
    return Path(str(resources.files("orchestrator").joinpath("data", "tools")))


def _load_dir(path: Path, specs: dict, origin: str) -> None:
    if not path.is_dir():
        return
    for f in sorted(path.glob("*.y*ml")):
        if f.name.endswith(".disabled"):
            continue
        with open(f, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if isinstance(data, dict) and data.get("disabled"):
            continue
        try:
            spec = ToolSpec.from_dict(data, source=f"{origin}:{f.name}")
        except ValueError as exc:
            log.warning("skipping %s: %s", f, exc)
            continue
        if spec.id in specs:
            log.info("tool %s from %s overrides %s", spec.id, spec.source, specs[spec.id].source)
        specs[spec.id] = spec


def load_specs(config: Config, include_builtin: bool = True) -> dict:
    specs: dict = {}
    if include_builtin:
        _load_dir(builtin_spec_dir(), specs, "builtin")
    user_dir = config.path("tools", "dir")
    _load_dir(user_dir, specs, "tools.d")
    return specs


def make_adapter(spec: ToolSpec, config: Config, docker=None) -> ToolAdapter:
    module_name, _, class_name = (spec.adapter or "orchestrator.tools.generic:CommandToolAdapter").partition(":")
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name or "CommandToolAdapter")
    if not issubclass(cls, ToolAdapter):
        raise TypeError(f"{spec.adapter} is not a ToolAdapter")
    return cls(spec, config, docker)


def load_adapters(config: Config, only: Optional[list] = None, docker=None) -> dict:
    specs = load_specs(config)
    enabled = list(only) if only else list(config.get("tools", "enabled", default=[]) or [])
    adapters: dict = {}
    for tool_id in enabled:
        if tool_id not in specs:
            raise KeyError(f"unknown tool {tool_id!r}; known: {', '.join(sorted(specs)) or '(none)'}")
        adapters[tool_id] = make_adapter(specs[tool_id], config, docker)
    return adapters
