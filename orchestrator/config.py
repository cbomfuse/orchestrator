"""Configuration: defaults merged with ``orchestrator.yaml`` and command-line overrides."""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Optional

import yaml

DEFAULT_CONFIG: dict = {
    "baseline": {
        "repo": "https://github.com/cbomfuse/baseline.git",
        "ref": "main",
        # Where the corpus is checked out.  Relative paths are resolved against the project root.
        "path": ".orchestrator/baseline",
        "include_cases": [],
        "exclude_cases": [],
        "exclude_dirs": ["_tooling"],
        "ground_truth_file": "ground-truth.json",
        "reference_cbom_file": "cbom.cdx.json",
    },
    "tools": {
        "dir": "tools.d",
        "enabled": ["cbomkit", "cdxgen", "cryptobom-forge"],
        "pins": {},
        "default_launcher": None,
        "cache_dir": ".orchestrator/cache",
    },
    "results": {
        "dir": "results",
        "keep_workspaces": False,
        "latest_symlink": True,
    },
    "github": {
        "api": "https://api.github.com",
        "token_env": "GITHUB_TOKEN",
        "allow_prerelease": False,
    },
    "docker": {
        "binary": "docker",
        "pull_policy": "missing",   # always | missing | never
        "user": "current",          # current | image | "<uid>:<gid>"
        "extra_args": [],
    },
    "run": {
        "timeout_seconds": 1800,
        "keep_going": True,
    },
    "scoring": {
        "weights": {
            "recall": 0.35,
            "precision": 0.15,
            "completeness": 0.15,
            "correctness": 0.25,
            "locality": 0.10,
        },
        "line_tolerance": 1,
        "min_support": 5,
        "min_support_head_to_head": 3,
        "strength_threshold": 0.80,
        "strength_min_support": 5,
        "treat_failed_as_zero": False,
        "undecided_below": 0.60,
        "backoff_relevance_decay": 0.15,
        "shrinkage_prior_weight": 5,
        "attribute_weights": {},
    },
    "export": {
        "twocbom": {"trust_floor": 20, "trust_ceiling": 95, "default_trust": 50},
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class Config:
    """A merged configuration plus the project root used to resolve relative paths."""

    def __init__(self, data: dict, root: Path, source: Optional[Path] = None):
        self.data = data
        self.root = root
        self.source = source

    # -- convenience accessors -------------------------------------------------
    def get(self, *keys: str, default: Any = None) -> Any:
        cur: Any = self.data
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur

    def path(self, *keys: str) -> Path:
        value = self.get(*keys)
        if value is None:
            raise KeyError("/".join(keys))
        p = Path(os.path.expanduser(str(value)))
        return p if p.is_absolute() else (self.root / p)

    @property
    def github_token(self) -> Optional[str]:
        env = self.get("github", "token_env", default="GITHUB_TOKEN")
        return os.environ.get(env) or None

    def to_dict(self) -> dict:
        return copy.deepcopy(self.data)

    # -- loading ---------------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[str | os.PathLike] = None, overrides: Optional[dict] = None) -> "Config":
        candidates = []
        if path:
            candidates.append(Path(path))
        if os.environ.get("ORCHESTRATOR_CONFIG"):
            candidates.append(Path(os.environ["ORCHESTRATOR_CONFIG"]))
        candidates.append(Path.cwd() / "orchestrator.yaml")
        source = next((c for c in candidates if c.is_file()), None)
        data = copy.deepcopy(DEFAULT_CONFIG)
        root = Path.cwd()
        if source is not None:
            with open(source, "r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            if not isinstance(loaded, dict):
                raise ValueError(f"{source}: top level must be a mapping")
            data = _deep_merge(data, loaded)
            root = source.resolve().parent
        if overrides:
            data = _deep_merge(data, overrides)
        return cls(data, root, source)

    @classmethod
    def defaults(cls, root: Optional[Path] = None) -> "Config":
        return cls(copy.deepcopy(DEFAULT_CONFIG), root or Path.cwd())


def default_config_yaml() -> str:
    """The commented default configuration written by ``orchestrator init``."""
    return """# cbom-orchestrator configuration.  Every key is optional; defaults are shown.
baseline:
  repo: https://github.com/cbomfuse/baseline.git
  ref: main                     # branch, tag or commit SHA of the ground-truth corpus
  path: .orchestrator/baseline  # where the corpus is checked out (relative to this file)
  include_cases: []             # e.g. [Python, Java]; empty = every directory with a ground-truth.json
  exclude_cases: []
  exclude_dirs: [_tooling]

tools:
  dir: tools.d                  # one YAML spec per CBOM generator (see docs/adding-a-tool.md)
  enabled: [cbomkit, cdxgen, cryptobom-forge]
  pins: {}                      # pin a tool to a version, e.g. {cdxgen: v13.7.0}; otherwise newest release
  default_launcher: null        # docker | local | null (= each tool's own default)
  cache_dir: .orchestrator/cache

results:
  dir: results                  # one sub-directory per run
  keep_workspaces: false        # keep the per-(tool, case) scan copies after a run

github:
  api: https://api.github.com
  token_env: GITHUB_TOKEN       # set the variable to lift the unauthenticated API rate limit
  allow_prerelease: false

docker:
  binary: docker
  pull_policy: missing          # always | missing | never
  user: current                 # run containers as the invoking user so outputs are not root-owned

run:
  timeout_seconds: 1800
  keep_going: true              # continue with the next (tool, case) pair after a failure

scoring:
  weights: {recall: 0.35, precision: 0.15, completeness: 0.15, correctness: 0.25, locality: 0.10}
  line_tolerance: 1             # a reported line within +/- N lines of a ground-truth span counts
  min_support: 5                # minimum ground-truth items before a category score is used
  min_support_head_to_head: 3
  strength_threshold: 0.80      # attribute correctness needed to list an attribute as a 2CBOM strength
  strength_min_support: 5
  treat_failed_as_zero: false   # count crashed scans as "detected nothing" instead of "no evidence"
  undecided_below: 0.60         # reconcile() reports "undecided" below this confidence
  backoff_relevance_decay: 0.15
  shrinkage_prior_weight: 5

export:
  twocbom: {trust_floor: 20, trust_ceiling: 95, default_trust: 50}
"""
