"""cryptobom-forge needs a CodeQL SARIF file first, so its adapter is a three-step pipeline:

1. ``codeql database create`` on the case workspace (``--build-mode=none`` for Java/C#),
2. ``codeql database analyze`` with the cryptography inventory queries that exist for the language,
3. ``cryptobom generate`` on the SARIF output.

Both the forge version (GitHub release of ``santandersecurityresearch/cryptobom-forge``) and the
CodeQL bundle (``github/codeql-action`` ``codeql-bundle-v*`` tags, which ship the CLI *and* the query
packs) are resolved to their newest versions and recorded, because the inventory queries -- not the
forge -- decide what gets detected.

Spec options (``options:`` in the YAML)::

    codeql:
      bundle_repo: https://github.com/github/codeql-action
      bundle_tag_pattern: "^codeql-bundle-v"
      binary: null              # use an existing `codeql` instead of downloading the bundle
      queries:                  # per corpus language, directories inside the language query pack
        Python: [experimental/cryptography/inventory/new_models]
        Java:   [experimental/quantum/InventorySlices]
      build_mode: {Java: none, "C#": none}
      threads: 0
    forge:
      extra_args: []            # appended to `cryptobom generate`
"""
from __future__ import annotations

import glob
import json
import logging
import os
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Optional

from .. import github
from ..baseline import Case
from ..process import run_command, which
from .base import ToolAdapter, ToolRunResult, ToolVersion, host_platform

log = logging.getLogger("orchestrator.tools.cryptobom_forge")

CODEQL_LANGUAGES = {"python": "python", "java": "java", "go": "go", "typescript": "javascript", "javascript": "javascript",
                    "c#": "csharp", "csharp": "csharp", "c": "cpp", "c++": "cpp", "cpp": "cpp", "ruby": "ruby",
                    "swift": "swift", "kotlin": "java", "rust": "rust"}

DEFAULT_QUERIES = {
    "Python": ["experimental/cryptography/inventory/new_models"],
    "Java": ["experimental/quantum/InventorySlices"],
}
DEFAULT_BUILD_MODE = {"Java": "none", "C#": "none", "CSharp": "none"}

FORGE_DEPENDENCIES = [
    "click>=8.0.0", "jsonschema>=2.0.0", "pyyaml>=3.10", "requests>=2.3.0",
    "cyclonedx-python-lib @ git+https://github.com/pre-quantum-research/cyclonedx-python-lib.git@cbom",
]


class CryptobomForgeAdapter(ToolAdapter):
    def __init__(self, spec, config, docker=None):
        super().__init__(spec, config, docker)
        self.launcher = "local"
        opts = spec.options or {}
        self.codeql_opts: dict = dict(opts.get("codeql") or {})
        self.forge_opts: dict = dict(opts.get("forge") or {})
        self.queries: dict = dict(DEFAULT_QUERIES)
        self.queries.update(self.codeql_opts.get("queries") or {})
        self.build_mode: dict = dict(DEFAULT_BUILD_MODE)
        self.build_mode.update(self.codeql_opts.get("build_mode") or {})

    # ------------------------------------------------------------------ paths
    @property
    def forge_root(self) -> Path:
        return self.cache_dir / "forge"

    def venv_dir(self, version: ToolVersion) -> Path:
        return self.forge_root / version.version / "venv"

    def venv_bin(self, version: ToolVersion, name: str) -> Path:
        sub = "Scripts" if os.name == "nt" else "bin"
        return self.venv_dir(version) / sub / (name + (".exe" if os.name == "nt" else ""))

    def codeql_root(self, bundle_version: str) -> Path:
        return self.cache_dir / "codeql" / bundle_version

    def codeql_binary(self, version: ToolVersion) -> Optional[Path]:
        configured = self.codeql_opts.get("binary")
        if configured:
            p = Path(str(configured)).expanduser()
            found = which(str(p)) if not p.exists() else str(p)
            return Path(found) if found else None
        bundle = (version.components.get("codeql") or {}).get("version")
        if not bundle:
            return None
        root = self.codeql_root(bundle) / "codeql"
        exe = root / ("codeql.exe" if os.name == "nt" else "codeql")
        return exe if exe.exists() else None

    # ------------------------------------------------------------------ version
    def resolve(self, pin: Optional[str] = None) -> ToolVersion:
        pin = pin or self.config.get("tools", "pins", default={}).get(self.spec.id)
        vs = self.spec.versioning or {}
        rv = github.resolve(self.spec.repo, str(vs.get("strategy") or "release"), pin=pin,
                            branch=str(vs.get("branch") or "main"), token=self.config.github_token,
                            api=str(self.config.get("github", "api")))
        tv = ToolVersion.from_resolved(self.spec.id, self.spec.name, rv, "local")
        tv.components["python"] = sys.version.split()[0]
        if self.codeql_opts.get("binary"):
            tv.components["codeql"] = {"source": "configured-binary", "binary": str(self.codeql_opts["binary"])}
        else:
            bundle_repo = str(self.codeql_opts.get("bundle_repo") or "https://github.com/github/codeql-action")
            pattern = str(self.codeql_opts.get("bundle_tag_pattern") or r"^codeql-bundle-v")
            bpin = self.config.get("tools", "pins", default={}).get("codeql") or self.codeql_opts.get("bundle_version")
            brv = github.resolve(bundle_repo, "tag", pin=bpin, token=self.config.github_token,
                                 api=str(self.config.get("github", "api")), tag_pattern=pattern)
            tv.components["codeql"] = {"source": "bundle", "repo": brv.repo, "tag": brv.tag, "version": brv.version,
                                       "commit": brv.commit, "resolvedAt": brv.resolved_at}
        return tv

    # ------------------------------------------------------------------ install
    def install(self, version: ToolVersion, log_path: Optional[Path] = None) -> None:
        self._install_forge(version, log_path)
        self._install_codeql(version, log_path)

    def _install_forge(self, version: ToolVersion, log_path: Optional[Path]) -> None:
        venv = self.venv_dir(version)
        cryptobom = self.venv_bin(version, "cryptobom")
        if cryptobom.exists():
            version.notes.append(f"cryptobom-forge {version.version} already installed in {venv}")
        else:
            venv.parent.mkdir(parents=True, exist_ok=True)
            res = run_command([sys.executable, "-m", "venv", str(venv)], timeout=600, log_path=log_path)
            if not res.ok:
                raise RuntimeError(f"venv creation failed: {res.summary(400)}")
            pip = self.venv_bin(version, "pip")
            steps = [
                [str(pip), "install", "--quiet", "--upgrade", "pip"],
                [str(pip), "install", "--quiet", *FORGE_DEPENDENCIES],
                [str(pip), "install", "--quiet", "--no-deps",
                 f"git+{github.normalize_repo(self.spec.repo)}.git@{version.tag or version.commit}"],
            ]
            for argv in steps:
                res = run_command(argv, timeout=1800, log_path=log_path)
                if not res.ok:
                    shutil.rmtree(venv, ignore_errors=True)
                    raise RuntimeError(f"cryptobom-forge install failed: {' '.join(argv)}\n{res.summary(800)}")
        res = run_command([str(cryptobom), "--version"], timeout=120, log_path=log_path)
        if res.ok:
            version.components["forge"] = {"reportedVersion": (res.stdout or res.stderr).strip()[:100]}

    def _install_codeql(self, version: ToolVersion, log_path: Optional[Path]) -> None:
        info = version.components.get("codeql") or {}
        if info.get("source") == "configured-binary":
            exe = self.codeql_binary(version)
            if exe is None:
                raise RuntimeError(f"configured codeql binary {info.get('binary')} not found")
        else:
            tag, ver = info["tag"], info["version"]
            root = self.codeql_root(ver)
            exe = root / "codeql" / ("codeql.exe" if os.name == "nt" else "codeql")
            if not exe.exists():
                plat = host_platform()
                if plat.endswith("arm64"):
                    version.notes.append(f"no CodeQL bundle for {plat}; trying the x86-64 bundle")
                    plat = plat.replace("-arm64", "64").replace("arm64", "64")
                asset = f"codeql-bundle-{plat}.tar.gz" if plat != "win64" else "codeql-bundle-win64.tar.gz"
                url = github.release_asset_url(info["repo"], tag, asset)
                archive = self.cache_dir / "downloads" / f"{tag}-{asset}"
                if not archive.exists():
                    github.download(url, archive, timeout=3600)
                root.mkdir(parents=True, exist_ok=True)
                log.info("extracting %s to %s", archive, root)
                if archive.suffix == ".zip":
                    with zipfile.ZipFile(archive) as zf:
                        zf.extractall(root)
                else:
                    with tarfile.open(archive) as tf:
                        try:
                            tf.extractall(root, filter="data")
                        except TypeError:  # Python < 3.12
                            tf.extractall(root)
                if not exe.exists():
                    raise RuntimeError(f"CodeQL bundle extracted but {exe} is missing")
        res = run_command([str(exe), "version", "--format=json"], timeout=300, log_path=log_path)
        if res.ok:
            try:
                data = json.loads(res.stdout)
                version.components["codeql"] = {**info, "cliVersion": data.get("version"), "binary": str(exe)}
            except json.JSONDecodeError:
                version.components["codeql"] = {**info, "binary": str(exe)}
        # query pack versions (bundle ships them under qlpacks/codeql/<lang>-queries/<version>)
        packs = {}
        for lang_dir in self._query_pack_dirs(exe):
            packs[lang_dir.parent.name] = lang_dir.name
        if packs:
            version.components["queryPacks"] = packs

    def _query_pack_dirs(self, exe: Path) -> list:
        base = exe.parent / "qlpacks" / "codeql"
        out = []
        if base.is_dir():
            for pack in sorted(base.glob("*-queries")):
                versions = sorted(p for p in pack.iterdir() if p.is_dir())
                if versions:
                    out.append(versions[-1])
        return out

    # ------------------------------------------------------------------ run
    def _codeql_language(self, case: Case) -> Optional[str]:
        entry = self.spec.language_entry(case) or {}
        if entry.get("value"):
            return str(entry["value"])
        return CODEQL_LANGUAGES.get(case.language.lower()) or CODEQL_LANGUAGES.get(case.id.lower())

    def _query_paths(self, exe: Path, case: Case, codeql_lang: str) -> tuple[list, list]:
        """Resolve configured query directories to absolute paths inside the bundle (or pack specifiers)."""
        configured = self.queries.get(case.language) or self.queries.get(case.id) or []
        if not configured:
            return [], []
        notes = []
        pack_root = None
        for d in self._query_pack_dirs(exe):
            if d.parent.name == f"{codeql_lang}-queries":
                pack_root = d
        paths = []
        for q in configured:
            q = str(q)
            if Path(q).is_absolute() and Path(q).exists():
                paths.append(q)
            elif pack_root is not None and (pack_root / q).exists():
                paths.append(str(pack_root / q))
            elif pack_root is None:
                paths.append(f"codeql/{codeql_lang}-queries:{q}")
                notes.append(f"using pack specifier for {q} (no bundle pack directory found)")
            else:
                notes.append(f"query path {q} not found in {pack_root}; skipped")
        return paths, notes

    def run(self, case: Case, workdir: Path, version: ToolVersion, out_dir: Path, log_path: Path) -> ToolRunResult:
        if not self.supports(case):
            return ToolRunResult("unsupported", notes=[f"no language entry for {case.language}"])
        codeql_lang = self._codeql_language(case)
        if not codeql_lang:
            return ToolRunResult("unsupported", notes=[f"no CodeQL language for {case.language}"])
        exe = self.codeql_binary(version)
        if exe is None:
            return ToolRunResult("failed", notes=["codeql binary not installed; run `orchestrator tools install cryptobom-forge`"])
        queries, notes = self._query_paths(exe, case, codeql_lang)
        if not queries:
            return ToolRunResult("unsupported", notes=[f"no cryptography inventory queries configured/available for "
                                                      f"{case.language}"] + notes)
        cryptobom = self.venv_bin(version, "cryptobom")
        if not cryptobom.exists():
            return ToolRunResult("failed", notes=["cryptobom-forge venv missing; run `orchestrator tools install cryptobom-forge`"])

        scratch = workdir.parent / f"{workdir.name}.codeql"
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True, exist_ok=True)
        db = scratch / "db"
        sarif_dir = scratch / "sarif"
        sarif_dir.mkdir()
        timeout = self.timeout()
        env = {"CODEQL_ALLOW_INSTALLATION_ANYWHERE": "true"}
        commands = []

        create = [str(exe), "database", "create", str(db), f"--language={codeql_lang}", f"--source-root={workdir}",
                  "--overwrite"]
        mode = self.build_mode.get(case.language) or self.build_mode.get(case.id)
        if mode:
            create.append(f"--build-mode={mode}")
        for extra in self.codeql_opts.get("create_args") or []:
            create.append(str(extra))
        res = run_command(create, cwd=workdir, env=env, timeout=timeout, log_path=log_path)
        commands.append(res.argv)
        if not res.ok:
            return ToolRunResult("timeout" if res.timed_out else "failed", None, res.returncode, res.duration_seconds,
                                 Path(res.log_path) if res.log_path else None, commands,
                                 notes + [f"codeql database create failed: {res.summary(300)}"])
        duration = res.duration_seconds

        sarif = sarif_dir / "crypto.sarif"
        analyze = [str(exe), "database", "analyze", str(db), *queries, "--format=sarif-latest", f"--output={sarif}",
                   "--sarif-add-snippets", f"--threads={self.codeql_opts.get('threads', 0)}", "--rerun"]
        for extra in self.codeql_opts.get("analyze_args") or []:
            analyze.append(str(extra))
        res = run_command(analyze, cwd=workdir, env=env, timeout=timeout, log_path=log_path)
        commands.append(res.argv)
        duration += res.duration_seconds
        if not res.ok or not sarif.exists():
            return ToolRunResult("timeout" if res.timed_out else "failed", None, res.returncode, duration,
                                 Path(res.log_path) if res.log_path else None, commands,
                                 notes + [f"codeql database analyze failed: {res.summary(300)}"])
        out_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sarif, out_dir / "crypto.sarif")

        output = workdir / "cbom.json"
        gen = [str(cryptobom), "generate", str(sarif_dir), "-o", str(output), "-n", case.id,
               *[str(a) for a in self.forge_opts.get("extra_args") or []]]
        res = run_command(gen, cwd=workdir, timeout=timeout, log_path=log_path)
        commands.append(res.argv)
        duration += res.duration_seconds
        if not output.exists():
            return ToolRunResult("timeout" if res.timed_out else "failed", None, res.returncode, duration,
                                 Path(res.log_path) if res.log_path else None, commands,
                                 notes + [f"cryptobom generate produced no output: {res.summary(300)}"])
        dest = out_dir / "cbom.json"
        shutil.copy2(output, dest)
        status = "ok"
        try:
            with open(dest, "r", encoding="utf-8") as fh:
                if not (json.load(fh).get("components") or []):
                    status = "empty"
        except (OSError, json.JSONDecodeError) as exc:
            status = "failed"
            notes.append(f"cbom.json is not valid JSON: {exc}")
        if not self.config.get("results", "keep_workspaces"):
            shutil.rmtree(scratch, ignore_errors=True)
        return ToolRunResult(status, dest, res.returncode, duration, Path(res.log_path) if res.log_path else None,
                             commands, notes, {"sarif": str(out_dir / "crypto.sarif"), "codeqlLanguage": codeql_lang,
                                               "queries": queries})
