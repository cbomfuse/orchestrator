"""cryptobom-forge needs a CodeQL SARIF file first, so its adapter is a three-step pipeline:

1. ``codeql database create`` on the case workspace (``--build-mode=none`` for Java/C#),
2. run the cryptography inventory queries and convert their results to SARIF (Java's experimental
   table queries require an explicit BQRS-to-SARIF conversion),
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
import re
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlsplit

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


def _query_metadata(query_path: Path) -> dict[str, str]:
    text = query_path.read_text(encoding="utf-8")
    doc = re.search(r"/\*\*(.*?)\*/", text, re.DOTALL)
    if not doc:
        return {}
    metadata = {}
    for line in doc.group(1).splitlines():
        line = re.sub(r"^\s*\*\s?", "", line).strip()
        if line.startswith("@"):
            key, _, value = line[1:].partition(" ")
            metadata[key] = value.strip()
    return metadata


def _add_sarif_context(sarif_path: Path, source_root: Path) -> None:
    with sarif_path.open("r", encoding="utf-8") as fh:
        sarif = json.load(fh)
    source_root = source_root.resolve()
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                physical = location.get("physicalLocation", {})
                if "contextRegion" in physical:
                    continue
                artifact = physical.get("artifactLocation", {})
                uri = artifact.get("uri")
                region = physical.get("region", {})
                if not uri or not region.get("startLine"):
                    raise ValueError(f"SARIF result has no source location in {sarif_path}")
                source_path = Path(uri)
                if not source_path.is_absolute():
                    source_path = source_root / source_path
                source_path = source_path.resolve()
                if not source_path.is_relative_to(source_root) or not source_path.is_file():
                    raise ValueError(f"SARIF source path is outside the workspace or missing: {uri}")
                lines = source_path.read_text(encoding="utf-8").splitlines(keepends=True)
                start_line = region["startLine"]
                end_line = region.get("endLine", start_line)
                if start_line > len(lines) or end_line > len(lines):
                    raise ValueError(f"SARIF source range is outside the file: {uri}:{start_line}-{end_line}")
                region.setdefault("startColumn", 1)
                if "endColumn" not in region:
                    region["endColumn"] = len(lines[end_line - 1].rstrip("\r\n")) + 1
                context_start = max(1, start_line - 2)
                context_end = min(len(lines), end_line + 2)
                physical["contextRegion"] = {
                    "startLine": context_start,
                    "endLine": context_end,
                    "snippet": {"text": "".join(lines[context_start - 1:context_end])},
                }
    with sarif_path.open("w", encoding="utf-8") as fh:
        json.dump(sarif, fh, ensure_ascii=False)


def _bqrs_entities_to_sarif(bqrs_json: Path, sarif_path: Path, source_root: Path, metadata: dict[str, str],
                            codeql_version: str) -> None:
    with bqrs_json.open("r", encoding="utf-8") as fh:
        result_set = json.load(fh).get("#select", {})
    tuples = result_set.get("tuples")
    if not isinstance(tuples, list):
        raise ValueError(f"BQRS output has no #select tuples: {bqrs_json}")

    source_root = source_root.resolve()
    query_id = metadata.get("id")
    if not query_id:
        raise ValueError(f"CodeQL query has no @id: {metadata.get('name', bqrs_json.name)}")
    results = []
    for row in tuples:
        if not row or not isinstance(row[0], dict) or not isinstance(row[0].get("url"), dict):
            raise ValueError(f"BQRS entity has no source URL: {bqrs_json}")
        entity = row[0]
        url = entity["url"]
        parsed_url = urlsplit(url.get("uri", ""))
        if parsed_url.scheme and parsed_url.scheme.lower() != "file":
            raise ValueError(f"unsupported BQRS entity URL: {url.get('uri')}")
        if parsed_url.scheme.lower() == "file":
            raw_path = unquote(parsed_url.path)
            if os.name == "nt":
                if parsed_url.netloc:
                    source_path = Path("\\\\" + parsed_url.netloc + raw_path.replace("/", "\\"))
                else:
                    if re.match(r"^/[A-Za-z]:/", raw_path):
                        raw_path = raw_path[1:]
                    source_path = Path(raw_path)
            else:
                source_path = Path(raw_path)
        else:
            source_path = Path(unquote(url.get("uri", "")))
        if not source_path.is_absolute():
            source_path = source_root / source_path
        source_path = source_path.resolve()
        if not source_path.is_relative_to(source_root) or not source_path.is_file():
            raise ValueError(f"BQRS source path is outside the workspace or missing: {url.get('uri')}")
        try:
            region = {key: int(url[key]) for key in ("startLine", "startColumn", "endLine", "endColumn")}
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"BQRS source URL has an invalid source range: {url}") from exc
        results.append({
            "ruleId": query_id,
            "ruleIndex": 0,
            "message": {"text": entity.get("string") or entity.get("label") or metadata.get("name", query_id)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": source_path.relative_to(source_root).as_posix(), "uriBaseId": "%SRCROOT%"},
                    "region": region,
                },
            }],
        })

    name = metadata.get("name", query_id)
    description = metadata.get("description", name)
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "organization": "GitHub",
                    "semanticVersion": codeql_version,
                    "rules": [{
                        "id": query_id,
                        "name": name,
                        "shortDescription": {"text": name},
                        "fullDescription": {"text": description},
                    }],
                },
            },
            "results": results,
            "columnKind": "utf16CodeUnits",
        }],
    }
    with sarif_path.open("w", encoding="utf-8") as fh:
        json.dump(document, fh, ensure_ascii=False)


def _merge_sarif_files(sarif_paths: list[Path], output_path: Path) -> None:
    documents = []
    for path in sarif_paths:
        with path.open("r", encoding="utf-8") as fh:
            documents.append(json.load(fh))
    if not documents:
        raise ValueError("CodeQL produced no SARIF query results")
    merged = dict(documents[0])
    merged["runs"] = [run for document in documents for run in document.get("runs", [])]
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(merged, fh, ensure_ascii=False)


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
            python = self.venv_bin(version, "python")
            steps = [
                [str(python), "-m", "pip", "install", "--quiet", "--upgrade", "pip"],
                [str(python), "-m", "pip", "install", "--quiet", *FORGE_DEPENDENCIES],
                [str(python), "-m", "pip", "install", "--quiet", "--no-deps",
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
        if codeql_lang == "java":
            query_files = []
            for query in queries:
                query_path = Path(query)
                if query_path.is_file() and query_path.suffix == ".ql":
                    query_files.append(query_path)
                elif query_path.is_dir():
                    query_files.extend(sorted(query_path.rglob("*.ql")))
            if not query_files:
                return ToolRunResult("failed", None, None, duration, Path(log_path), commands,
                                     notes + ["Java table-query conversion requires local .ql query files"])

            run_queries = [str(exe), "database", "run-queries",
                           f"--threads={self.codeql_opts.get('threads', 0)}", "--", str(db), *queries]
            res = run_command(run_queries, cwd=workdir, env=env, timeout=timeout, log_path=log_path)
            commands.append(res.argv)
            duration += res.duration_seconds
            if not res.ok:
                return ToolRunResult("timeout" if res.timed_out else "failed", None, res.returncode, duration,
                                     Path(res.log_path) if res.log_path else None, commands,
                                     notes + [f"codeql database run-queries failed: {res.summary(300)}"])

            query_sarifs = []
            for query_path in query_files:
                metadata = _query_metadata(query_path)
                query_id = metadata.get("id")
                if not query_id:
                    return ToolRunResult("failed", None, None, duration, Path(log_path), commands,
                                         notes + [f"query metadata has no @id: {query_path}"])
                bqrs_candidates = list((db / "results").rglob(f"{query_path.stem}.bqrs"))
                if len(bqrs_candidates) != 1:
                    return ToolRunResult("failed", None, None, duration, Path(log_path), commands,
                                         notes + [f"expected one BQRS result for {query_path.name}, found "
                                                  f"{len(bqrs_candidates)}"])
                bqrs = bqrs_candidates[0]
                query_sarif = sarif_dir / f"{query_path.stem}.sarif"
                if metadata.get("kind") == "table":
                    info = run_command([str(exe), "bqrs", "info", "--format=json", str(bqrs)],
                                       cwd=workdir, env=env, timeout=timeout, log_path=log_path)
                    commands.append(info.argv)
                    duration += info.duration_seconds
                    if not info.ok:
                        return ToolRunResult("timeout" if info.timed_out else "failed", None,
                                             info.returncode, duration, Path(info.log_path) if info.log_path else None,
                                             commands, notes + [f"could not inspect BQRS result for "
                                                                f"{query_path.name}: {info.summary(300)}"])
                    try:
                        result_sets = json.loads(info.stdout).get("result-sets", [])
                        select = next((rs for rs in result_sets if rs.get("name") == "#select"), None)
                        column_count = len(select.get("columns", [])) if select else 0
                    except (json.JSONDecodeError, TypeError, AttributeError) as exc:
                        return ToolRunResult("failed", None, info.returncode, duration,
                                             Path(info.log_path) if info.log_path else None, commands,
                                             notes + [f"invalid BQRS metadata for {query_path.name}: {exc}"])
                    if column_count == 1:
                        decoded = scratch / f"{query_path.stem}.bqrs.json"
                        decode = [str(exe), "bqrs", "decode", str(bqrs), "--format=json", "--entities=all",
                                  f"--output={decoded}"]
                        res = run_command(decode, cwd=workdir, env=env, timeout=timeout, log_path=log_path)
                        commands.append(res.argv)
                        duration += res.duration_seconds
                        if not res.ok:
                            return ToolRunResult("timeout" if res.timed_out else "failed", None, res.returncode,
                                                 duration, Path(res.log_path) if res.log_path else None, commands,
                                                 notes + [f"could not decode one-column BQRS result for "
                                                          f"{query_path.name}: {res.summary(300)}"])
                        try:
                            codeql_version = str((version.components.get("codeql") or {}).get("cliVersion")
                                                 or (version.components.get("codeql") or {}).get("version")
                                                 or "unknown")
                            _bqrs_entities_to_sarif(decoded, query_sarif, workdir, metadata, codeql_version)
                            _add_sarif_context(query_sarif, workdir)
                        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                            return ToolRunResult("failed", None, res.returncode, duration,
                                                 Path(res.log_path) if res.log_path else None, commands,
                                                 notes + [f"could not convert one-column BQRS result for "
                                                          f"{query_path.name}: {exc}"])
                        query_sarifs.append(query_sarif)
                        continue
                    if column_count < 2:
                        return ToolRunResult("failed", None, info.returncode, duration,
                                             Path(info.log_path) if info.log_path else None, commands,
                                             notes + [f"unexpected BQRS result shape for {query_path.name}: "
                                                      f"{column_count} columns"])
                interpret = [str(exe), "bqrs", "interpret", str(bqrs), "--format=sarif-latest",
                            f"--output={query_sarif}", f"--source-archive={workdir}",
                            f"--source-location-prefix={workdir}", "-t=kind=problem", f"-t=id={query_id}"]
                for key in ("name", "description"):
                    if metadata.get(key):
                        interpret.append(f"-t={key}={metadata[key]}")
                res = run_command(interpret, cwd=workdir, env=env, timeout=timeout, log_path=log_path)
                commands.append(res.argv)
                duration += res.duration_seconds
                if not res.ok:
                    return ToolRunResult("timeout" if res.timed_out else "failed", None, res.returncode, duration,
                                         Path(res.log_path) if res.log_path else None, commands,
                                         notes + [f"codeql BQRS interpretation failed for {query_path.name}: "
                                                  f"{res.summary(300)}"])
                try:
                    _add_sarif_context(query_sarif, workdir)
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    return ToolRunResult("failed", None, res.returncode, duration, Path(res.log_path) if res.log_path else None,
                                         commands, notes + [f"could not add source context for {query_path.name}: {exc}"])
                query_sarifs.append(query_sarif)
            if not query_sarifs:
                return ToolRunResult("failed", None, None, duration, Path(log_path), commands,
                                     notes + ["CodeQL produced no interpretable SARIF query results"])
            try:
                _merge_sarif_files(query_sarifs, sarif)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                return ToolRunResult("failed", None, None, duration, Path(log_path), commands,
                                     notes + [f"could not combine CodeQL SARIF results: {exc}"])
        else:
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
                    if status == "ok":
                        status = "empty"
        except (OSError, json.JSONDecodeError) as exc:
            status = "failed"
            notes.append(f"cbom.json is not valid JSON: {exc}")
        if not self.config.get("results", "keep_workspaces"):
            shutil.rmtree(scratch, ignore_errors=True)
        return ToolRunResult(status, dest, res.returncode, duration, Path(res.log_path) if res.log_path else None,
                             commands, notes, {"sarif": str(out_dir / "crypto.sarif"), "codeqlLanguage": codeql_lang,
                                               "queries": queries})
