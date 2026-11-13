"""A declarative adapter: everything about the tool comes from its YAML spec.

Spec excerpt (see ``orchestrator/data/tools/cdxgen.yaml`` for a complete example)::

    launcher: docker                       # default launcher; --launcher overrides
    docker:
      image: ghcr.io/cyclonedx/cdxgen:{tag}
      mount: /app                          # where the case workspace is mounted
      workdir: /app
      user: current                        # current | image | uid:gid
      env: {FETCH_LICENSE: "false"}
      args: ["-t", "{language}", "--include-crypto", "-o", "{output_container}", "{mount}"]
    local:
      install: ["npm install -g @cyclonedx/cdxgen@{version}"]
      command: ["cdxgen", "-t", "{language}", "--include-crypto", "-o", "{output}", "{workdir}"]
    output: bom.json                       # relative to the workspace (glob allowed)
    languages: {Python: python, Java: java, Go: go, TypeScript: js, C#: dotnet}

Placeholders: ``{version}`` (tag without ``v``), ``{tag}``, ``{commit}``, ``{workdir}`` (host path of
the case copy), ``{mount}``, ``{output}`` (host path), ``{output_container}``, ``{language}`` (the
per-language value), ``{language_<key>}`` (other per-language keys), ``{case}``, ``{cache}``,
``{home}``, ``{platform}``, ``{uid}``, ``{gid}``.
"""
from __future__ import annotations

import glob
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Optional

from .. import github
from ..baseline import Case
from ..docker import DockerError
from ..process import run_command, which
from .base import ToolAdapter, ToolRunResult, ToolVersion, as_argv, render

log = logging.getLogger("orchestrator.tools.generic")


def _resolve_executable(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    if os.name == "nt" and not os.path.splitext(argv[0])[1]:
        for suffix in (".cmd", ".bat"):
            shim = argv[0] + suffix
            if os.path.isfile(shim):
                return [shim, *argv[1:]]
    executable = which(argv[0])
    return [executable, *argv[1:]] if executable else argv


class CommandToolAdapter(ToolAdapter):
    # ------------------------------------------------------------------ version
    def resolve(self, pin: Optional[str] = None) -> ToolVersion:
        vs = self.spec.versioning or {}
        pin = pin or self.config.get("tools", "pins", default={}).get(self.spec.id)
        if not self.spec.repo:
            return ToolVersion.fixed(self.spec.id, self.spec.name, pin or str(vs.get("version") or "unversioned"),
                                     launcher=self.launcher, notes=["no repository configured"])
        rv = github.resolve(self.spec.repo, str(vs.get("strategy") or "release"), pin=pin,
                            branch=str(vs.get("branch") or "main"), token=self.config.github_token,
                            api=str(self.config.get("github", "api")),
                            allow_prerelease=bool(vs.get("allow_prerelease", self.config.get("github", "allow_prerelease"))),
                            tag_pattern=vs.get("tag_pattern"))
        tv = ToolVersion.from_resolved(self.spec.id, self.spec.name, rv, self.launcher)
        if self.launcher == "docker":
            tv.image = render(self.spec.docker.get("image"), self.variables(tv))
        return tv

    # ------------------------------------------------------------------ install
    def install(self, version: ToolVersion, log_path: Optional[Path] = None) -> None:
        if self.launcher == "docker":
            self._install_docker(version, log_path)
        elif self.launcher == "local":
            self._install_local(version, log_path)
        else:
            raise ValueError(f"{self.spec.id}: unknown launcher {self.launcher!r}")

    def _install_docker(self, version: ToolVersion, log_path: Optional[Path]) -> None:
        if self.docker is None or not self.docker.available():
            raise DockerError(f"{self.spec.id}: Docker is not available (try --launcher local or install Docker)")
        image = version.image or render(self.spec.docker.get("image"), self.variables(version))
        fallback = self.spec.docker.get("fallback_tag")
        try:
            self.docker.pull(image, log_path)
        except DockerError as exc:
            if fallback:
                base = image.rsplit(":", 1)[0]
                alt = f"{base}:{fallback}"
                version.notes.append(f"image {image} unavailable ({str(exc)[:120]}); using {alt}")
                self.docker.pull(alt, log_path)
                image = alt
            else:
                raise
        version.image = image
        version.image_digest = self.docker.image_digest(image)
        version.image_id = self.docker.image_id(image)
        for label in ("org.opencontainers.image.version", "org.opencontainers.image.revision"):
            val = self.docker.image_label(image, label)
            if val:
                version.components[label] = val

    def _install_local(self, version: ToolVersion, log_path: Optional[Path]) -> None:
        local = self.spec.local or {}
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        variables = self.variables(version)
        env = render(local.get("env") or {}, variables)
        for step in local.get("install") or []:
            argv = _resolve_executable(render(as_argv(step), variables))
            res = run_command(argv, cwd=self.cache_dir, env=env, timeout=1800, log_path=log_path)
            if not res.ok:
                raise RuntimeError(f"{self.spec.id}: install step failed: {' '.join(argv)}\n{res.summary(800)}")
        check = local.get("check")
        if check:
            argv = _resolve_executable(render(as_argv(check), variables))
            res = run_command(argv, cwd=self.cache_dir, env=env, timeout=300, log_path=log_path)
            if res.ok:
                version.components["check"] = (res.stdout or res.stderr).strip()[:200]
            else:
                version.notes.append(f"version check failed: {res.summary(200)}")

    # ------------------------------------------------------------------ run
    def _output_spec(self) -> str:
        return str(self.spec.output or "cbom.json")

    def _locate_output(self, workdir: Path, variables: dict) -> Optional[Path]:
        pattern = render(self._output_spec(), variables)
        p = Path(pattern)
        candidates = [p] if p.is_absolute() else [workdir / pattern]
        for cand in candidates:
            hits = sorted(glob.glob(str(cand), recursive=True))
            files = [Path(h) for h in hits if Path(h).is_file()]
            if files:
                # prefer the largest file (consolidated CBOMs beat per-module ones)
                return max(files, key=lambda f: f.stat().st_size)
        return None

    def run(self, case: Case, workdir: Path, version: ToolVersion, out_dir: Path, log_path: Path) -> ToolRunResult:
        if not self.supports(case):
            return ToolRunResult("unsupported", notes=[f"{self.spec.id} has no configuration for {case.language}"])
        entry = self.spec.language_entry(case) or {}
        if self.launcher == "docker":
            return self._run_docker(case, workdir, version, out_dir, log_path, entry)
        return self._run_local(case, workdir, version, out_dir, log_path, entry)

    def _finish(self, res, workdir: Path, variables: dict, out_dir: Path, command: list) -> ToolRunResult:
        output = self._locate_output(workdir, variables)
        status = "ok"
        notes: list[str] = []
        if res.timed_out:
            status = "timeout"
        elif output is None:
            status = "failed"
            notes.append("no output file produced" + (f" (exit {res.returncode})" if res.returncode else ""))
        elif not res.ok:
            notes.append(f"tool exited with {res.returncode} but produced output; scored anyway")
        dest = None
        if output is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            dest = out_dir / output.name
            shutil.copy2(output, dest)
            try:
                with open(dest, "r", encoding="utf-8") as fh:
                    doc = json.load(fh)
                if not (doc.get("components") or []):
                    status = "empty" if status == "ok" else status
            except (OSError, json.JSONDecodeError) as exc:
                status = "failed"
                notes.append(f"output is not valid JSON: {exc}")
        return ToolRunResult(status, dest, res.returncode, res.duration_seconds, Path(res.log_path) if res.log_path else None,
                             command, notes)

    def _run_docker(self, case: Case, workdir: Path, version: ToolVersion, out_dir: Path, log_path: Path, entry: dict) -> ToolRunResult:
        dk = self.spec.docker or {}
        mount = str(dk.get("mount") or "/src")
        rel_output = render(self._output_spec(), self.variables(version, case, workdir))
        variables = self.variables(version, case, workdir, {
            "mount": mount, "output": str(workdir / rel_output), "output_container": f"{mount}/{rel_output}",
        })
        env = render(dk.get("env") or {}, variables)
        env.update(render(entry.get("env") or {}, variables))
        args = render(as_argv(entry.get("args") if entry.get("args") is not None else dk.get("args")), variables)
        image = version.image or render(dk.get("image"), variables)
        mounts = {str(workdir): mount}
        for host, cont in (render(dk.get("mounts") or {}, variables)).items():
            mounts[host] = cont
        res = self.docker.run(image, args, mounts=mounts, env=env, workdir=render(dk.get("workdir"), variables),
                              user=dk.get("user"), timeout=self.timeout(), log_path=log_path,
                              entrypoint=dk.get("entrypoint"), extra_args=render(dk.get("extra_args") or [], variables),
                              network=dk.get("network"))
        return self._finish(res, workdir, variables, out_dir, res.argv)

    def _run_local(self, case: Case, workdir: Path, version: ToolVersion, out_dir: Path, log_path: Path, entry: dict) -> ToolRunResult:
        local = self.spec.local or {}
        rel_output = render(self._output_spec(), self.variables(version, case, workdir))
        variables = self.variables(version, case, workdir, {"mount": str(workdir), "output": str(workdir / rel_output),
                                                           "output_container": str(workdir / rel_output)})
        env = render(local.get("env") or {}, variables)
        env.update(render(entry.get("env") or {}, variables))
        argv = render(as_argv(entry.get("command") if entry.get("command") is not None else local.get("command")), variables)
        if argv and not which(argv[0]) and not Path(argv[0]).exists():
            return ToolRunResult("failed", notes=[f"{argv[0]} not found on PATH; run `orchestrator tools install {self.spec.id}`"])
        argv = _resolve_executable(argv)
        res = run_command(argv, cwd=render(local.get("cwd"), variables) or workdir, env=env, timeout=self.timeout(),
                          log_path=log_path)
        return self._finish(res, workdir, variables, out_dir, res.argv)
