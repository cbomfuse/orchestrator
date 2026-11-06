"""Thin Docker/Podman wrapper used by the launchers."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .process import CommandResult, run_command, which

log = logging.getLogger("orchestrator.docker")


class DockerError(RuntimeError):
    pass


class Docker:
    def __init__(self, binary: str = "docker", pull_policy: str = "missing", user: str = "current",
                 extra_args: Optional[Sequence[str]] = None):
        self.binary = binary
        self.pull_policy = pull_policy
        self.user = user
        self.extra_args = list(extra_args or [])

    # ------------------------------------------------------------------ status
    def available(self) -> bool:
        if not which(self.binary):
            return False
        return run_command([self.binary, "info", "--format", "{{.ServerVersion}}"], timeout=60).ok

    def version(self) -> Optional[str]:
        res = run_command([self.binary, "version", "--format", "{{.Server.Version}}"], timeout=60)
        return res.stdout.strip() if res.ok else None

    # ------------------------------------------------------------------ images
    def image_present(self, image: str) -> bool:
        return run_command([self.binary, "image", "inspect", image], timeout=60).ok

    def manifest_exists(self, image: str) -> bool:
        return run_command([self.binary, "manifest", "inspect", image], timeout=120).ok

    def pull(self, image: str, log_path: Optional[Path] = None) -> None:
        if self.pull_policy == "never":
            if not self.image_present(image):
                raise DockerError(f"image {image} not present and pull_policy=never")
            return
        if self.pull_policy == "missing" and self.image_present(image):
            return
        res = run_command([self.binary, "pull", image], timeout=1800, log_path=log_path)
        if not res.ok:
            raise DockerError(f"docker pull {image} failed: {res.stderr.strip()[-400:]}")

    def image_digest(self, image: str) -> Optional[str]:
        res = run_command([self.binary, "image", "inspect", "--format", "{{join .RepoDigests \",\"}}", image], timeout=60)
        if not res.ok:
            return None
        digests = [d for d in res.stdout.strip().split(",") if d]
        return digests[0] if digests else None

    def image_id(self, image: str) -> Optional[str]:
        res = run_command([self.binary, "image", "inspect", "--format", "{{.Id}}", image], timeout=60)
        return res.stdout.strip() if res.ok else None

    def image_label(self, image: str, label: str) -> Optional[str]:
        res = run_command([self.binary, "image", "inspect", "--format", f'{{{{index .Config.Labels "{label}"}}}}', image],
                          timeout=60)
        v = res.stdout.strip() if res.ok else ""
        return v or None

    # ------------------------------------------------------------------ run
    def _user_args(self, user_override: Optional[str]) -> list[str]:
        user = user_override if user_override is not None else self.user
        if not user or user == "image":
            return []
        if user == "current":
            if hasattr(os, "getuid"):
                return ["--user", f"{os.getuid()}:{os.getgid()}"]
            return []
        return ["--user", str(user)]

    def run(self, image: str, args: Sequence[str], *, mounts: Mapping[str, str], env: Mapping[str, str],
            workdir: Optional[str] = None, user: Optional[str] = None, timeout: Optional[float] = None,
            log_path: Optional[Path] = None, entrypoint: Optional[str] = None,
            extra_args: Optional[Sequence[str]] = None, network: Optional[str] = None) -> CommandResult:
        argv = [self.binary, "run", "--rm"]
        argv += self.extra_args
        argv += list(extra_args or [])
        argv += self._user_args(user)
        for host, container in mounts.items():
            argv += ["-v", f"{Path(host).resolve()}:{container}"]
        for k, v in env.items():
            argv += ["-e", f"{k}={v}"]
        if workdir:
            argv += ["-w", workdir]
        if network:
            argv += ["--network", network]
        if entrypoint:
            argv += ["--entrypoint", entrypoint]
        argv.append(image)
        argv += list(args)
        return run_command(argv, timeout=timeout, log_path=log_path)
