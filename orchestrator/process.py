"""Subprocess execution with timeouts, duration and log capture."""
from __future__ import annotations

import logging
import os
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence

log = logging.getLogger("orchestrator.process")


@dataclass
class CommandResult:
    argv: list
    returncode: Optional[int]
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    cwd: Optional[str] = None
    log_path: Optional[str] = None
    extra: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def summary(self, limit: int = 2000) -> str:
        tail = (self.stderr or self.stdout or "")[-limit:]
        return f"exit={self.returncode} timed_out={self.timed_out} duration={self.duration_seconds:.1f}s\n{tail}"


def which(binary: str) -> Optional[str]:
    from shutil import which as _which
    return _which(binary)


def run_command(argv: Sequence[str], *, cwd: Optional[os.PathLike | str] = None,
                env: Optional[Mapping[str, str]] = None, timeout: Optional[float] = None,
                log_path: Optional[os.PathLike | str] = None, input_text: Optional[str] = None,
                check: bool = False) -> CommandResult:
    """Run ``argv`` and capture everything.  Never raises on non-zero exit unless ``check``."""
    argv = [str(a) for a in argv]
    merged_env = dict(os.environ)
    if env:
        merged_env.update({k: str(v) for k, v in env.items()})
    log.debug("$ %s (cwd=%s)", " ".join(shlex.quote(a) for a in argv), cwd)
    start = time.monotonic()
    timed_out = False
    process_argv = argv
    if os.name == "nt" and argv[0].lower().endswith((".bat", ".cmd")):
        process_argv = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", *argv]
    try:
        proc = subprocess.run(process_argv, cwd=cwd, env=merged_env, input=input_text, capture_output=True,
                              text=True, timeout=timeout, errors="replace")
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc = None
        out = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    except FileNotFoundError as exc:
        rc, out, err = 127, "", f"{argv[0]}: not found ({exc})"
    duration = time.monotonic() - start
    result = CommandResult(argv, rc, out, err, duration, timed_out, str(cwd) if cwd else None)
    if log_path:
        p = Path(log_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(f"$ {' '.join(shlex.quote(a) for a in argv)}\n")
            fh.write(f"# cwd={cwd} exit={rc} timed_out={timed_out} duration={duration:.2f}s\n")
            if out:
                fh.write("--- stdout ---\n" + out + ("\n" if not out.endswith("\n") else ""))
            if err:
                fh.write("--- stderr ---\n" + err + ("\n" if not err.endswith("\n") else ""))
            fh.write("\n")
        result.log_path = str(p)
    if check and not result.ok:
        raise RuntimeError(f"command failed: {' '.join(argv)}\n{result.summary()}")
    return result
