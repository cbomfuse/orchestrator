"""Resolve "the newest version" of a tool from its GitHub repository, and download release assets.

Resolution never requires a token: the GitHub REST API is tried first (it knows which tag is the
*latest release*), and ``git ls-remote`` is the fallback (it only knows tags and branches, so the
highest non-pre-release semantic version is taken).  Every result records the tag, the commit SHA
and how it was obtained so that a run can be reproduced later with ``tools.pins``.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .process import run_command

log = logging.getLogger("orchestrator.github")

_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
_PRERELEASE_RE = re.compile(r"(?i)(?:^|[.\-+_])(alpha|beta|rc|pre|preview|dev|snapshot|nightly|canary|next)")


class GitHubError(RuntimeError):
    pass


@dataclass
class ResolvedVersion:
    repo: str
    strategy: str
    tag: Optional[str]
    version: str
    commit: Optional[str]
    resolved_at: str
    source: str
    url: Optional[str] = None
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_repo(url: str) -> str:
    url = url.strip()
    if url.startswith("git@github.com:"):
        url = "https://github.com/" + url[len("git@github.com:"):]
    url = re.sub(r"\.git$", "", url.rstrip("/"))
    return url


def parse_repo(url: str) -> tuple[str, str]:
    m = re.search(r"github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?/?$", url.strip())
    if not m:
        raise GitHubError(f"not a GitHub repository URL: {url}")
    return m.group(1), m.group(2)


def gh_api(path: str, token: Optional[str] = None, api: str = "https://api.github.com") -> object:
    url = path if path.startswith("http") else f"{api.rstrip('/')}/{path.lstrip('/')}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "cbom-orchestrator",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        raise GitHubError(f"GitHub API {exc.code} for {url}: {body}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise GitHubError(f"GitHub API unreachable for {url}: {exc}") from exc


# ----------------------------------------------------------------------------- semver helpers
def strip_v(tag: str) -> str:
    """``v2.2.0`` -> ``2.2.0``; ``codeql-bundle-v2.27.4`` -> ``2.27.4``; ``release-2.7.0`` -> ``2.7.0``."""
    t = tag.strip()
    m = re.search(r"\d+(?:\.\d+)*(?:[-+._].*)?$", t)
    return m.group(0) if m else t


def semver_key(tag: str) -> tuple:
    """A sort key that orders tags like 'v2.10.1' > 'v2.9.0' and tolerates odd suffixes."""
    s = strip_v(tag)
    main, _, rest = s.partition("-")
    parts = []
    for piece in re.split(r"[.]", main):
        m = re.match(r"(\d+)(.*)", piece)
        if m:
            parts.append((int(m.group(1)), m.group(2)))
        else:
            parts.append((-1, piece))
    while len(parts) < 4:
        parts.append((0, ""))
    return (tuple(parts), 1 if not rest else 0, rest)


def is_prerelease(tag: str) -> bool:
    return bool(_PRERELEASE_RE.search(strip_v(tag)))


def looks_like_version(tag: str) -> bool:
    t = tag.strip()
    return bool(re.match(r"^(?:[A-Za-z][A-Za-z0-9]*[-_])*v?\d+(\.\d+)+", t)) or bool(re.match(r"^v?\d+(\.\d+)*$", t))


# ----------------------------------------------------------------------------- git ls-remote
_LS_REMOTE_CACHE: dict[str, dict[str, str]] = {}


def ls_remote_tags(repo: str) -> dict[str, str]:
    """Return {tag: commit sha} using peeled refs where available (annotated tags)."""
    repo = normalize_repo(repo)
    if repo in _LS_REMOTE_CACHE:
        return _LS_REMOTE_CACHE[repo]
    res = run_command(["git", "ls-remote", "--tags", repo + ".git"], timeout=120)
    if not res.ok:
        raise GitHubError(f"git ls-remote failed for {repo}: {res.stderr.strip()[:300]}")
    tags: dict[str, str] = {}
    peeled: dict[str, str] = {}
    for line in res.stdout.splitlines():
        if not line.strip():
            continue
        sha, _, ref = line.partition("\t")
        if not ref.startswith("refs/tags/"):
            continue
        name = ref[len("refs/tags/"):]
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            tags[name] = sha
    for name, sha in peeled.items():
        tags[name] = sha
    _LS_REMOTE_CACHE[repo] = tags
    return tags


def ls_remote_ref(repo: str, ref: str) -> Optional[str]:
    repo = normalize_repo(repo)
    res = run_command(["git", "ls-remote", repo + ".git", ref, f"refs/heads/{ref}"], timeout=120)
    if not res.ok:
        raise GitHubError(f"git ls-remote failed for {repo}: {res.stderr.strip()[:300]}")
    for line in res.stdout.splitlines():
        sha, _, name = line.partition("\t")
        if name in (ref, f"refs/heads/{ref}", f"refs/tags/{ref}"):
            return sha
    return None


def _tag_commit_via_api(owner: str, name: str, tag: str, token: Optional[str], api: str) -> Optional[str]:
    try:
        ref = gh_api(f"repos/{owner}/{name}/git/ref/tags/{tag}", token, api)
    except GitHubError:
        return None
    obj = ref.get("object", {}) if isinstance(ref, dict) else {}
    if obj.get("type") == "tag":
        try:
            tagobj = gh_api(f"repos/{owner}/{name}/git/tags/{obj['sha']}", token, api)
            return tagobj.get("object", {}).get("sha")
        except GitHubError:
            return obj.get("sha")
    return obj.get("sha")


def _best_tag(tags: dict[str, str], allow_prerelease: bool, pattern: Optional[str] = None) -> Optional[str]:
    rx = re.compile(pattern) if pattern else None
    candidates = [t for t in tags if looks_like_version(t) and (rx is None or rx.search(t))]
    if not allow_prerelease:
        stable = [t for t in candidates if not is_prerelease(t)]
        candidates = stable or candidates
    if not candidates:
        return None
    return max(candidates, key=semver_key)


def resolve(repo: str, strategy: str = "release", *, pin: Optional[str] = None, branch: str = "main",
            token: Optional[str] = None, api: str = "https://api.github.com", allow_prerelease: bool = False,
            tag_pattern: Optional[str] = None) -> ResolvedVersion:
    """Resolve a version of ``repo``.

    strategy: ``release`` (latest GitHub release, falls back to highest tag), ``tag`` (highest tag),
    ``branch`` (tip of ``branch``) or ``fixed`` (``pin`` must be given).
    ``pin`` overrides the strategy: a tag name (with or without ``v``) or a commit SHA.
    """
    repo = normalize_repo(repo)
    owner, name = parse_repo(repo)
    notes: list[str] = []
    stamp = now_iso()

    if pin:
        pin = pin.strip()
        if _SHA_RE.match(pin) and len(pin) >= 7 and not looks_like_version(pin):
            return ResolvedVersion(repo, "fixed", None, pin[:12], pin, stamp, "pinned",
                                   f"{repo}/commit/{pin}", ["pinned to commit"])
        tags = ls_remote_tags(repo)
        for cand in (pin, f"v{pin}", strip_v(pin)):
            if cand in tags:
                return ResolvedVersion(repo, "fixed", cand, strip_v(cand), tags[cand], stamp, "pinned",
                                       f"{repo}/releases/tag/{cand}", ["pinned to tag"])
        if _SHA_RE.match(pin):
            return ResolvedVersion(repo, "fixed", None, pin[:12], pin, stamp, "pinned", f"{repo}/commit/{pin}",
                                   ["pinned to commit (no matching tag)"])
        raise GitHubError(f"{repo}: pinned version {pin!r} is neither a tag nor a commit")

    if strategy == "branch":
        sha = ls_remote_ref(repo, branch)
        if not sha:
            raise GitHubError(f"{repo}: branch {branch!r} not found")
        return ResolvedVersion(repo, "branch", None, f"{branch}@{sha[:12]}", sha, stamp, "ls-remote",
                               f"{repo}/tree/{sha}", [f"tip of branch {branch}"])

    if strategy == "release":
        try:
            rel = gh_api(f"repos/{owner}/{name}/releases/latest", token, api)
            tag = rel["tag_name"]
            if tag_pattern and not re.search(tag_pattern, tag):
                notes.append(f"latest release {tag} does not match tag_pattern; using highest matching tag")
            else:
                commit = _tag_commit_via_api(owner, name, tag, token, api) or ls_remote_tags(repo).get(tag)
                return ResolvedVersion(repo, "release", tag, strip_v(tag), commit, stamp, "api",
                                       rel.get("html_url") or f"{repo}/releases/tag/{tag}",
                                       notes + [f"release {rel.get('name') or tag} published {rel.get('published_at')}"])
        except GitHubError as exc:
            notes.append(f"GitHub API unavailable ({str(exc)[:120]}); fell back to git ls-remote tags")
        except (KeyError, TypeError) as exc:
            notes.append(f"unexpected release payload ({exc}); fell back to git ls-remote tags")

    tags = ls_remote_tags(repo)
    best = _best_tag(tags, allow_prerelease, tag_pattern)
    if best is None:
        if strategy in ("release", "tag"):
            notes.append("no version-like tags found; using default branch tip")
            sha = ls_remote_ref(repo, branch) or ls_remote_ref(repo, "HEAD")
            if not sha:
                raise GitHubError(f"{repo}: no tags and no branch {branch!r}")
            return ResolvedVersion(repo, "branch", None, f"{branch}@{sha[:12]}", sha, stamp, "ls-remote",
                                   f"{repo}/tree/{sha}", notes)
        raise GitHubError(f"{repo}: no version-like tags")
    return ResolvedVersion(repo, "tag" if strategy != "release" else "release", best, strip_v(best), tags[best],
                           stamp, "ls-remote", f"{repo}/releases/tag/{best}", notes + ["highest semantic-version tag"])


# ----------------------------------------------------------------------------- downloads
def download(url: str, dest: Path, token: Optional[str] = None, timeout: float = 600) -> Path:
    """Stream ``url`` to ``dest`` (atomically via a temp file)."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "cbom-orchestrator"})
    if token and "api.github.com" in url:
        req.add_header("Authorization", f"Bearer {token}")
    log.info("downloading %s", url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as fh:
            shutil.copyfileobj(resp, fh, length=1 << 20)
    except urllib.error.HTTPError as exc:
        raise GitHubError(f"download failed ({exc.code}) for {url}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise GitHubError(f"download failed for {url}: {exc}") from exc
    tmp.replace(dest)
    return dest


def release_asset_url(repo: str, tag: str, asset: str) -> str:
    return f"{normalize_repo(repo)}/releases/download/{tag}/{asset}"
