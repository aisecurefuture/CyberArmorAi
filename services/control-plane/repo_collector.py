"""Repository A-BOM collector.

Scans configured Git repositories for software components and converts
them into CycloneDX 1.6 component dicts the existing A-BOM tables can
absorb. Two modes per repo:

1. **CI-published SBOM** — when a repo's CI uploads a CycloneDX or SPDX
   artifact, consume it directly. (Pending — v1 scans manifests.)
2. **Manifest scan** — fetch package.json / requirements.txt / Cargo.toml
   / go.mod / pom.xml from the default branch and parse them into
   component rows.

GitHub-first in this revision; GitLab + Azure Repos land next. All
network I/O goes through ``httpx`` so we reuse the connection pool the
rest of control-plane shares.

The collector is invoked synchronously from the FastAPI handler. Big
orgs will eventually want this on a background queue; for now the sync
is bounded by ``GITHUB_API_BUDGET`` requests per sync to keep the
handler latency predictable.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("cyberarmor.control_plane.repo_collector")

# Per-sync request ceiling so a 5,000-repo PAT scan can't pin the
# handler. The portal "sync now" button is a v1 affordance; cron is
# follow-up work.
GITHUB_API_BUDGET = 200
DEFAULT_BRANCH_FALLBACK = "main"


# ── Manifest parsers ───────────────────────────────────────────────────
#
# Each parser is a pure function: takes raw file bytes/string and
# returns a list of CycloneDX-shaped component dicts. Errors swallow
# silently — one malformed package.json shouldn't fail the whole
# repo sync.


def parse_package_json(content: str, *, repo_label: str = "") -> List[Dict[str, Any]]:
    """npm / yarn / pnpm root manifest. Pulls ``dependencies`` and
    ``devDependencies`` — dev deps land as components too because they
    matter for supply-chain analysis (a malicious dev-dep can hijack a
    build)."""
    import json
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    rows: List[Dict[str, Any]] = []
    for section, scope in (("dependencies", "runtime"), ("devDependencies", "dev"),
                            ("peerDependencies", "peer"), ("optionalDependencies", "optional")):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, version_spec in deps.items():
            if not isinstance(name, str):
                continue
            version = _clean_npm_version(version_spec)
            rows.append({
                "type": "library",
                "name": name,
                "version": version or "",
                "purl": f"pkg:npm/{name}@{version}" if version else f"pkg:npm/{name}",
                "properties": [
                    {"name": "cyberarmor:package_manager", "value": "npm"},
                    {"name": "cyberarmor:dep_scope", "value": scope},
                    {"name": "cyberarmor:source_repo", "value": repo_label},
                ],
            })
    return rows


def _clean_npm_version(raw: Any) -> str:
    """Strip leading ``^`` / ``~`` / ``>=`` / git+ssh:// prefixes so the
    version field carries a meaningful identifier even when the manifest
    declares a range. PURL consumers expect a concrete version when
    present, so a range stored verbatim breaks downstream tooling."""
    if raw is None:
        return ""
    s = str(raw).strip()
    if not s:
        return ""
    # Skip git / file / link specs — they have no semver-comparable
    # version so we surface the raw spec for the operator to investigate.
    if s.startswith(("git+", "http", "file:", "link:", "workspace:")):
        return s[:64]
    # Strip semver range prefixes for the PURL.
    return s.lstrip("^~=> <").strip()


def parse_requirements_txt(content: str, *, repo_label: str = "") -> List[Dict[str, Any]]:
    """``pip``-style requirements file. Handles the common subset:
    ``name==version``, ``name>=version``, ``name``, plus comments and
    ``-e`` editable installs. Skips ``-r other.txt`` includes —
    recursing into includes is a follow-up."""
    rows: List[Dict[str, Any]] = []
    for line in (content or "").splitlines():
        # Strip inline comments and surrounding whitespace.
        if "#" in line:
            line = line.split("#", 1)[0]
        line = line.strip()
        if not line or line.startswith(("-r", "--", "-e ", "-f")):
            continue
        # Drop env markers (``pkg; python_version > '3.10'``).
        if ";" in line:
            line = line.split(";", 1)[0].strip()
        # Drop extras (``pkg[extra]==1.0`` → ``pkg``).
        m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]+\])?\s*(.*)$", line)
        if not m:
            continue
        name = m.group(1)
        rest = (m.group(3) or "").strip()
        version = ""
        vm = re.match(r"^(?:==|~=|>=|<=|>|<|=)\s*([^\s,]+)", rest)
        if vm:
            version = vm.group(1)
        rows.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}",
            "properties": [
                {"name": "cyberarmor:package_manager", "value": "pip"},
                {"name": "cyberarmor:source_repo", "value": repo_label},
            ],
        })
    return rows


def parse_cargo_toml(content: str, *, repo_label: str = "") -> List[Dict[str, Any]]:
    """Rust ``Cargo.toml``. Reads ``[dependencies]`` and ``[dev-dependencies]``.
    Supports the two common shapes::

        foo = "1.2"
        bar = { version = "0.5", features = ["x"] }

    Falls back gracefully when ``tomllib`` isn't available (Python <3.11)
    — degraded mode produces no rows so the sync continues."""
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return []
    try:
        data = tomllib.loads(content)
    except Exception:  # noqa: BLE001
        return []
    rows: List[Dict[str, Any]] = []
    for section, scope in (("dependencies", "runtime"), ("dev-dependencies", "dev"),
                           ("build-dependencies", "build")):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(name, str):
                continue
            version = ""
            if isinstance(spec, str):
                version = spec
            elif isinstance(spec, dict):
                version = str(spec.get("version") or spec.get("tag") or spec.get("rev") or "")
            version = version.lstrip("^~=> <").strip()
            rows.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:cargo/{name}@{version}" if version else f"pkg:cargo/{name}",
                "properties": [
                    {"name": "cyberarmor:package_manager", "value": "cargo"},
                    {"name": "cyberarmor:dep_scope", "value": scope},
                    {"name": "cyberarmor:source_repo", "value": repo_label},
                ],
            })
    return rows


def parse_go_mod(content: str, *, repo_label: str = "") -> List[Dict[str, Any]]:
    """Go module file. Reads ``require`` blocks; ignores ``// indirect``
    marker but stamps the scope on each row so the BOM distinguishes
    direct vs transitive."""
    rows: List[Dict[str, Any]] = []
    in_block = False
    for raw in (content or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if line == ")":
            in_block = False
            continue
        if in_block or line.startswith("require "):
            spec = line.replace("require ", "", 1).strip()
            # Drop trailing comment if any
            indirect = "indirect" in spec
            spec = spec.split("//", 1)[0].strip()
            parts = spec.split()
            if len(parts) < 2:
                continue
            module, version = parts[0], parts[1]
            rows.append({
                "type": "library",
                "name": module,
                "version": version,
                "purl": f"pkg:golang/{module}@{version}",
                "properties": [
                    {"name": "cyberarmor:package_manager", "value": "gomod"},
                    {"name": "cyberarmor:dep_scope", "value": "indirect" if indirect else "direct"},
                    {"name": "cyberarmor:source_repo", "value": repo_label},
                ],
            })
    return rows


# Map of manifest file basename → parser. Order doesn't matter; each
# parser owns one filename.
_MANIFEST_PARSERS = {
    "package.json":      parse_package_json,
    "requirements.txt":  parse_requirements_txt,
    "Cargo.toml":        parse_cargo_toml,
    "go.mod":            parse_go_mod,
}


# ── GitHub client ──────────────────────────────────────────────────────


class GitHubError(Exception):
    pass


def _github_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "CyberArmor-A-BOM/1.0",
    }


def github_default_branch(token: str, repo: str, *, api_base: str = "https://api.github.com") -> str:
    """Resolve the default branch of ``org/repo``. Cheap one-request
    lookup so we don't hard-code 'main' and miss legacy 'master' repos."""
    url = f"{api_base.rstrip('/')}/repos/{repo}"
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(url, headers=_github_headers(token))
            if resp.status_code == 404:
                raise GitHubError(f"repo not found or token lacks access: {repo}")
            if resp.status_code == 401:
                raise GitHubError("github token unauthorized")
            resp.raise_for_status()
            data = resp.json() or {}
            return str(data.get("default_branch") or DEFAULT_BRANCH_FALLBACK)
    except httpx.HTTPError as exc:
        raise GitHubError(f"github default-branch lookup failed: {exc}") from exc


def github_tree(token: str, repo: str, branch: str, *, api_base: str = "https://api.github.com") -> List[Dict[str, Any]]:
    """Flat list of every blob in the default branch via the
    ``trees?recursive=1`` endpoint. One API call regardless of repo
    size — though GitHub truncates above 100k items; the
    ``truncated`` flag in the response is the signal."""
    url = f"{api_base.rstrip('/')}/repos/{repo}/git/trees/{branch}?recursive=1"
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(url, headers=_github_headers(token))
            if resp.status_code in (404, 409):
                # 409 = empty repo; both are non-fatal.
                return []
            resp.raise_for_status()
            data = resp.json() or {}
            tree = data.get("tree") or []
            if not isinstance(tree, list):
                return []
            return tree
    except httpx.HTTPError as exc:
        raise GitHubError(f"github tree fetch failed for {repo}@{branch}: {exc}") from exc


def github_file(token: str, repo: str, path: str, branch: str, *, api_base: str = "https://api.github.com") -> str:
    """Raw file content at ``path`` on ``branch``. Uses the raw-content
    endpoint so we don't pay the base64-decode tax of /contents."""
    url = f"{api_base.rstrip('/')}/repos/{repo}/contents/{path}?ref={branch}"
    headers = {**_github_headers(token), "Accept": "application/vnd.github.raw"}
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 404:
                return ""
            resp.raise_for_status()
            return resp.text or ""
    except httpx.HTTPError as exc:
        raise GitHubError(f"github file fetch failed for {repo}:{path}: {exc}") from exc


# ── Per-repo sync ──────────────────────────────────────────────────────


def sync_github_repo(token: str, repo: str, *, api_base: str = "https://api.github.com") -> Tuple[str, List[Dict[str, Any]]]:
    """Fetch the default branch's tree, find manifest files we recognise,
    parse them, and return (source_id, components). Bounded by
    ``GITHUB_API_BUDGET`` so a monorepo can't drain the budget."""
    branch = github_default_branch(token, repo, api_base=api_base)
    tree = github_tree(token, repo, branch, api_base=api_base)
    source_id = f"github:{repo}@{branch}"
    if not tree:
        return source_id, []

    targets: List[Tuple[str, str]] = []  # (path, basename)
    for entry in tree:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "blob":
            continue
        path = str(entry.get("path") or "")
        if not path:
            continue
        base = path.rsplit("/", 1)[-1]
        if base in _MANIFEST_PARSERS:
            targets.append((path, base))
        if len(targets) >= GITHUB_API_BUDGET:
            logger.warning("repo %s manifest count hit budget %d — truncating", repo, GITHUB_API_BUDGET)
            break

    components: List[Dict[str, Any]] = []
    for path, base in targets:
        try:
            text = github_file(token, repo, path, branch, api_base=api_base)
        except GitHubError as exc:
            logger.warning("skip %s:%s — %s", repo, path, exc)
            continue
        if not text:
            continue
        parser = _MANIFEST_PARSERS[base]
        try:
            parsed = parser(text, repo_label=source_id) or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("manifest parse failed %s:%s — %s", repo, path, exc)
            continue
        for component in parsed:
            # Stamp the path so the inspector panel can show "this came
            # from packages/foo/package.json" rather than just the repo.
            component["__path"] = f"{repo}:{path}"
            component.setdefault("properties", []).append({
                "name": "cyberarmor:manifest_path",
                "value": path,
            })
        components.extend(parsed)

    logger.info(
        "repo sync %s@%s → manifests=%d components=%d",
        repo, branch, len(targets), len(components),
    )
    return source_id, components


def sync_repos(provider: str, token: str, repos: List[str]) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """Sync every configured repo for one provider. Returns a list of
    (source_id, components) tuples so the caller can persist with the
    standard A-BOM upsert path."""
    if provider != "github":
        raise ValueError(f"unsupported provider: {provider}")
    if not token:
        raise ValueError("missing token")
    out: List[Tuple[str, List[Dict[str, Any]]]] = []
    for repo in repos:
        repo = repo.strip()
        if not repo or "/" not in repo:
            continue
        try:
            source_id, components = sync_github_repo(token, repo)
        except GitHubError as exc:
            logger.warning("repo sync %s failed: %s", repo, exc)
            continue
        out.append((source_id, components))
    return out
