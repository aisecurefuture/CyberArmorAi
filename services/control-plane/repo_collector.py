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
    if provider not in ("github", "gitlab", "azure_devops"):
        raise ValueError(f"unsupported provider: {provider}")
    if not token:
        raise ValueError("missing token")
    sync_fn = {
        "github": sync_github_repo,
        "gitlab": sync_gitlab_repo,
        "azure_devops": sync_azure_repo,
    }[provider]
    out: List[Tuple[str, List[Dict[str, Any]]]] = []
    for repo in repos:
        repo = repo.strip()
        if not repo or "/" not in repo:
            continue
        try:
            source_id, components = sync_fn(token, repo)
        except (GitHubError, GitLabError, AzureRepoError) as exc:
            logger.warning("repo sync %s failed: %s", repo, exc)
            continue
        out.append((source_id, components))
    return out


# ── GitLab client ──────────────────────────────────────────────────────


class GitLabError(Exception):
    pass


def _gitlab_headers(token: str) -> Dict[str, str]:
    return {
        "PRIVATE-TOKEN": token,
        "Accept": "application/json",
        "User-Agent": "CyberArmor-A-BOM/1.0",
    }


def _gitlab_project_id(token: str, project_path: str, *, api_base: str = "https://gitlab.com/api/v4") -> str:
    """GitLab keys most APIs on numeric project ID *or* URL-encoded
    path. URL-encoded is fine for everything we need so we just
    quote-plus the slash."""
    return project_path.replace("/", "%2F")


def sync_gitlab_repo(token: str, project_path: str, *, api_base: str = "https://gitlab.com/api/v4") -> Tuple[str, List[Dict[str, Any]]]:
    """Sync one GitLab project. ``project_path`` is ``group/subgroup/project``
    (URL-encoded for the API). Uses the repository tree endpoint with
    ``recursive=true`` and pagination."""
    pid = _gitlab_project_id(token, project_path)
    # Pull project info for the default branch.
    info_url = f"{api_base.rstrip('/')}/projects/{pid}"
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(info_url, headers=_gitlab_headers(token))
            if resp.status_code == 404:
                raise GitLabError(f"gitlab project not found or token lacks access: {project_path}")
            if resp.status_code == 401:
                raise GitLabError("gitlab token unauthorized")
            resp.raise_for_status()
            branch = str(resp.json().get("default_branch") or DEFAULT_BRANCH_FALLBACK)
    except httpx.HTTPError as exc:
        raise GitLabError(f"gitlab project lookup failed: {exc}") from exc

    source_id = f"gitlab:{project_path}@{branch}"

    # Walk the tree. GitLab paginates at 100 per page; budget cap kicks in.
    tree_url = f"{api_base.rstrip('/')}/projects/{pid}/repository/tree"
    targets: List[Tuple[str, str]] = []
    page = 1
    try:
        with httpx.Client(timeout=20.0) as client:
            while page < 50:  # hard ceiling
                resp = client.get(
                    tree_url,
                    headers=_gitlab_headers(token),
                    params={"recursive": "true", "per_page": "100", "page": str(page), "ref": branch},
                )
                if resp.status_code == 404:
                    break
                resp.raise_for_status()
                entries = resp.json() or []
                if not isinstance(entries, list) or not entries:
                    break
                for entry in entries:
                    if not isinstance(entry, dict) or entry.get("type") != "blob":
                        continue
                    path = str(entry.get("path") or "")
                    base = path.rsplit("/", 1)[-1]
                    if base in _MANIFEST_PARSERS:
                        targets.append((path, base))
                        if len(targets) >= GITHUB_API_BUDGET:
                            break
                if len(targets) >= GITHUB_API_BUDGET or len(entries) < 100:
                    break
                page += 1
    except httpx.HTTPError as exc:
        raise GitLabError(f"gitlab tree fetch failed for {project_path}@{branch}: {exc}") from exc

    # Fetch + parse each manifest.
    components: List[Dict[str, Any]] = []
    file_url = f"{api_base.rstrip('/')}/projects/{pid}/repository/files"
    for path, base in targets:
        url = f"{file_url}/{path.replace('/', '%2F')}/raw"
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.get(url, headers=_gitlab_headers(token), params={"ref": branch})
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                text = resp.text or ""
        except httpx.HTTPError as exc:
            logger.warning("skip gitlab %s:%s — %s", project_path, path, exc)
            continue
        try:
            parsed = _MANIFEST_PARSERS[base](text, repo_label=source_id) or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("manifest parse failed %s:%s — %s", project_path, path, exc)
            continue
        for component in parsed:
            component["__path"] = f"{project_path}:{path}"
            component.setdefault("properties", []).append(
                {"name": "cyberarmor:manifest_path", "value": path}
            )
        components.extend(parsed)

    logger.info("gitlab sync %s@%s → manifests=%d components=%d",
                project_path, branch, len(targets), len(components))
    return source_id, components


# ── Azure DevOps client ────────────────────────────────────────────────


class AzureRepoError(Exception):
    pass


def _azure_auth(token: str) -> httpx.BasicAuth:
    """Azure DevOps PAT is sent as Basic auth with the PAT as the
    password and an empty username. httpx handles the encoding."""
    return httpx.BasicAuth("", token)


def sync_azure_repo(token: str, project_path: str, *, api_base: str = "https://dev.azure.com") -> Tuple[str, List[Dict[str, Any]]]:
    """Sync one Azure DevOps repo. ``project_path`` shape:
    ``org/project/repo``. Walks the default-branch items endpoint."""
    parts = project_path.split("/")
    if len(parts) != 3:
        raise AzureRepoError(
            f"azure repo path must be org/project/repo (got: {project_path})"
        )
    org, project, repo = parts
    auth = _azure_auth(token)
    base = f"{api_base.rstrip('/')}/{org}/{project}/_apis/git/repositories/{repo}"

    # Default branch (drop the refs/heads/ prefix).
    try:
        with httpx.Client(timeout=15.0, auth=auth) as client:
            resp = client.get(f"{base}?api-version=7.1")
            if resp.status_code == 404:
                raise AzureRepoError(f"azure repo not found or token lacks access: {project_path}")
            if resp.status_code in (401, 203):
                raise AzureRepoError("azure devops token unauthorized")
            resp.raise_for_status()
            default_ref = str(resp.json().get("defaultBranch") or "")
            branch = default_ref.removeprefix("refs/heads/") or DEFAULT_BRANCH_FALLBACK
    except httpx.HTTPError as exc:
        raise AzureRepoError(f"azure default-branch lookup failed: {exc}") from exc

    source_id = f"azure:{project_path}@{branch}"

    # Recursive items list. ``recursionLevel=Full`` gives us every file.
    items_url = f"{base}/items"
    try:
        with httpx.Client(timeout=30.0, auth=auth) as client:
            resp = client.get(items_url, params={
                "scopePath": "/",
                "recursionLevel": "Full",
                "versionDescriptor.version": branch,
                "api-version": "7.1",
            })
            if resp.status_code == 404:
                return source_id, []
            resp.raise_for_status()
            items = resp.json().get("value") or []
    except httpx.HTTPError as exc:
        raise AzureRepoError(f"azure tree fetch failed for {project_path}@{branch}: {exc}") from exc

    targets: List[Tuple[str, str]] = []
    for item in items:
        if not isinstance(item, dict) or item.get("isFolder"):
            continue
        path = str(item.get("path") or "").lstrip("/")
        if not path:
            continue
        basename = path.rsplit("/", 1)[-1]
        if basename in _MANIFEST_PARSERS:
            targets.append((path, basename))
            if len(targets) >= GITHUB_API_BUDGET:
                break

    components: List[Dict[str, Any]] = []
    for path, basename in targets:
        try:
            with httpx.Client(timeout=15.0, auth=auth) as client:
                resp = client.get(items_url, params={
                    "path": "/" + path,
                    "$format": "octetStream",
                    "versionDescriptor.version": branch,
                    "api-version": "7.1",
                    "includeContent": "true",
                })
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                text = resp.text or ""
        except httpx.HTTPError as exc:
            logger.warning("skip azure %s:%s — %s", project_path, path, exc)
            continue
        try:
            parsed = _MANIFEST_PARSERS[basename](text, repo_label=source_id) or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("manifest parse failed %s:%s — %s", project_path, path, exc)
            continue
        for component in parsed:
            component["__path"] = f"{project_path}:{path}"
            component.setdefault("properties", []).append(
                {"name": "cyberarmor:manifest_path", "value": path}
            )
        components.extend(parsed)

    logger.info("azure sync %s@%s → manifests=%d components=%d",
                project_path, branch, len(targets), len(components))
    return source_id, components
