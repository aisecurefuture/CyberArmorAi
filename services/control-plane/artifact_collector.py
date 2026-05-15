"""Artifact-repository A-BOM collector.

Phase 4 (first slice). Walks container registries + binary repo
managers (GHCR, Docker Hub, JFrog Artifactory / Xray) and emits
CycloneDX 1.6 ``container`` components for each image:tag we see.

The control-plane uses the standard ``_abom_upsert_component`` +
``ABOMObservation`` path to land these alongside endpoint / repo
sightings — same identity_key dedup, same provenance trail.

source_kind = "container" so the Components view filter, the
Loaded-vs-Installed overlay (phase 2), and the IOC scan all light
up automatically.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("cyberarmor.control_plane.artifact_collector")

# Per-sync request ceiling so an org with 50 container repos × 100 tags
# can't pin the FastAPI thread for minutes. Matches GITHUB_API_BUDGET
# in repo_collector.py.
ARTIFACT_API_BUDGET = 200


# ── GitHub Container Registry (GHCR) ──────────────────────────────────


class GHCRError(Exception):
    pass


def _github_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "CyberArmor-A-BOM/1.0",
    }


def _ghcr_list_package_versions(
    token: str,
    org_or_user: str,
    package: str,
    *,
    is_user: bool,
    api_base: str = "https://api.github.com",
) -> List[Dict[str, Any]]:
    """List versions of a single container package. GitHub paginates 100
    at a time; we walk until exhausted or until the budget cap fires."""
    scope = "users" if is_user else "orgs"
    url = (
        f"{api_base.rstrip('/')}/{scope}/{org_or_user}/packages/container/"
        f"{package}/versions"
    )
    out: List[Dict[str, Any]] = []
    page = 1
    while page < 50:
        try:
            with httpx.Client(timeout=20.0) as client:
                resp = client.get(
                    url,
                    headers=_github_headers(token),
                    params={"per_page": "100", "page": str(page)},
                )
        except httpx.HTTPError as exc:
            raise GHCRError(f"ghcr versions fetch failed: {exc}") from exc
        if resp.status_code == 404:
            return out
        if resp.status_code in (401, 403):
            raise GHCRError(f"ghcr token unauthorized for {org_or_user}/{package}")
        if resp.status_code >= 300:
            raise GHCRError(f"ghcr versions returned {resp.status_code}")
        page_data = resp.json() or []
        if not isinstance(page_data, list) or not page_data:
            break
        out.extend(page_data)
        if len(out) >= ARTIFACT_API_BUDGET or len(page_data) < 100:
            break
        page += 1
    return out[:ARTIFACT_API_BUDGET]


def _ghcr_list_packages(token: str, owner: str, *, is_user: bool, api_base: str = "https://api.github.com") -> List[str]:
    """Enumerate container packages for a single owner. Used when the
    config says ``ghcr:my-org/*`` (wildcard) so we can fan out without
    the operator listing every repo by hand."""
    scope = "users" if is_user else "orgs"
    url = f"{api_base.rstrip('/')}/{scope}/{owner}/packages"
    out: List[str] = []
    page = 1
    while page < 20:
        try:
            with httpx.Client(timeout=20.0) as client:
                resp = client.get(
                    url,
                    headers=_github_headers(token),
                    params={"package_type": "container", "per_page": "100", "page": str(page)},
                )
        except httpx.HTTPError as exc:
            raise GHCRError(f"ghcr package list failed: {exc}") from exc
        if resp.status_code == 404:
            break
        if resp.status_code in (401, 403):
            raise GHCRError(f"ghcr token unauthorized for {owner} package list")
        if resp.status_code >= 300:
            break
        rows = resp.json() or []
        if not isinstance(rows, list) or not rows:
            break
        for row in rows:
            name = row.get("name") if isinstance(row, dict) else None
            if name:
                out.append(str(name))
        if len(rows) < 100:
            break
        page += 1
    return out


def sync_ghcr_package(token: str, package_ref: str, *, api_base: str = "https://api.github.com") -> List[Tuple[str, List[Dict[str, Any]]]]:
    """Sync one GHCR package reference.

    ``package_ref`` forms accepted:
      ``ghcr:my-org/my-image``           single image, all tags
      ``ghcr:my-org/*``                   every container package the owner publishes
      ``ghcr:my-user/my-image:type=user`` single image owned by a user (not org)

    Returns a list of (source_id, components) tuples so a wildcard
    expansion can produce multiple observations within one config entry.
    """
    if not package_ref.startswith("ghcr:"):
        raise GHCRError(f"not a ghcr ref: {package_ref}")
    rest = package_ref[len("ghcr:"):]
    is_user = False
    if ":type=user" in rest:
        rest = rest.replace(":type=user", "")
        is_user = True
    if "/" not in rest:
        raise GHCRError(f"expected ghcr:<owner>/<image>, got {package_ref}")
    owner, image = rest.split("/", 1)
    images: List[str] = [image] if image != "*" else _ghcr_list_packages(token, owner, is_user=is_user, api_base=api_base)
    out: List[Tuple[str, List[Dict[str, Any]]]] = []

    for img in images:
        try:
            versions = _ghcr_list_package_versions(token, owner, img, is_user=is_user, api_base=api_base)
        except GHCRError as exc:
            logger.warning("ghcr version list failed for %s/%s: %s", owner, img, exc)
            continue
        components: List[Dict[str, Any]] = []
        for v in versions:
            if not isinstance(v, dict):
                continue
            name = str(v.get("name") or "")  # digest sha256:...
            metadata = v.get("metadata") or {}
            container = metadata.get("container") or {} if isinstance(metadata, dict) else {}
            tags = container.get("tags") if isinstance(container, dict) else []
            if not isinstance(tags, list):
                tags = []
            # One component per (image, tag). A digest with no tag still
            # surfaces — handy for "untagged image still referenced
            # somewhere" forensic queries.
            target_tags: List[Optional[str]] = tags or [None]
            for tag in target_tags:
                qualifier = tag or name.replace(":", "_") or "unknown"
                full = f"ghcr.io/{owner}/{img}"
                components.append({
                    "type": "container",
                    "name": f"{owner}/{img}",
                    "version": qualifier,
                    "purl": f"pkg:oci/{owner}%2F{img}@{qualifier}?repository_url=ghcr.io",
                    "hashes": [{"alg": "SHA-256", "content": name.removeprefix("sha256:")}]
                                if name.startswith("sha256:") else [],
                    "properties": [
                        {"name": "cyberarmor:registry", "value": "ghcr"},
                        {"name": "cyberarmor:repository", "value": full},
                        {"name": "cyberarmor:digest", "value": name},
                        {"name": "cyberarmor:tag", "value": tag or ""},
                        {"name": "cyberarmor:created_at", "value": str(v.get("created_at") or "")},
                    ],
                    "__path": f"{full}:{qualifier}",
                })
        if components:
            out.append((f"ghcr:{owner}/{img}", components))
    logger.info("ghcr sync %s → images=%d total_components=%d",
                package_ref, len(images),
                sum(len(c) for _, c in out))
    return out


# ── JFrog Artifactory / Xray ──────────────────────────────────────────


class JFrogError(Exception):
    pass


def _jfrog_headers(token: str) -> Dict[str, str]:
    """JFrog supports a Bearer token (access token) for the REST API.
    Older deployments use Basic; the operator chooses by giving us
    either a ``user:password`` (caller pre-encodes) or a bare token."""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "CyberArmor-A-BOM/1.0",
    }


def sync_jfrog_repo(token: str, repo_ref: str, *, base_url: str = "") -> List[Tuple[str, List[Dict[str, Any]]]]:
    """Sync one Artifactory repository.

    ``repo_ref`` shape: ``jfrog:<repo_name>`` and ``base_url`` should be
    the Artifactory host (e.g. ``https://acme.jfrog.io/artifactory``).
    For Xray-enabled deployments the operator can swap in
    ``https://acme.jfrog.io/xray`` and we'll use the SBOM-export
    endpoint instead.

    Lists every artifact in the repo's storage tree and emits one
    component per (artifact, version). v1 supports docker / generic;
    npm / pypi / maven layouts produce similar shapes but with
    package-type-specific PURLs which we'll layer in next.
    """
    if not repo_ref.startswith("jfrog:"):
        raise JFrogError(f"not a jfrog ref: {repo_ref}")
    if not base_url:
        raise JFrogError("jfrog base_url required")
    repo = repo_ref[len("jfrog:"):]
    api_base = base_url.rstrip("/")
    # /api/storage/<repo>/?list&deep=1&listFolders=0&mdTimestamps=1
    list_url = f"{api_base}/api/storage/{repo}"
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(
                list_url,
                headers=_jfrog_headers(token),
                params={"list": "", "deep": "1", "listFolders": "0", "mdTimestamps": "1"},
            )
    except httpx.HTTPError as exc:
        raise JFrogError(f"jfrog list failed: {exc}") from exc
    if resp.status_code == 404:
        return []
    if resp.status_code in (401, 403):
        raise JFrogError(f"jfrog token unauthorized for {repo}")
    if resp.status_code >= 300:
        raise JFrogError(f"jfrog list returned {resp.status_code}: {resp.text[:200]}")
    data = resp.json() or {}
    files = data.get("files") if isinstance(data, dict) else []
    if not isinstance(files, list):
        return []

    components: List[Dict[str, Any]] = []
    for entry in files[:ARTIFACT_API_BUDGET]:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("uri") or "").lstrip("/")
        if not path:
            continue
        sha256 = str(entry.get("sha256") or "")
        size = entry.get("size") or 0
        # Heuristic: split path into name + version where the last
        # segment is the filename and the parent dir is the version.
        # Good enough for docker / generic layouts; refined per
        # package type later.
        parts = path.split("/")
        name = parts[-1] if parts else path
        version = parts[-2] if len(parts) >= 2 else ""
        component: Dict[str, Any] = {
            "type": "container" if path.endswith(("/manifest.json", "/layer.tar.gz", ".tgz")) else "library",
            "name": f"{repo}/{name}",
            "version": version,
            "purl": f"pkg:generic/{repo}%2F{name}@{version}" if version else f"pkg:generic/{repo}%2F{name}",
            "properties": [
                {"name": "cyberarmor:registry", "value": "jfrog"},
                {"name": "cyberarmor:repository", "value": repo},
                {"name": "cyberarmor:artifact_path", "value": path},
                {"name": "cyberarmor:size_bytes", "value": str(size)},
            ],
            "__path": f"{repo}:{path}",
        }
        if sha256:
            component["hashes"] = [{"alg": "SHA-256", "content": sha256}]
        components.append(component)

    logger.info("jfrog sync %s → artifacts=%d", repo, len(components))
    return [(f"jfrog:{repo}", components)] if components else []


# ── Dispatch ──────────────────────────────────────────────────────────


def sync_artifact_source(
    provider: str,
    token: str,
    refs: List[str],
    *,
    base_url: str = "",
) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """Run one artifact provider over its configured refs. Returns the
    standard list-of-tuples shape so the FastAPI handler can drop the
    output straight into the existing _abom_upsert_component path."""
    if provider not in ("ghcr", "jfrog"):
        raise ValueError(f"unsupported artifact provider: {provider}")
    if not token:
        raise ValueError("missing token")
    out: List[Tuple[str, List[Dict[str, Any]]]] = []
    for ref in refs:
        ref = ref.strip()
        if not ref:
            continue
        try:
            if provider == "ghcr":
                out.extend(sync_ghcr_package(token, ref))
            elif provider == "jfrog":
                out.extend(sync_jfrog_repo(token, ref, base_url=base_url))
        except (GHCRError, JFrogError) as exc:
            logger.warning("artifact sync %s failed: %s", ref, exc)
            continue
    return out
