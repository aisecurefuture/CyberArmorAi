"""Threat-intel feeds — KEV + EPSS.

Layered on top of the OSV vulnerability scanner. Both feeds are free,
public, and CVE-keyed; we fetch and cache them per refresh, then
enrich each advisory row before the policy evaluator runs.

KEV (CISA Known Exploited Vulnerabilities)
  ~1,200 entries, full-replace catalog. Tells us which CVEs are
  *actually being exploited in the wild*. A policy that fires on
  ``content.is_kev equals true`` is the most defensible
  "block-this-regardless-of-CVSS" gate we ship.

EPSS (FIRST.org Exploit Prediction Scoring System)
  Per-CVE probability score (0..1) that the vuln will be exploited
  in the next 30 days, plus a percentile rank. Updated daily. We
  query the JSON API per CVE batch rather than mirroring the
  300k-row bulk CSV — keeps the table light.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx

logger = logging.getLogger("cyberarmor.control_plane.threat_intel")

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# FIRST EPSS API accepts up to 100 CVEs per request via ``cve=`` repeated.
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100


def _parse_ts(raw: Any) -> Optional[datetime]:
    if raw is None or raw == "":
        return None
    s = str(raw)
    # CISA uses ISO date (YYYY-MM-DD); EPSS the same. Both parse with
    # fromisoformat — append a zone when the source omits it.
    try:
        if "T" in s:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        return datetime.fromisoformat(s + "T00:00:00+00:00")
    except (ValueError, TypeError):
        return None


def fetch_kev_catalog(*, timeout: float = 30.0) -> Dict[str, Dict[str, Any]]:
    """Pull the CISA KEV catalog. Returns ``{CVE-ID: row}`` where row
    has the fields the upsert path cares about. Best-effort: returns
    ``{}`` on any HTTP failure so a flaky upstream doesn't take down
    the rest of vuln scanning.
    """
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(
                KEV_FEED_URL,
                headers={"User-Agent": "CyberArmor-A-BOM/1.0", "Accept": "application/json"},
            )
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as exc:
        logger.warning("KEV catalog fetch failed: %s", exc)
        return {}

    out: Dict[str, Dict[str, Any]] = {}
    for entry in data.get("vulnerabilities") or []:
        if not isinstance(entry, dict):
            continue
        cve = str(entry.get("cveID") or "").strip()
        if not cve:
            continue
        out[cve] = {
            "is_kev": True,
            "kev_added_at": _parse_ts(entry.get("dateAdded")),
            "kev_due_date": _parse_ts(entry.get("dueDate")),
            "kev_action":   entry.get("requiredAction") or entry.get("shortDescription") or "",
            "kev_ransomware": entry.get("knownRansomwareCampaignUse") or "",
        }
    logger.info("KEV catalog loaded entries=%d", len(out))
    return out


def fetch_epss_scores(cve_ids: Iterable[str], *, timeout: float = 30.0) -> Dict[str, Dict[str, Any]]:
    """Query EPSS for a list of CVE IDs. The API accepts ``cve=``
    comma-separated up to 100 per call; we chunk and union the
    results. Returns ``{CVE-ID: {epss_score, epss_percentile,
    epss_updated_at}}``. Unknown CVEs are simply absent from the
    return — caller should treat missing as "no data."
    """
    out: Dict[str, Dict[str, Any]] = {}
    batch: List[str] = []
    seen: set = set()
    for raw in cve_ids:
        cve = str(raw or "").strip().upper()
        if not cve or not cve.startswith("CVE-") or cve in seen:
            continue
        seen.add(cve)
        batch.append(cve)
        if len(batch) >= EPSS_BATCH_SIZE:
            _query_epss_batch(batch, out, timeout=timeout)
            batch = []
    if batch:
        _query_epss_batch(batch, out, timeout=timeout)
    logger.info("EPSS scored cves=%d hits=%d", len(seen), len(out))
    return out


def _query_epss_batch(batch: List[str], out: Dict[str, Dict[str, Any]], *, timeout: float) -> None:
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(
                EPSS_API_URL,
                params={"cve": ",".join(batch)},
                headers={"User-Agent": "CyberArmor-A-BOM/1.0"},
            )
        resp.raise_for_status()
        payload = resp.json()
    except httpx.HTTPError as exc:
        logger.debug("EPSS batch failed: %s", exc)
        return
    for row in payload.get("data") or []:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cve") or "").strip().upper()
        if not cve:
            continue
        try:
            score = float(row.get("epss") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        try:
            percentile = float(row.get("percentile") or 0.0)
        except (TypeError, ValueError):
            percentile = 0.0
        out[cve] = {
            "epss_score": score,
            "epss_percentile": percentile,
            "epss_updated_at": _parse_ts(row.get("date")),
        }


def collect_cve_ids(vuln_id: str, aliases: Optional[List[str]]) -> List[str]:
    """Return every CVE id associated with an advisory — the primary
    id when it starts with CVE-, plus any aliases that do. GHSA-…
    advisories alias to one or more CVEs (when one exists), so we
    don't want to miss the EPSS / KEV signal just because the
    advisory's canonical id is GHSA-shaped."""
    out: List[str] = []
    if vuln_id and vuln_id.upper().startswith("CVE-"):
        out.append(vuln_id.upper())
    for a in (aliases or []):
        if a and isinstance(a, str) and a.upper().startswith("CVE-"):
            out.append(a.upper())
    # Dedup while preserving order.
    seen: set = set()
    deduped: List[str] = []
    for c in out:
        if c not in seen:
            seen.add(c)
            deduped.append(c)
    return deduped
