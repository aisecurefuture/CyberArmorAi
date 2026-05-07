"""External reputation feed adapters.

The trust gate's primary detection signal is its own ML pipeline (via
the detection service). External feeds are a second opinion: cheap,
high-precision, low-recall. They're particularly valuable for the
phishing/malware dimensions where Google and Microsoft already have
massive ground-truth corpora.

Implemented:
  - Google Safe Browsing v4 (Lookup API, network-call variant). For
    high-volume deployments switch to the Update API + local hash
    cache; the interface here is shaped to allow that drop-in.

Stubbed (TODO):
  - Microsoft Defender / SmartScreen indicator API.
  - VirusTotal v3 url/{id} (rate-limited; cache aggressively).
  - Tenant-supplied STIX/TAXII feeds.

All adapters implement ``ReputationFeed.lookup`` and ``ReputationFeed.name``;
``ReputationAggregator`` fans out concurrently and merges results into
the gate's score vector.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import List, Optional, Protocol, runtime_checkable

import httpx

logger = logging.getLogger("url_trust_gate.feeds")


@dataclass
class FeedVerdict:
    feed: str
    matched: bool = False
    threat_types: List[str] = field(default_factory=list)
    confidence: float = 0.0
    raw: Optional[dict] = None


@runtime_checkable
class ReputationFeed(Protocol):
    name: str

    async def lookup(self, url: str) -> FeedVerdict: ...


# ---------------------------------------------------------------------------
# Google Safe Browsing v4
# ---------------------------------------------------------------------------


class SafeBrowsingFeed:
    """Google Safe Browsing v4 Lookup API client.

    Configure with ``SAFE_BROWSING_API_KEY``. Returns a feed verdict
    indicating whether the URL is in any of the threat lists (MALWARE,
    SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION).
    """

    name = "google-safe-browsing"
    ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    THREAT_TYPES = [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
    ]

    def __init__(
        self,
        api_key: Optional[str] = None,
        client_id: str = "cyberarmor-url-trust-gate",
        client_version: str = "0.1.0",
        timeout_s: float = 1.5,
    ):
        self._api_key = api_key or os.getenv("SAFE_BROWSING_API_KEY", "")
        self._client_id = client_id
        self._client_version = client_version
        self._timeout_s = timeout_s

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    async def lookup(self, url: str) -> FeedVerdict:
        if not self._api_key:
            return FeedVerdict(feed=self.name)

        body = {
            "client": {
                "clientId": self._client_id,
                "clientVersion": self._client_version,
            },
            "threatInfo": {
                "threatTypes": self.THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout_s, trust_env=False) as c:
                resp = await c.post(
                    f"{self.ENDPOINT}?key={self._api_key}",
                    json=body,
                )
                if resp.status_code != 200:
                    logger.debug(
                        "safe_browsing non-200 status=%s body=%s",
                        resp.status_code,
                        resp.text[:200],
                    )
                    return FeedVerdict(feed=self.name)
                data = resp.json() or {}
                matches = data.get("matches", []) or []
                if not matches:
                    return FeedVerdict(feed=self.name)
                threat_types = sorted({m.get("threatType", "") for m in matches if m.get("threatType")})
                return FeedVerdict(
                    feed=self.name,
                    matched=True,
                    threat_types=threat_types,
                    # Safe Browsing matches are very high precision.
                    confidence=0.95,
                    raw=data,
                )
        except Exception as exc:
            logger.debug("safe_browsing unreachable err=%s", exc)
            return FeedVerdict(feed=self.name)


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


@dataclass
class AggregatedReputation:
    matched: bool = False
    phishing: float = 0.0
    malware: float = 0.0
    threat_types: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    elapsed_ms: int = 0


class ReputationAggregator:
    """Fan out across configured feeds and merge into score deltas.

    Latency-bounded: if a feed exceeds its timeout it's silently dropped.
    """

    def __init__(self, feeds: Optional[List[ReputationFeed]] = None):
        self._feeds = feeds or []

    def add(self, feed: ReputationFeed) -> None:
        self._feeds.append(feed)

    @classmethod
    def from_env(cls) -> "ReputationAggregator":
        feeds: List[ReputationFeed] = []
        sb = SafeBrowsingFeed()
        if sb.configured:
            feeds.append(sb)
        # TODO: add SmartScreen / VirusTotal / STIX/TAXII adapters here
        # once their credentials are wired through the secrets service.
        return cls(feeds)

    async def lookup(self, url: str) -> AggregatedReputation:
        if not self._feeds:
            return AggregatedReputation()

        start = time.monotonic()
        results = await asyncio.gather(
            *(f.lookup(url) for f in self._feeds), return_exceptions=True
        )

        agg = AggregatedReputation()
        for r in results:
            if isinstance(r, Exception):
                continue
            if not isinstance(r, FeedVerdict):
                continue
            if not r.matched:
                continue
            agg.matched = True
            agg.sources.append(r.feed)
            for tt in r.threat_types:
                if tt and tt not in agg.threat_types:
                    agg.threat_types.append(tt)
            # Map threat-type -> score channel.
            if any(t in r.threat_types for t in ("SOCIAL_ENGINEERING",)):
                agg.phishing = max(agg.phishing, r.confidence)
            if any(t in r.threat_types for t in (
                "MALWARE",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            )):
                agg.malware = max(agg.malware, r.confidence)

        agg.elapsed_ms = int((time.monotonic() - start) * 1000)
        return agg
