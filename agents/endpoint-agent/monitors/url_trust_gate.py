"""URL Trust Gate integration for the endpoint agent.

Two responsibilities:

1. **Outbound advisory.** When the network monitor sees an outbound TCP
   connection that maps to a known domain, this module asks the
   centralised URL Trust Gate service whether the destination is safe
   for AI ingestion (prompt injection / promptware / phishing). The
   verdict is reported as a telemetry event; high-severity verdicts
   trigger a local toast via the platform notifier.

2. **Local query daemon.** Exposes a loopback-only HTTP endpoint
   (default ``http://127.0.0.1:48515/v1/url``) that other software on
   the endpoint — IDE extensions, custom AI agents, CLI tools, MCP
   clients — can call BEFORE making an outbound request. The daemon
   round-trips to the central gate and caches verdicts locally so
   repeated queries don't add latency.

The daemon binds 127.0.0.1 by default. Production installs may switch
to a Unix domain socket (``/var/run/cyberarmor/url-trust-gate.sock``)
for stronger isolation; the socket path is configurable.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import socket
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

import httpx

if TYPE_CHECKING:
    from agent import EndpointAgent

logger = logging.getLogger("cyberarmor.monitors.url_trust_gate")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DAEMON_HOST = os.getenv("CYBERARMOR_URL_TRUST_GATE_DAEMON_HOST", "127.0.0.1")
DAEMON_PORT = int(os.getenv("CYBERARMOR_URL_TRUST_GATE_DAEMON_PORT", "48515"))
GATE_URL = os.getenv("CYBERARMOR_URL_TRUST_GATE_URL", "http://localhost:8005/evaluate")
GATE_API_KEY_ENV = "CYBERARMOR_URL_TRUST_GATE_API_KEY"
GATE_REQUEST_TIMEOUT_S = float(os.getenv("CYBERARMOR_URL_TRUST_GATE_TIMEOUT_S", "1.5"))
LOCAL_CACHE_TTL_S = int(os.getenv("CYBERARMOR_URL_TRUST_GATE_CACHE_TTL_S", "300"))
LOCAL_CACHE_MAX = int(os.getenv("CYBERARMOR_URL_TRUST_GATE_CACHE_MAX", "2048"))


# ---------------------------------------------------------------------------
# Local LRU+TTL cache
# ---------------------------------------------------------------------------


@dataclass
class _CacheEntry:
    verdict: Dict[str, Any]
    stored_at: float


class _LocalCache:
    """Thread-safe LRU+TTL cache. Replaces a Redis dependency on the endpoint."""

    def __init__(self, ttl_s: int, max_entries: int):
        self._ttl = ttl_s
        self._max = max_entries
        self._lock = threading.Lock()
        self._items: "OrderedDict[str, _CacheEntry]" = OrderedDict()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        now = time.monotonic()
        with self._lock:
            entry = self._items.get(key)
            if entry is None:
                return None
            if now - entry.stored_at > self._ttl:
                self._items.pop(key, None)
                return None
            self._items.move_to_end(key)
            return entry.verdict

    def put(self, key: str, verdict: Dict[str, Any]) -> None:
        with self._lock:
            self._items[key] = _CacheEntry(verdict=verdict, stored_at=time.monotonic())
            self._items.move_to_end(key)
            while len(self._items) > self._max:
                self._items.popitem(last=False)


# ---------------------------------------------------------------------------
# Gate client
# ---------------------------------------------------------------------------


class URLTrustGateClient:
    """Async HTTP client for the centralised URL Trust Gate service."""

    def __init__(
        self,
        gate_url: str,
        api_key: str,
        tenant_id: str,
        timeout_s: float = GATE_REQUEST_TIMEOUT_S,
    ):
        self._gate_url = gate_url
        self._api_key = api_key
        self._tenant_id = tenant_id
        self._timeout_s = timeout_s
        self._cache = _LocalCache(ttl_s=LOCAL_CACHE_TTL_S, max_entries=LOCAL_CACHE_MAX)
        # Reuse a single AsyncClient per process. Connection pooling matters
        # because every outbound URL query lands here.
        self._http: Optional[httpx.AsyncClient] = None

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            # IMPORTANT: trust_env=False so the agent's outbound calls to
            # the gate aren't routed back through any user-configured
            # proxy. The gate itself must be reachable directly.
            self._http = httpx.AsyncClient(
                timeout=self._timeout_s,
                trust_env=False,
                http2=False,
            )
        return self._http

    async def close(self) -> None:
        if self._http is not None and not self._http.is_closed:
            await self._http.aclose()

    async def evaluate(
        self,
        url: str,
        *,
        source: str,
        depth: str = "fast",
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        agent_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        cache_key = f"{depth}|{url}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        payload = {
            "tenant_id": self._tenant_id,
            "url": url,
            "source": f"endpoint-agent:{source}",
            "depth": depth,
            "context": _strip_none(
                {"process_name": process_name, "pid": pid, "agent_id": agent_id}
            ),
        }

        try:
            client = await self._client()
            resp = await client.post(
                self._gate_url,
                json=payload,
                headers={"x-api-key": self._api_key},
            )
            if resp.status_code != 200:
                logger.debug(
                    "url_trust_gate non-200 status=%s body=%s",
                    resp.status_code,
                    resp.text[:200],
                )
                return None
            verdict = resp.json()
            self._cache.put(cache_key, verdict)
            return verdict
        except Exception as exc:
            # Fail open. Reachability is monitored separately so an outage
            # doesn't silently drop endpoint coverage.
            logger.debug("url_trust_gate unreachable err=%s", exc)
            return None


# ---------------------------------------------------------------------------
# Network monitor adapter — called by NetworkMonitor for outbound connections
# ---------------------------------------------------------------------------


class URLTrustGateAdvisor:
    """Glue between the network monitor and the gate client.

    The network monitor only sees (ip, port, pid). We map back to a
    domain via reverse DNS where possible, then query the gate at
    ``depth=fast`` so we don't stall the monitor's poll loop.
    """

    def __init__(self, agent: "EndpointAgent", client: URLTrustGateClient):
        self._agent = agent
        self._client = client
        # Don't re-query the same (domain, pid) combo within the local
        # cache TTL. The gate-side cache also dedups but we want to avoid
        # the round trip entirely.
        self._asked: Dict[Tuple[str, Optional[int]], float] = {}

    async def advise(
        self,
        *,
        remote_ip: str,
        remote_port: int,
        domain: Optional[str],
        pid: Optional[int],
        process_name: Optional[str],
    ) -> None:
        host = domain or remote_ip
        if not host or _is_internal_destination(host):
            return

        scheme = "https" if remote_port in {443, 8443} else "http"
        url = f"{scheme}://{host}"
        if remote_port not in {80, 443, 8080, 8443}:
            url += f":{remote_port}"

        key = (url, pid)
        now = time.monotonic()
        last = self._asked.get(key, 0)
        if now - last < LOCAL_CACHE_TTL_S:
            return
        self._asked[key] = now
        if len(self._asked) > LOCAL_CACHE_MAX:
            # Cheap eviction.
            cutoff = now - LOCAL_CACHE_TTL_S
            self._asked = {k: v for k, v in self._asked.items() if v > cutoff}

        verdict = await self._client.evaluate(
            url,
            source="network-monitor",
            depth="fast",
            process_name=process_name,
            pid=pid,
            agent_id=getattr(self._agent, "agent_id", None),
        )
        if verdict is None:
            return

        decision = (verdict.get("decision") or {}).get("action", "allow")
        if decision == "allow":
            return

        severity = "high" if decision in {"block", "isolate"} else "medium"
        await self._agent.report_event(
            {
                "source": "url_trust_gate",
                "event_type": "url_trust_gate_verdict",
                "url": url,
                "domain": domain,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "process_name": process_name,
                "pid": pid,
                "decision": decision,
                "reason": (verdict.get("decision") or {}).get("reason", ""),
                "evidence_id": verdict.get("evidence_id"),
                "scores": verdict.get("scores", {}),
                "severity": severity,
            }
        )


# ---------------------------------------------------------------------------
# Local query daemon — loopback HTTP for local clients
# ---------------------------------------------------------------------------


class LocalQueryDaemon:
    """Loopback HTTP daemon clients can call BEFORE making outbound requests.

    Only accepts connections from 127.0.0.1 (or the configured Unix
    socket path). The daemon never echoes its own bind address to
    untrusted callers.
    """

    def __init__(
        self,
        client: URLTrustGateClient,
        host: str = DAEMON_HOST,
        port: int = DAEMON_PORT,
    ):
        self._client = client
        self._host = host
        self._port = port
        self._server: Optional[asyncio.base_events.Server] = None

    async def start(self) -> None:
        # Belt-and-braces: even though we're binding 127.0.0.1, refuse to
        # start if someone has overridden the host to a non-loopback
        # address. The endpoint agent has full system privileges and this
        # daemon must NEVER be reachable off-box.
        try:
            ip = ipaddress.ip_address(self._host)
            if not ip.is_loopback:
                raise RuntimeError(
                    f"Refusing to bind URL Trust Gate daemon to non-loopback host {self._host}"
                )
        except ValueError as exc:
            raise RuntimeError(
                f"Invalid host for URL Trust Gate daemon: {self._host}"
            ) from exc

        self._server = await asyncio.start_server(
            self._handle, host=self._host, port=self._port
        )
        logger.info(
            "URL Trust Gate local daemon listening on %s:%d", self._host, self._port
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        with contextlib.suppress(Exception):
            await self._server.wait_closed()
        self._server = None

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        try:
            # Reject any peer whose address isn't loopback. Defence in
            # depth — we already bind to 127.0.0.1 but a misconfigured
            # listener should still refuse non-local peers.
            if peer and isinstance(peer, tuple):
                try:
                    if not ipaddress.ip_address(peer[0]).is_loopback:
                        await self._write_response(
                            writer, 403, {"error": "non-loopback peer rejected"}
                        )
                        return
                except ValueError:
                    await self._write_response(
                        writer, 403, {"error": "invalid peer"}
                    )
                    return

            request_line = await asyncio.wait_for(reader.readline(), timeout=2.0)
            if not request_line:
                return
            try:
                method, path, _ = request_line.decode().split(" ", 2)
            except ValueError:
                await self._write_response(writer, 400, {"error": "bad request line"})
                return

            # Drain headers; capture content-length.
            content_length = 0
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if line in (b"\r\n", b"\n", b""):
                    break
                lower = line.decode("latin-1").lower()
                if lower.startswith("content-length:"):
                    try:
                        content_length = int(lower.split(":", 1)[1].strip())
                    except ValueError:
                        content_length = 0

            body = b""
            if content_length > 0:
                # Hard cap. The local daemon takes only tiny JSON payloads.
                if content_length > 16_384:
                    await self._write_response(
                        writer, 413, {"error": "payload too large"}
                    )
                    return
                body = await asyncio.wait_for(
                    reader.readexactly(content_length), timeout=2.0
                )

            if method == "GET" and path.startswith("/health"):
                await self._write_response(writer, 200, {"status": "ok"})
                return

            if method != "POST" or not path.startswith("/v1/url"):
                await self._write_response(writer, 404, {"error": "not found"})
                return

            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                await self._write_response(writer, 400, {"error": "invalid json"})
                return

            url = payload.get("url")
            if not isinstance(url, str) or not url:
                await self._write_response(
                    writer, 400, {"error": "url required (string)"}
                )
                return

            depth = payload.get("depth", "fast")
            if depth not in {"fast", "standard", "deep"}:
                depth = "fast"

            verdict = await self._client.evaluate(
                url,
                source=f"local:{payload.get('client', 'unknown')}",
                depth=depth,
                process_name=payload.get("process_name"),
                pid=payload.get("pid"),
            )

            if verdict is None:
                # Local clients should fail-open if they want to, but they
                # need to know the gate was unreachable so they can log it.
                await self._write_response(
                    writer,
                    503,
                    {"error": "gate_unreachable", "fail_open": True},
                )
                return

            await self._write_response(writer, 200, verdict)
        except asyncio.TimeoutError:
            with contextlib.suppress(Exception):
                await self._write_response(writer, 408, {"error": "timeout"})
        except Exception as exc:
            logger.warning("daemon handler error err=%s", exc)
            with contextlib.suppress(Exception):
                await self._write_response(writer, 500, {"error": "internal"})
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    @staticmethod
    async def _write_response(
        writer: asyncio.StreamWriter, status: int, body: Dict[str, Any]
    ) -> None:
        body_bytes = json.dumps(body).encode("utf-8")
        reason = {200: "OK", 400: "Bad Request", 403: "Forbidden",
                  404: "Not Found", 408: "Request Timeout", 413: "Payload Too Large",
                  500: "Internal Server Error", 503: "Service Unavailable"}.get(
            status, "Status"
        )
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin-1")
        writer.write(head + body_bytes)
        with contextlib.suppress(Exception):
            await writer.drain()


# ---------------------------------------------------------------------------
# Top-level monitor task — what agent.py spawns
# ---------------------------------------------------------------------------


class URLTrustGateMonitor:
    """Composite that owns the gate client + local daemon as one task."""

    def __init__(self, agent: "EndpointAgent"):
        self._agent = agent
        api_key = os.getenv(GATE_API_KEY_ENV) or os.getenv("AGENT_API_KEY", "")
        tenant_id = os.getenv("TENANT_ID", "default")
        self._client = URLTrustGateClient(
            gate_url=GATE_URL,
            api_key=api_key,
            tenant_id=tenant_id,
        )
        self._daemon = LocalQueryDaemon(self._client)
        # Expose the advisor on the agent so NetworkMonitor can call it.
        self._advisor = URLTrustGateAdvisor(agent, self._client)
        try:
            setattr(agent, "url_trust_gate_advisor", self._advisor)
        except Exception:
            pass

    async def run(self) -> None:
        try:
            await self._daemon.start()
        except Exception as exc:
            logger.error("URL Trust Gate daemon failed to start: %s", exc)
            return
        try:
            # Idle until cancelled. The daemon serves on its own listener;
            # this task just keeps the lifecycle aligned with other monitors.
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await self._daemon.stop()
            await self._client.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strip_none(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


def _is_internal_destination(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # It's a domain. Resolve and check.
        try:
            infos = socket.getaddrinfo(host, None)
        except Exception:
            return False
        for info in infos:
            try:
                ip = ipaddress.ip_address(info[4][0])
            except ValueError:
                continue
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
                return True
        return False

    return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved
