"""RASP-side A-BOM collector.

Picks up what the endpoint-agent collector can't: what's *actually
loaded* in this Python process at runtime, versus what's just sitting
on disk. Two signals:

1. ``sys.modules`` snapshot — every Python module imported so far,
   with versions pulled via ``importlib.metadata`` when available.
2. ``/proc/self/maps`` (Linux only) — native shared libraries (.so /
   .dylib) the dynamic loader has mapped in. Catches what the
   pure-Python introspection misses (libssl, libc, NumPy's BLAS, …).

Plus the interpreter itself as one component so the BOM carries the
exact Python binary running the workload.

Posts to ``POST /rasp/abom/ingest`` with ``source_kind=workload`` and
``source_id=workload:<host>:<pid>``. Runs once at ``init()`` and then
every ``abom_sweep_interval`` seconds in a daemon thread so the
runtime path stays unblocked.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cyberarmor.rasp.abom")

# Default sweep cadence — RASP is process-scoped, so a long
# observation gap is fine. Override via init(abom_sweep_interval=…).
DEFAULT_SWEEP_INTERVAL_S = 30 * 60


def _interpreter_component() -> Dict[str, Any]:
    """The Python interpreter itself, captured as a CycloneDX
    ``application`` so the BOM carries the exact runtime binary —
    matters when a CVE only affects, say, CPython 3.11.0–3.11.7."""
    impl = sys.implementation.name or "cpython"
    version = ".".join(str(v) for v in sys.version_info[:3])
    return {
        "type": "application",
        "name": impl,
        "version": version,
        "purl": f"pkg:generic/{impl}@{version}",
        "properties": [
            {"name": "cyberarmor:package_manager", "value": "interpreter"},
            {"name": "cyberarmor:executable", "value": sys.executable or ""},
            {"name": "cyberarmor:full_version", "value": sys.version.split()[0] if sys.version else ""},
            {"name": "cyberarmor:abi_tag", "value": getattr(sys.implementation, "version", "")  and ".".join(str(v) for v in sys.implementation.version[:3])},
        ],
    }


def _module_components() -> List[Dict[str, Any]]:
    """One component per top-level Python package imported so far.

    Strategy:
      - Snapshot ``sys.modules`` so concurrent imports during the walk
        don't raise RuntimeError.
      - Group by top-level package (``foo.bar.baz`` → ``foo``) so the
        BOM doesn't carry one row per submodule.
      - Resolve version via ``importlib.metadata.version()`` — covers
        anything pip-installed. Fall back to the module's
        ``__version__`` attribute when metadata lookup fails.
      - Skip stdlib + ``__main__`` + cyberarmor itself; the
        interpreter component above already carries the stdlib
        identity, and we don't want to dedup against our own RASP
        package.
    """
    import importlib.metadata  # imported lazily so a missing metadata
    # subsystem (unlikely on modern Python) never crashes RASP init.

    # Top-level package → resolved version. dict-of-dict ensures we
    # only emit one row per package even if 50 submodules are loaded.
    seen: Dict[str, Dict[str, Any]] = {}
    snapshot = list(sys.modules.items())

    stdlib_top = _stdlib_top_level()

    for fullname, mod in snapshot:
        if not fullname:
            continue
        top = fullname.partition(".")[0]
        if not top or top in seen:
            continue
        if top.startswith("_"):
            continue
        if top in stdlib_top:
            continue
        if top in ("__main__", "builtins", "cyberarmor_rasp", "cyberarmor_rasp_impl",
                   "cyberarmor_rasp_url_trust_gate", "cyberarmor_abom"):
            continue

        version = ""
        try:
            version = importlib.metadata.version(top)
        except Exception:  # noqa: BLE001 — fall back to __version__
            version = ""
        if not version and mod is not None:
            version = str(getattr(mod, "__version__", "") or "")

        file_path = ""
        try:
            file_path = str(getattr(mod, "__file__", "") or "")
        except Exception:  # noqa: BLE001
            file_path = ""

        seen[top] = {
            "type": "library",
            "name": top,
            "version": version or "unknown",
            "purl": f"pkg:pypi/{top}@{version}" if version else f"pkg:pypi/{top}",
            "properties": [
                {"name": "cyberarmor:package_manager", "value": "python_runtime"},
                {"name": "cyberarmor:loaded_path", "value": file_path[:1024]},
            ],
        }

    return list(seen.values())


def _native_lib_components() -> List[Dict[str, Any]]:
    """Native shared libs the dynamic loader has mapped into this
    process. Linux-only path; macOS doesn't expose an equivalent
    /proc fs so we skip there. CycloneDX type stays ``library``."""
    if not sys.platform.startswith("linux"):
        return []
    maps_path = f"/proc/{os.getpid()}/maps"
    try:
        with open(maps_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    seen: Dict[str, Dict[str, Any]] = {}
    for line in lines:
        # /proc/{pid}/maps format:
        # address perms offset dev inode pathname
        parts = line.strip().split(maxsplit=5)
        if len(parts) < 6:
            continue
        path = parts[5].strip()
        if not path or path.startswith("["):  # [stack], [heap], [vdso]
            continue
        # Filter to actually-shared objects so anonymous mmap'd files
        # don't pollute the BOM.
        if not (path.endswith(".so") or ".so." in path or path.endswith(".dylib")):
            continue
        name = os.path.basename(path)
        if name in seen:
            continue
        # Strip the .so.<ver> suffix → ("libssl", "3") so each library
        # version surfaces distinctly.
        base, _, soversion = name.partition(".so.")
        if not base:
            base = name.removesuffix(".so")
            soversion = ""
        seen[path] = {
            "type": "library",
            "name": base,
            "version": soversion or "",
            "purl": f"pkg:generic/{base}@{soversion}" if soversion else f"pkg:generic/{base}",
            "properties": [
                {"name": "cyberarmor:package_manager", "value": "linux_native_loader"},
                {"name": "cyberarmor:loaded_path", "value": path[:1024]},
            ],
            "__path": path,
        }
    return list(seen.values())


def _stdlib_top_level() -> set:
    """Top-level names that ship with the Python stdlib in this
    interpreter. ``sys.stdlib_module_names`` is the authoritative
    source (Python 3.10+). Fall back to a small hand-rolled set for
    older interpreters."""
    names = getattr(sys, "stdlib_module_names", None)
    if names:
        return set(names)
    return {
        "abc", "asyncio", "base64", "collections", "concurrent", "contextlib",
        "copy", "dataclasses", "datetime", "decimal", "email", "enum", "fnmatch",
        "functools", "glob", "hashlib", "heapq", "hmac", "http", "importlib",
        "inspect", "io", "ipaddress", "itertools", "json", "logging", "math",
        "multiprocessing", "operator", "os", "pathlib", "pickle", "platform",
        "posixpath", "queue", "random", "re", "secrets", "select", "shutil",
        "signal", "site", "socket", "socketserver", "ssl", "stat", "string",
        "struct", "subprocess", "sys", "tempfile", "textwrap", "threading",
        "time", "traceback", "types", "typing", "unicodedata", "urllib", "uuid",
        "warnings", "weakref", "xml", "zipfile", "zlib",
    }


def collect() -> List[Dict[str, Any]]:
    """Run all RASP-side collectors and return the union. Each helper
    is best-effort; one failing never blocks the others."""
    rows: List[Dict[str, Any]] = []
    for fn in (_interpreter_component, _module_components, _native_lib_components):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            logger.debug("RASP A-BOM helper %s failed: %s", fn.__name__, exc)
            continue
        if isinstance(result, dict):
            rows.append(result)
        elif isinstance(result, list):
            rows.extend(result)
    return rows


def workload_source_id() -> str:
    """Stable per-process identifier — host + pid. Restart of the
    process yields a new source_id, which is what we want: the loaded
    set of a new process is genuinely different observable state."""
    host = "unknown-host"
    try:
        host = socket.gethostname() or host
    except OSError:
        pass
    return f"workload:{host}:{os.getpid()}"


def _ingest_once(config: Any) -> None:
    """Send one A-BOM sweep to /rasp/abom/ingest. ``config`` is the
    RASPConfig object from cyberarmor_rasp_impl.py — duck-typed so we
    don't introduce a circular import.
    """
    components = collect()
    if not components:
        return
    try:
        host = socket.gethostname()
    except OSError:
        host = ""
    body = {
        "tenant_id": getattr(config, "tenant_id", "default"),
        "collector": "rasp-python",
        "collector_version": getattr(config, "version", "1.0"),
        "source_kind": "workload",
        "source_id": workload_source_id(),
        "hostname": host,
        "observed_at": _now_iso(),
        "components": components,
    }
    url = f"{getattr(config, 'control_plane_url', 'http://localhost:8000').rstrip('/')}/rasp/abom/ingest"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-api-key": getattr(config, "api_key", "") or "",
            "x-tenant-id": getattr(config, "tenant_id", "default") or "",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info("CyberArmor RASP A-BOM ingest status=%s components=%d", resp.status, len(components))
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")[:200]
        logger.warning("CyberArmor RASP A-BOM ingest HTTP %s: %s", exc.code, body_text)
    except Exception as exc:  # noqa: BLE001
        logger.warning("CyberArmor RASP A-BOM ingest failed: %s", exc)


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


_started = False
_started_lock = threading.Lock()


def start_periodic(config: Any, interval_s: int = DEFAULT_SWEEP_INTERVAL_S) -> None:
    """Kick off a daemon thread that ingests an A-BOM sweep
    periodically. Idempotent — repeat calls are no-ops so RASP init()
    can be invoked safely from many places (WSGI factory, ASGI
    lifespan, manual)."""
    global _started
    with _started_lock:
        if _started:
            return
        _started = True

    def _loop() -> None:
        # First sweep immediate so the dashboard lights up on cold
        # start. Subsequent sweeps run at the configured interval.
        try:
            _ingest_once(config)
        except Exception as exc:  # noqa: BLE001
            logger.debug("CyberArmor RASP A-BOM initial sweep failed: %s", exc)
        while True:
            time.sleep(max(60, int(interval_s)))
            try:
                _ingest_once(config)
            except Exception as exc:  # noqa: BLE001
                logger.debug("CyberArmor RASP A-BOM periodic sweep failed: %s", exc)

    threading.Thread(target=_loop, name="cyberarmor-rasp-abom", daemon=True).start()
    logger.info("CyberArmor RASP A-BOM collector started (interval=%ds)", interval_s)
