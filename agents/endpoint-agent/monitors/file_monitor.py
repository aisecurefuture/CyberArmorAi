"""File System Monitor -- watches for sensitive file access and AI model downloads.

Uses the ``watchdog`` library for cross-platform file-system event observation.
Detects bulk-copy / exfiltration patterns, AI model downloads, and clipboard
activity involving sensitive content.
"""

from __future__ import annotations

import asyncio
import glob
import hashlib
import logging
import os
import platform
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from watchdog.events import (
    FileCreatedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

try:
    from dlp.redactor import is_redaction_action, redact_text
except ImportError:  # pragma: no cover - package-relative fallback for tests
    from ..dlp.redactor import is_redaction_action, redact_text

if TYPE_CHECKING:
    from agent import EndpointAgent

logger = logging.getLogger("cyberarmor.monitors.file")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# AI model file extensions to monitor
AI_MODEL_EXTENSIONS: Set[str] = {
    ".gguf",
    ".safetensors",
    ".bin",
    ".onnx",
    ".pt",
    ".pth",
    ".h5",
    ".hdf5",
    ".tflite",
    ".pb",
    ".mlmodel",
    ".mlpackage",
    ".ckpt",
}

# Archive extensions used for potential exfiltration
ARCHIVE_EXTENSIONS: Set[str] = {
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".7z", ".rar", ".xz",
}

# Simple malware signature patterns (byte-level, very basic)
MALWARE_SIGNATURES: Dict[str, bytes] = {
    "eicar_test": b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
}

# Default paths to watch (platform-dependent)
DEFAULT_WATCH_PATHS_UNIX: List[str] = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Desktop"),
    "/tmp",
]

DEFAULT_WATCH_PATHS_WINDOWS: List[str] = [
    os.path.expanduser("~\\Documents"),
    os.path.expanduser("~\\Downloads"),
    os.path.expanduser("~\\Desktop"),
    os.environ.get("TEMP", "C:\\Temp"),
]

TRANSIENT_PATH_PREFIXES: tuple[str, ...] = (
    "/tmp/",
    "/private/tmp/",
    "/private/var/folders/",
    "/var/folders/",
)

TRANSIENT_FILE_SUFFIXES: tuple[str, ...] = (
    ".tmp",
    ".temp",
    ".part",
    ".download",
    ".crdownload",
    ".swp",
    ".swx",
)


# ---------------------------------------------------------------------------
# Exfiltration detector
# ---------------------------------------------------------------------------


@dataclass
class ExfiltrationTracker:
    """Tracks rapid file activity to detect bulk-copy / exfiltration patterns."""

    window_seconds: float = 60.0
    threshold_count: int = 50
    cooldown_seconds: float = 300.0
    _events: Dict[str, float] = field(default_factory=dict)
    _last_alert_at: float = 0.0

    def record(self, path: str) -> tuple[bool, int]:
        """Record a file event. Returns ``(alert, count)``."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        normalized = os.path.realpath(path)
        self._events[normalized] = now
        self._events = {
            candidate: ts for candidate, ts in self._events.items() if ts >= cutoff
        }
        event_count = len(self._events)
        if event_count < self.threshold_count:
            return False, event_count
        if now - self._last_alert_at < self.cooldown_seconds:
            return False, event_count
        self._last_alert_at = now
        return True, event_count


# ---------------------------------------------------------------------------
# Watchdog event handler
# ---------------------------------------------------------------------------


class _CyberArmorEventHandler(FileSystemEventHandler):
    """Handles file-system events and forwards them to the async event queue."""

    def __init__(self, queue: asyncio.Queue[Dict[str, Any]], loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._queue = queue
        self._loop = loop

    def _enqueue(self, event_type: str, src_path: str, dest_path: Optional[str] = None) -> None:
        payload: Dict[str, Any] = {
            "fs_event": event_type,
            "src_path": src_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if dest_path:
            payload["dest_path"] = dest_path
        self._loop.call_soon_threadsafe(self._queue.put_nowait, payload)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._enqueue("created", event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._enqueue("modified", event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory and isinstance(event, FileMovedEvent):
            self._enqueue("moved", event.src_path, event.dest_path)


# ---------------------------------------------------------------------------
# FileMonitor
# ---------------------------------------------------------------------------


class FileMonitor:
    """Watches configured directories for sensitive file activity.

    Parameters
    ----------
    agent : EndpointAgent
        Parent agent for telemetry and configuration.
    extra_watch_paths : list[str], optional
        Additional paths to watch beyond platform defaults.
    """

    def __init__(
        self,
        agent: EndpointAgent,
        extra_watch_paths: Optional[List[str]] = None,
    ) -> None:
        self._agent = agent
        self._observer: Optional[Observer] = None
        self._event_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=5000)
        self._exfil_tracker = ExfiltrationTracker()
        self._recent_model_downloads: List[Dict[str, Any]] = []

        # Determine watch paths
        system = platform.system()
        self._watch_paths = self._resolve_watch_paths(system)
        if extra_watch_paths:
            self._watch_paths.extend(extra_watch_paths)

        # Filter to paths that actually exist
        seen: Set[str] = set()
        resolved_watch_paths: List[str] = []
        for candidate in self._watch_paths:
            normalized = os.path.realpath(candidate)
            if not os.path.isdir(normalized) or normalized in seen:
                continue
            seen.add(normalized)
            resolved_watch_paths.append(normalized)
        self._watch_paths = resolved_watch_paths

    @staticmethod
    def _resolve_watch_paths(system: str) -> List[str]:
        if system == "Windows":
            return list(DEFAULT_WATCH_PATHS_WINDOWS)
        if system == "Darwin":
            expanded: List[str] = []
            for pattern in ("/Users/*/Documents", "/Users/*/Downloads", "/Users/*/Desktop"):
                expanded.extend(glob.glob(pattern))
            # Keep /tmp for malware/model visibility, but temp churn is excluded
            # from exfiltration heuristics below.
            expanded.append("/tmp")
            return expanded
        return list(DEFAULT_WATCH_PATHS_UNIX)

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def _is_ai_model_file(self, path: str) -> bool:
        """Check whether the path has a known AI model file extension."""
        _, ext = os.path.splitext(path)
        return ext.lower() in AI_MODEL_EXTENSIONS

    def _is_archive_file(self, path: str) -> bool:
        _, ext = os.path.splitext(path)
        return ext.lower() in ARCHIVE_EXTENSIONS

    def _check_malware_signatures(self, path: str) -> Optional[str]:
        """Scan the first 1 KB of a file for known malware signatures.

        Returns the signature name if matched, otherwise ``None``.
        """
        try:
            with open(path, "rb") as fh:
                header = fh.read(1024)
            for name, sig in MALWARE_SIGNATURES.items():
                if sig in header:
                    return name
        except (OSError, PermissionError):
            pass
        return None

    def _get_file_size(self, path: str) -> int:
        try:
            return os.path.getsize(path)
        except OSError:
            return 0

    def _should_track_exfil_path(self, path: str) -> bool:
        normalized = os.path.realpath(path)
        lowered = normalized.lower()
        if any(lowered.startswith(prefix) for prefix in TRANSIENT_PATH_PREFIXES):
            return False
        file_name = os.path.basename(lowered)
        if not file_name:
            return False
        if file_name.startswith(".") and not self._is_archive_file(file_name):
            return False
        if file_name.startswith("com.apple.") or file_name.startswith(".ds_store"):
            return False
        if file_name.endswith(TRANSIENT_FILE_SUFFIXES):
            return False
        return True

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    async def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Emit a telemetry event with optional policy-driven redaction.

        Path B / compliance pass: file paths frequently encode user-
        identifiable info (`/Users/john.smith/...`) and customer/employee
        names in filenames (`Q4_review_alice.docx`). When a tenant policy
        with action="redact" matches, those values are masked here, at the
        agent, before any telemetry leaves the endpoint.

        Pseudonymization companion fields (when CYBERARMOR_REDACT_LOG_CONTENT_HASH
        is enabled): each redacted field gets a `{field}_hmac` companion
        with a per-tenant HMAC of the original value, so audit/forensics
        can correlate occurrences without recovering the raw path.
        """
        try:
            from policy_enforcer import PolicyEnforcer
            enforcer = PolicyEnforcer.instance()
        except Exception:
            enforcer = None

        if enforcer is not None:
            ctx = {
                "source": {"name": "file_monitor"},
                "event": {"type": event_type},
                "file": {
                    "path": str(data.get("path") or data.get("file_path") or ""),
                    "size_bytes": data.get("size_bytes", 0),
                },
            }
            try:
                res = enforcer.evaluate(ctx)
                if res.highest_action == "redact" and res.redact_classes:
                    tenant_for_hmac = ctx.get("tenant_id") or data.get("tenant_id") or ""
                    # Path/filename text fields that may carry employee or
                    # customer identifiers. archive_contents could contain
                    # nested paths (also worth scrubbing if present).
                    for field_name in (
                        "path", "file_path", "src_path", "dest_path",
                        "dirname", "filename", "archive_contents",
                    ):
                        original = data.get(field_name)
                        if isinstance(original, str) and original:
                            redacted, counts = enforcer.redact_text(original, res.redact_classes)
                            if counts:
                                data[field_name] = redacted
                                content_hmac = PolicyEnforcer.redact_content_hmac(
                                    tenant_for_hmac, original,
                                )
                                if content_hmac:
                                    data[f"{field_name}_hmac"] = content_hmac
                                logger.info(
                                    "redacted_telemetry_field source=file_monitor "
                                    "event=%s field=%s class_counts=%s",
                                    event_type, field_name, counts,
                                )
                elif res.highest_action == "block":
                    logger.info(
                        "policy_blocked_telemetry source=file_monitor event=%s",
                        event_type,
                    )
                    return
            except Exception as exc:
                logger.warning("file_monitor enforce error: %s", exc)

        event = {
            "source": "file_monitor",
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **data,
        }
        await self._agent.report_event(event)

    # ------------------------------------------------------------------
    # Event processing
    # ------------------------------------------------------------------

    async def _process_event(self, payload: Dict[str, Any]) -> None:
        """Evaluate a single file-system event."""
        src_path: str = payload.get("src_path", "")
        fs_event: str = payload.get("fs_event", "")

        # --- AI model file detection ---
        if fs_event in ("created", "moved") and self._is_ai_model_file(src_path):
            size = self._get_file_size(src_path)
            logger.warning("AI model file detected: %s (size=%d)", src_path, size)
            record = {
                "path": src_path,
                "size_bytes": size,
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
            self._recent_model_downloads.append(record)
            await self._emit_event(
                "ai_model_file_detected",
                {
                    "path": src_path,
                    "size_bytes": size,
                    "severity": "high",
                },
            )

        # --- Exfiltration pattern detection ---
        if fs_event in ("created", "moved"):
            if self._should_track_exfil_path(src_path):
                should_alert, event_count = self._exfil_tracker.record(src_path)
            else:
                should_alert, event_count = False, 0
            if should_alert:
                logger.warning("Potential exfiltration pattern detected (rapid file creation)")
                await self._emit_event(
                    "exfiltration_pattern_detected",
                    {
                        "path": src_path,
                        "event_count_in_window": event_count,
                        "severity": "critical",
                    },
                )

        # --- Archive creation in sensitive directories ---
        if fs_event == "created" and self._is_archive_file(src_path):
            size = self._get_file_size(src_path)
            if size > 10 * 1024 * 1024:  # > 10 MB
                logger.warning(
                    "Large archive created in monitored path: %s (size=%d)",
                    src_path,
                    size,
                )
                await self._emit_event(
                    "large_archive_created",
                    {
                        "path": src_path,
                        "size_bytes": size,
                        "severity": "high",
                    },
                )

        # --- Malware signature scan on new files ---
        if fs_event == "created":
            sig = self._check_malware_signatures(src_path)
            if sig:
                logger.critical("Malware signature matched: %s in %s", sig, src_path)
                await self._emit_event(
                    "malware_signature_detected",
                    {
                        "path": src_path,
                        "signature_name": sig,
                        "severity": "critical",
                    },
                )

    # ------------------------------------------------------------------
    # Clipboard monitoring (best-effort)
    # ------------------------------------------------------------------

    async def _monitor_clipboard(self) -> None:
        """Periodically check clipboard for sensitive content.

        Uses ``pyperclip`` when available; silently disables if unavailable
        or if the system has no display.
        """
        try:
            import pyperclip  # type: ignore[import-untyped]
        except ImportError:
            logger.info("pyperclip not available; clipboard monitoring disabled")
            return

        logger.info("Clipboard monitor started (poll_interval=3s)")
        last_content = ""
        consecutive_errors = 0
        poll_count = 0
        empty_streak = 0
        while True:
            try:
                await asyncio.sleep(3)
                content = pyperclip.paste()
                poll_count += 1
                # Log the FIRST few polls so we can tell from the log whether
                # the daemon-context pasteboard actually returns user data on
                # this host. Truncated; content hashes go to telemetry, not
                # the file log.
                if poll_count <= 3:
                    preview = (content or "")[:24]
                    logger.info("Clipboard poll #%d len=%d preview=%r",
                                poll_count, len(content or ""), preview)
                # macOS LaunchDaemons run outside the user's pasteboard
                # session, so pyperclip.paste() reliably returns "". If we
                # see 10 empty polls in a row, the daemon is the wrong place
                # for clipboard work — stop polling and point the operator at
                # the user-session helper. The clipboard_helper.py LaunchAgent
                # covers this gap.
                if not content:
                    empty_streak += 1
                    if empty_streak == 10:
                        logger.warning(
                            "Clipboard polling returned empty 10 times in a row "
                            "(typical for system LaunchDaemons on macOS). Stopping "
                            "daemon-side clipboard monitor. Install the user-session "
                            "helper via agents/endpoint-agent/install_clipboard_helper.sh."
                        )
                        return
                    continue
                empty_streak = 0
                if content and content != last_content:
                    last_content = content
                    redaction_action = self._clipboard_action()
                    redaction = redact_text(content, redaction_action)
                    if redaction.changed and is_redaction_action(redaction_action):
                        pyperclip.copy(redaction.text)
                        last_content = redaction.text
                        logger.warning("Sensitive clipboard data redacted")
                        await self._emit_event(
                            "clipboard_sensitive_data_redacted",
                            {
                                "length": len(content),
                                "redacted_length": len(redaction.text),
                                "finding_count": redaction.count,
                                "labels": [finding.label for finding in redaction.findings],
                                "categories": sorted({finding.category for finding in redaction.findings}),
                                "original_sha256": hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest(),
                                "redacted_sha256": hashlib.sha256(redaction.text.encode("utf-8", errors="ignore")).hexdigest(),
                                "action": redaction.action,
                                "severity": "high",
                            },
                        )
                    elif redaction.changed or self._clipboard_has_sensitive_data(content):
                        logger.warning("Sensitive data detected in clipboard")
                        await self._emit_event(
                            "clipboard_sensitive_data",
                            {
                                "length": len(content),
                                "finding_count": redaction.count,
                                "labels": [finding.label for finding in redaction.findings],
                                "categories": sorted({finding.category for finding in redaction.findings}),
                                "content_sha256": hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest(),
                                "action": redaction_action,
                                "severity": "high",
                            },
                        )
            except Exception as exc:
                # Clipboard access can fail in headless environments (and
                # always fails when the agent runs as a LaunchDaemon outside
                # the user's pasteboard session — log so that case is
                # diagnosable instead of silent).
                consecutive_errors += 1
                if consecutive_errors <= 3 or consecutive_errors % 20 == 0:
                    logger.warning("Clipboard poll error #%d: %s",
                                   consecutive_errors, exc)
                await asyncio.sleep(10)

    def _clipboard_action(self) -> str:
        """Return clipboard response action, defaulting to monitor-safe telemetry."""
        env_action = os.getenv("CYBERARMOR_CLIPBOARD_ACTION") or os.getenv("CYBERARMOR_MODE")
        if env_action:
            return env_action.strip().lower()
        try:
            return self._agent.config.get("dlp", "clipboard_action", fallback="monitor").strip().lower()
        except Exception:
            return "monitor"

    @staticmethod
    def _clipboard_has_sensitive_data(text: str) -> bool:
        """Return True if the clipboard text appears to contain PII/secrets."""
        patterns = [
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"\b\d{16}\b",  # Credit card (basic)
            r"\b[A-Za-z0-9+/]{40,}\b",  # Base64-encoded blobs
            r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S+",
            r"\b(?:sk-|pk-|ghp_|gho_|AKIA)[A-Za-z0-9]{20,}\b",  # API keys
        ]
        for pat in patterns:
            if re.search(pat, text):
                return True
        return False

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start watchdog observer and process events until cancelled."""
        loop = asyncio.get_running_loop()

        handler = _CyberArmorEventHandler(self._event_queue, loop)
        self._observer = Observer()

        for path in self._watch_paths:
            try:
                self._observer.schedule(handler, path, recursive=True)
                logger.info("Watching directory: %s", path)
            except Exception as exc:
                logger.warning("Cannot watch %s: %s", path, exc)

        self._observer.start()
        logger.info("File monitor started (watching %d paths)", len(self._watch_paths))

        # Start clipboard monitoring in background
        clipboard_enabled = self._agent.config.getboolean(
            "dlp", "scan_clipboard", fallback=True
        )
        clipboard_task: Optional[asyncio.Task[None]] = None
        if clipboard_enabled:
            clipboard_task = asyncio.create_task(
                self._monitor_clipboard(), name="clipboard_monitor"
            )

        try:
            while True:
                try:
                    payload = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                    await self._process_event(payload)
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            logger.info("File monitor stopping")
            if clipboard_task:
                clipboard_task.cancel()
            self._observer.stop()
            self._observer.join(timeout=5)
            raise

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_recent_model_downloads(self) -> List[Dict[str, Any]]:
        """Return recent AI model file detections."""
        return list(self._recent_model_downloads[-50:])
