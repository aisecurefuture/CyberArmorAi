"""A-BOM endpoint-agent collector.

Walks the host once per sweep and returns a list of CycloneDX 1.6
component dicts that the agent ships to ``/agents/{agent_id}/abom/ingest``.

Coverage on Linux + macOS in this revision; Windows lands in a follow-up
(WMI + Get-AppxPackage + DriverStore). Pure stdlib — no extra deps so
the agent's wheel stays small.

Component types emitted (CycloneDX 1.6 component.type values):

- ``operating-system``       — distro + kernel
- ``device``                 — CPU, RAM, disks, NICs, GPU
- ``application``            — installed apps from package managers + .app bundles
- ``library``                — system libraries that show up as packages
- ``machine-learning-model`` — Ollama / Hugging Face / .gguf model files

Each component carries ``properties`` so the control-plane can attribute
provenance (e.g., the package manager that surfaced it).
"""

from __future__ import annotations

import os
import sys

# Same shadowing dance clipboard_helper.py does: the endpoint-agent
# package ships a ``platform`` sub-package that hides the stdlib
# ``platform`` module on disk. Drop the agent's parent dir from sys.path
# before importing platform/socket/etc. so we get the stdlib versions.
_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:] = [p for p in sys.path if os.path.abspath(p) != _PARENT]

import hashlib
import json
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


# Each helper returns a list of CycloneDX-shaped dicts. The collector
# composes them in order: lighter (OS, hardware) first so a giant package
# scan can never starve them.


def _run(cmd: List[str], timeout: float = 30.0) -> Optional[str]:
    """Best-effort subprocess. Returns stdout text or None on any failure
    so callers can fall through to the next strategy without try/except
    boilerplate."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# ── Operating system ──────────────────────────────────────────────────

def _collect_os() -> List[Dict[str, Any]]:
    """One ``operating-system`` component capturing distro, kernel,
    and machine arch. The properties block stays tight so we don't
    serialize the full uname output."""
    uname = platform.uname()
    out: Dict[str, Any] = {
        "type": "operating-system",
        "name": uname.system or "unknown",
        "version": uname.release or "",
        "properties": [
            {"name": "cyberarmor:kernel", "value": str(uname.release or "")},
            {"name": "cyberarmor:arch", "value": str(uname.machine or "")},
        ],
    }
    # Windows: prefer the friendly Caption / BuildNumber from CIM. Falls
    # back to uname.release which is just the NT build number.
    if uname.system == "Windows":
        raw = _run([
            "powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | ConvertTo-Json -Compress",
        ], timeout=10.0) or ""
        try:
            data = json.loads(raw) if raw else {}
            if isinstance(data, list) and data:
                data = data[0]
            if isinstance(data, dict):
                if data.get("Caption"):
                    out["name"] = str(data["Caption"])
                if data.get("Version"):
                    out["version"] = str(data["Version"])
                if data.get("BuildNumber"):
                    out["properties"].append({"name": "cyberarmor:build", "value": str(data["BuildNumber"])})
        except (json.JSONDecodeError, AttributeError):
            pass
        return [out]
    # Linux: pull pretty-name from /etc/os-release for a useful display name.
    osrel = Path("/etc/os-release")
    if osrel.exists():
        try:
            kv: Dict[str, str] = {}
            for line in osrel.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip().strip('"').strip("'")
            if kv.get("PRETTY_NAME"):
                out["name"] = kv["PRETTY_NAME"]
            if kv.get("VERSION_ID"):
                out["version"] = kv["VERSION_ID"]
            if kv.get("ID"):
                out["properties"].append({"name": "cyberarmor:os_id", "value": kv["ID"]})
        except OSError:
            pass
    elif uname.system == "Darwin":
        # sw_vers gives "ProductName / ProductVersion / BuildVersion".
        sw = _run(["/usr/bin/sw_vers"]) or ""
        for line in sw.splitlines():
            if line.startswith("ProductName:"):
                out["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("ProductVersion:"):
                out["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("BuildVersion:"):
                out["properties"].append({"name": "cyberarmor:build", "value": line.split(":", 1)[1].strip()})
    return [out]


# ── Hardware (CPU / RAM / disks / NICs / GPU) ─────────────────────────

def _collect_cpu() -> List[Dict[str, Any]]:
    """One ``device`` row for the CPU package(s)."""
    model = ""
    if platform.system() == "Linux":
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.exists():
            try:
                for line in cpuinfo.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.lower().startswith("model name"):
                        model = line.split(":", 1)[1].strip()
                        break
            except OSError:
                pass
    elif platform.system() == "Darwin":
        model = (_run(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"]) or "").strip()
    elif platform.system() == "Windows":
        raw = _run([
            "powershell", "-NoProfile", "-Command",
            "(Get-CimInstance Win32_Processor | Select-Object -First 1).Name",
        ], timeout=10.0) or ""
        model = raw.strip()
    if not model:
        model = platform.processor() or "cpu"
    try:
        cores = os.cpu_count() or 0
    except NotImplementedError:
        cores = 0
    return [{
        "type": "device",
        "name": model,
        "manufacturer": _vendor_from_model(model),
        "properties": [
            {"name": "cyberarmor:device_kind", "value": "cpu"},
            {"name": "cyberarmor:cpu_cores", "value": str(cores)},
            {"name": "cyberarmor:arch", "value": platform.machine() or ""},
        ],
    }]


def _vendor_from_model(model: str) -> str:
    """Best-effort vendor extraction from a CPU model string. CycloneDX
    `manufacturer` is just a free-text field so a heuristic is fine."""
    m = (model or "").lower()
    if "intel" in m:    return "Intel"
    if "amd"   in m:    return "AMD"
    if "apple" in m:    return "Apple"
    if "arm"   in m:    return "ARM"
    return ""


def _collect_ram() -> List[Dict[str, Any]]:
    total_bytes = 0
    if platform.system() == "Linux":
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            try:
                for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        total_bytes = kb * 1024
                        break
            except (OSError, ValueError, IndexError):
                pass
    elif platform.system() == "Darwin":
        raw = _run(["/usr/sbin/sysctl", "-n", "hw.memsize"]) or ""
        try:
            total_bytes = int(raw.strip())
        except ValueError:
            total_bytes = 0
    elif platform.system() == "Windows":
        raw = _run([
            "powershell", "-NoProfile", "-Command",
            "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
        ], timeout=10.0) or ""
        try:
            total_bytes = int(raw.strip())
        except ValueError:
            total_bytes = 0
    if total_bytes <= 0:
        return []
    gb = total_bytes // (1024 * 1024 * 1024)
    return [{
        "type": "device",
        "name": f"{gb} GB RAM",
        "properties": [
            {"name": "cyberarmor:device_kind", "value": "memory"},
            {"name": "cyberarmor:total_bytes", "value": str(total_bytes)},
        ],
    }]


def _collect_nics() -> List[Dict[str, Any]]:
    """One ``device`` per non-loopback NIC. Mac address is the identity
    anchor — manufacturer comes from OUI lookup heuristics for the demo,
    not a real database."""
    rows: List[Dict[str, Any]] = []
    if platform.system() == "Windows":
        # PowerShell Get-NetAdapter is the supported path on modern Windows;
        # fall back to wmic for older releases.
        raw = _run([
            "powershell", "-NoProfile", "-Command",
            "Get-NetAdapter | Where-Object {$_.MacAddress} | Select-Object Name, MacAddress, InterfaceDescription | ConvertTo-Json -Compress",
        ], timeout=10.0) or ""
        try:
            data = json.loads(raw) if raw else []
            if isinstance(data, dict):
                data = [data]
            for nic in data:
                mac = str(nic.get("MacAddress") or "").replace("-", ":")
                name = str(nic.get("Name") or "?")
                if not mac:
                    continue
                rows.append(_nic_component({"name": name, "mac": mac}))
        except (json.JSONDecodeError, AttributeError):
            pass
        return rows
    if platform.system() == "Darwin":
        raw = _run(["/sbin/ifconfig"]) or ""
        cur: Dict[str, str] = {}
        for line in raw.splitlines():
            if line and not line.startswith((" ", "\t")):
                # New interface header: "en0: flags=…"
                if cur and cur.get("mac") and cur["name"] != "lo0":
                    rows.append(_nic_component(cur))
                cur = {"name": line.split(":", 1)[0].strip()}
            else:
                stripped = line.strip()
                if stripped.startswith("ether "):
                    cur["mac"] = stripped.split()[1]
        if cur and cur.get("mac") and cur.get("name") and cur["name"] != "lo0":
            rows.append(_nic_component(cur))
    elif platform.system() == "Linux":
        net = Path("/sys/class/net")
        if net.exists():
            try:
                for iface in net.iterdir():
                    if iface.name in ("lo",):
                        continue
                    mac_path = iface / "address"
                    if not mac_path.exists():
                        continue
                    mac = mac_path.read_text(encoding="utf-8", errors="ignore").strip()
                    if not mac or mac == "00:00:00:00:00:00":
                        continue
                    rows.append(_nic_component({"name": iface.name, "mac": mac}))
            except OSError:
                pass
    return rows


def _nic_component(info: Dict[str, str]) -> Dict[str, Any]:
    return {
        "type": "device",
        "name": f"NIC {info.get('name', '?')}",
        "properties": [
            {"name": "cyberarmor:device_kind", "value": "network_interface"},
            {"name": "cyberarmor:mac_address", "value": info.get("mac", "")},
            {"name": "cyberarmor:iface", "value": info.get("name", "")},
        ],
    }


# ── Installed software ────────────────────────────────────────────────

def _collect_dpkg() -> List[Dict[str, Any]]:
    """Debian / Ubuntu installed packages. PURL: pkg:deb/<name>@<version>."""
    raw = _run(["/usr/bin/dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${Architecture}\\t${Description}\\n"])
    if raw is None:
        return []
    rows: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0]:
            continue
        name = parts[0].strip()
        version = parts[1].strip()
        arch = parts[2].strip() if len(parts) > 2 else ""
        rows.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:deb/{name}@{version}" + (f"?arch={arch}" if arch else ""),
            "properties": [
                {"name": "cyberarmor:package_manager", "value": "dpkg"},
                {"name": "cyberarmor:arch", "value": arch},
            ],
        })
    return rows


def _collect_rpm() -> List[Dict[str, Any]]:
    """RHEL / Fedora / SUSE installed packages."""
    raw = _run(["/usr/bin/rpm", "-qa", "--queryformat", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\n"])
    if raw is None:
        return []
    rows: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0]:
            continue
        name, version = parts[0].strip(), parts[1].strip()
        arch = parts[2].strip() if len(parts) > 2 else ""
        vendor = parts[3].strip() if len(parts) > 3 else ""
        rows.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:rpm/{name}@{version}" + (f"?arch={arch}" if arch else ""),
            "manufacturer": vendor or None,
            "properties": [
                {"name": "cyberarmor:package_manager", "value": "rpm"},
                {"name": "cyberarmor:arch", "value": arch},
            ],
        })
    return rows


def _collect_brew() -> List[Dict[str, Any]]:
    """Homebrew formulae (excluding casks — those are .app bundles we
    catch separately). brew is a per-user install so prefer the
    /opt/homebrew/bin or /usr/local/bin entry."""
    brew = shutil.which("brew") or "/opt/homebrew/bin/brew"
    if not Path(brew).exists():
        return []
    raw = _run([brew, "list", "--formula", "--versions"], timeout=20.0)
    if raw is None:
        return []
    rows: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        version = parts[1] if len(parts) > 1 else ""
        rows.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:brew/{name}@{version}" if version else f"pkg:brew/{name}",
            "properties": [
                {"name": "cyberarmor:package_manager", "value": "homebrew"},
            ],
        })
    return rows


def _collect_windows_apps() -> List[Dict[str, Any]]:
    """Installed Win32 apps from the Uninstall registry hive plus
    AppX/UWP packages. Skips MSI components without a DisplayName so
    the BOM doesn't fill up with unnamed system orphans.
    """
    if platform.system() != "Windows":
        return []
    rows: List[Dict[str, Any]] = []

    # Uninstall registry — covers MSI + EXE installers.
    script = (
        "$paths = @("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
        "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object {$_.DisplayName} | "
        "Select-Object DisplayName, DisplayVersion, Publisher | ConvertTo-Json -Compress"
    )
    raw = _run(["powershell", "-NoProfile", "-Command", script], timeout=30.0) or ""
    try:
        data = json.loads(raw) if raw else []
        if isinstance(data, dict):
            data = [data]
        for app in data:
            name = str(app.get("DisplayName") or "").strip()
            if not name:
                continue
            version = str(app.get("DisplayVersion") or "").strip()
            publisher = str(app.get("Publisher") or "").strip()
            rows.append({
                "type": "application",
                "name": name,
                "version": version,
                "manufacturer": publisher or None,
                "properties": [
                    {"name": "cyberarmor:package_manager", "value": "windows_uninstall_registry"},
                    {"name": "cyberarmor:publisher", "value": publisher},
                ],
            })
    except (json.JSONDecodeError, AttributeError):
        pass

    # AppX / UWP store packages — Get-AppxPackage runs in user context.
    script_appx = (
        "Get-AppxPackage | "
        "Select-Object Name, Version, Publisher, PackageFullName | "
        "ConvertTo-Json -Compress"
    )
    raw = _run(["powershell", "-NoProfile", "-Command", script_appx], timeout=30.0) or ""
    try:
        data = json.loads(raw) if raw else []
        if isinstance(data, dict):
            data = [data]
        for pkg in data:
            name = str(pkg.get("Name") or "").strip()
            version = str(pkg.get("Version") or "").strip()
            publisher = str(pkg.get("Publisher") or "").strip()
            full = str(pkg.get("PackageFullName") or "").strip()
            if not name:
                continue
            rows.append({
                "type": "application",
                "name": name,
                "version": version,
                "manufacturer": publisher or None,
                "purl": f"pkg:appx/{name}@{version}" if version else f"pkg:appx/{name}",
                "properties": [
                    {"name": "cyberarmor:package_manager", "value": "appx"},
                    {"name": "cyberarmor:package_full_name", "value": full},
                ],
            })
    except (json.JSONDecodeError, AttributeError):
        pass

    return rows


def _collect_windows_drivers() -> List[Dict[str, Any]]:
    """Loaded drivers from the DriverStore + currently-attached devices.
    Drivers map to CycloneDX type ``device-driver``."""
    if platform.system() != "Windows":
        return []
    rows: List[Dict[str, Any]] = []
    script = (
        "Get-WindowsDriver -Online -ErrorAction SilentlyContinue | "
        "Select-Object Driver, OriginalFileName, ClassName, ProviderName, Version, Date | "
        "ConvertTo-Json -Compress"
    )
    raw = _run(["powershell", "-NoProfile", "-Command", script], timeout=60.0) or ""
    try:
        data = json.loads(raw) if raw else []
        if isinstance(data, dict):
            data = [data]
        for drv in data:
            name = str(drv.get("OriginalFileName") or drv.get("Driver") or "").strip()
            if not name:
                continue
            version = str(drv.get("Version") or "").strip()
            provider = str(drv.get("ProviderName") or "").strip()
            cls = str(drv.get("ClassName") or "").strip()
            rows.append({
                "type": "device-driver",
                "name": name,
                "version": version,
                "manufacturer": provider or None,
                "properties": [
                    {"name": "cyberarmor:driver_class", "value": cls},
                    {"name": "cyberarmor:driver_provider", "value": provider},
                ],
            })
    except (json.JSONDecodeError, AttributeError):
        pass
    return rows


def _collect_macos_apps() -> List[Dict[str, Any]]:
    """macOS .app bundles. Reads CFBundleShortVersionString from each
    Info.plist (via plutil). Walks /Applications + ~/Applications only;
    /System/Applications is OS-bundled and adds noise.
    """
    rows: List[Dict[str, Any]] = []
    locations = [Path("/Applications"), Path.home() / "Applications"]
    plutil = shutil.which("plutil")
    if not plutil:
        return rows
    for loc in locations:
        if not loc.exists():
            continue
        try:
            entries = list(loc.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_dir() or entry.suffix != ".app":
                continue
            plist = entry / "Contents" / "Info.plist"
            if not plist.exists():
                continue
            info = _run([plutil, "-convert", "json", "-o", "-", str(plist)], timeout=5.0)
            name = entry.stem
            version = ""
            bundle_id = ""
            if info:
                try:
                    data = json.loads(info)
                    name = str(data.get("CFBundleName") or data.get("CFBundleDisplayName") or name)
                    version = str(data.get("CFBundleShortVersionString") or data.get("CFBundleVersion") or "")
                    bundle_id = str(data.get("CFBundleIdentifier") or "")
                except (json.JSONDecodeError, ValueError):
                    pass
            rows.append({
                "type": "application",
                "name": name,
                "version": version,
                "purl": f"pkg:macapp/{bundle_id}@{version}" if bundle_id else None,
                "properties": [
                    {"name": "cyberarmor:package_manager", "value": "macos_app_bundle"},
                    {"name": "cyberarmor:bundle_id", "value": bundle_id},
                    {"name": "cyberarmor:install_path", "value": str(entry)},
                ],
                "__path": str(entry),
            })
    return rows


# ── Browser profiles (extensions) ─────────────────────────────────────

def _collect_browser_extensions() -> List[Dict[str, Any]]:
    """Chrome / Brave / Edge installed extensions. We don't pull every
    profile field — just enough to identify the extension and its
    version so dependency-style queries work. Firefox + Safari have
    their own profile shapes; lands in a follow-up."""
    home = Path.home()
    candidates = [
        ("Chrome",  home / "Library" / "Application Support" / "Google" / "Chrome"),
        ("Chrome",  home / ".config" / "google-chrome"),
        ("Brave",   home / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser"),
        ("Brave",   home / ".config" / "BraveSoftware" / "Brave-Browser"),
        ("Edge",    home / "Library" / "Application Support" / "Microsoft Edge"),
        ("Edge",    home / ".config" / "microsoft-edge"),
    ]
    rows: List[Dict[str, Any]] = []
    for browser, root in candidates:
        if not root.exists():
            continue
        try:
            profile_dirs = [p for p in root.iterdir() if p.is_dir() and (p / "Preferences").exists()]
        except OSError:
            continue
        for profile in profile_dirs:
            ext_root = profile / "Extensions"
            if not ext_root.exists() or not ext_root.is_dir():
                continue
            try:
                ext_ids = [d for d in ext_root.iterdir() if d.is_dir()]
            except OSError:
                continue
            for ext_dir in ext_ids:
                try:
                    versions = [v for v in ext_dir.iterdir() if v.is_dir()]
                except OSError:
                    continue
                # newest version wins
                versions.sort(key=lambda p: p.name, reverse=True)
                for v in versions[:1]:
                    manifest = v / "manifest.json"
                    if not manifest.exists():
                        continue
                    try:
                        data = json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
                    except (OSError, json.JSONDecodeError):
                        continue
                    name = str(data.get("name") or ext_dir.name)
                    if name.startswith("__MSG_"):
                        name = ext_dir.name  # localized; skip resolution for now
                    version = str(data.get("version") or v.name)
                    rows.append({
                        "type": "application",
                        "name": name,
                        "version": version,
                        "purl": f"pkg:chromeextension/{ext_dir.name}@{version}",
                        "properties": [
                            {"name": "cyberarmor:package_manager", "value": "browser_extension"},
                            {"name": "cyberarmor:browser", "value": browser},
                            {"name": "cyberarmor:extension_id", "value": ext_dir.name},
                            {"name": "cyberarmor:profile", "value": profile.name},
                        ],
                        "__path": str(v),
                    })
    return rows


# ── AI models ─────────────────────────────────────────────────────────

def _collect_ai_models() -> List[Dict[str, Any]]:
    """Ollama / Hugging Face / .gguf model artefacts. Emit as
    ``machine-learning-model`` so the CycloneDX ML-BOM section picks
    them up."""
    rows: List[Dict[str, Any]] = []

    # Ollama keeps a manifest store under ~/.ollama/models/manifests
    ollama_root = Path.home() / ".ollama" / "models" / "manifests"
    if ollama_root.exists():
        for manifest in ollama_root.rglob("latest"):
            # ~/.ollama/models/manifests/registry.ollama.ai/library/llama3.2/latest
            parts = manifest.parts
            # name = parent dir
            if len(parts) >= 2:
                model_name = parts[-2]
                rows.append({
                    "type": "machine-learning-model",
                    "name": model_name,
                    "version": "latest",
                    "purl": f"pkg:ollama/{model_name}@latest",
                    "properties": [
                        {"name": "cyberarmor:source", "value": "ollama"},
                        {"name": "cyberarmor:install_path", "value": str(manifest.parent)},
                    ],
                    "__path": str(manifest.parent),
                })

    # Hugging Face hub cache
    hf_cache = Path.home() / ".cache" / "huggingface" / "hub"
    if hf_cache.exists():
        for entry in hf_cache.iterdir():
            if not entry.is_dir() or not entry.name.startswith("models--"):
                continue
            # models--org--name → org/name
            parts = entry.name[len("models--"):].split("--", 1)
            model_name = "/".join(parts) if len(parts) == 2 else parts[0]
            rows.append({
                "type": "machine-learning-model",
                "name": model_name,
                "version": "hub-cached",
                "purl": f"pkg:huggingface/{model_name}",
                "properties": [
                    {"name": "cyberarmor:source", "value": "huggingface_cache"},
                    {"name": "cyberarmor:install_path", "value": str(entry)},
                ],
                "__path": str(entry),
            })

    return rows


# ── Top-level collector ───────────────────────────────────────────────

def collect() -> List[Dict[str, Any]]:
    """Run every collector and return the union. Each helper is best-
    effort; one source failing never blocks the others. Returns a list
    of CycloneDX component dicts ready for the A-BOM ingest endpoint.
    """
    rows: List[Dict[str, Any]] = []
    for fn in (
        _collect_os,
        _collect_cpu,
        _collect_ram,
        _collect_nics,
        _collect_dpkg,
        _collect_rpm,
        _collect_brew,
        _collect_macos_apps,
        _collect_windows_apps,
        _collect_windows_drivers,
        _collect_browser_extensions,
        _collect_ai_models,
    ):
        try:
            rows.extend(fn() or [])
        except Exception:  # noqa: BLE001 — never let one collector kill the sweep
            continue
    return rows


def host_source_id() -> str:
    """Stable per-host identifier for observation rows. Hostname is
    enough for the demo; in production we'd prefer the agent_id, which
    the calling code injects."""
    try:
        return socket.gethostname() or "unknown-host"
    except OSError:
        return "unknown-host"
