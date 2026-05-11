#!/usr/bin/env bash
# Install the per-user clipboard helper LaunchAgent.
#
# Run as the user who will be protected (NOT root). The script copies
# credentials from the system daemon's /etc/cyberarmor/agent.json into
# ~/.config/cyberarmor/helper.json (mode 600), then installs and loads a
# LaunchAgent that runs clipboard_helper.py in the user's GUI session so
# pyperclip.paste() actually returns the user's pasteboard contents.
#
# Idempotent: re-running unloads any previous instance before reloading.

set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
    echo "Run this as your user (without sudo). The script will prompt for sudo only when reading /etc/cyberarmor/agent.json." >&2
    exit 1
fi

AGENT_JSON="/etc/cyberarmor/agent.json"
HELPER_SCRIPT="/usr/local/cyberarmor/clipboard_helper.py"
HELPER_WRAPPER="/usr/local/cyberarmor/cyberarmor-clipboard-helper"
SOURCE_HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/clipboard_helper.py"
SOURCE_WRAPPER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cyberarmor-clipboard-helper"
TEMPLATE_PLIST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/launchagent/ai.cyberarmor.clipboard-helper.plist.template"

USER_CONFIG_DIR="${HOME}/.config/cyberarmor"
USER_CONFIG="${USER_CONFIG_DIR}/helper.json"
LAUNCH_AGENT_DIR="${HOME}/Library/LaunchAgents"
LAUNCH_AGENT_PLIST="${LAUNCH_AGENT_DIR}/ai.cyberarmor.clipboard-helper.plist"
LOG_DIR="${HOME}/Library/Logs"

if [[ ! -f "${SOURCE_HELPER}" ]]; then
    echo "missing source helper script at ${SOURCE_HELPER}" >&2
    exit 1
fi
if [[ ! -f "${TEMPLATE_PLIST}" ]]; then
    echo "missing plist template at ${TEMPLATE_PLIST}" >&2
    exit 1
fi

echo "→ Copying clipboard_helper.py to ${HELPER_SCRIPT}"
sudo install -m 0755 "${SOURCE_HELPER}" "${HELPER_SCRIPT}"

echo "→ Copying launcher wrapper to ${HELPER_WRAPPER}"
sudo install -m 0755 "${SOURCE_WRAPPER}" "${HELPER_WRAPPER}"

echo "→ Ensuring pyperclip + setproctitle are installed in the agent venv"
sudo /usr/local/cyberarmor/.venv/bin/python3 -m pip install --quiet pyperclip setproctitle

mkdir -p "${USER_CONFIG_DIR}" "${LAUNCH_AGENT_DIR}" "${LOG_DIR}"

echo "→ Generating ${USER_CONFIG} from system agent.json (sudo required)"
sudo /usr/local/cyberarmor/.venv/bin/python3 - <<PY
import json, pathlib, os, pwd, sys
agent = json.loads(pathlib.Path("${AGENT_JSON}").read_text())
# Field name varies: agent.json uses "api_key" but the bootstrap response
# uses "service_api_key". Accept either.
api_key = agent.get("api_key") or agent.get("service_api_key") or agent.get("agent_api_key")
if not api_key:
    sys.exit("no api_key found in /etc/cyberarmor/agent.json — has the agent been bootstrapped?")
helper = {
    "control_plane_url": agent.get("control_plane_url", "https://app.cyberarmor.ai"),
    "tenant_id": agent.get("tenant_id", "default"),
    "service_api_key": api_key,
    "poll_interval_s": 3,
    "clipboard_action": os.environ.get("CYBERARMOR_CLIPBOARD_ACTION", "monitor"),
}
target = pathlib.Path("${USER_CONFIG}")
target.write_text(json.dumps(helper, indent=2))
target.chmod(0o600)
user = pwd.getpwnam("${USER}")
os.chown(target, user.pw_uid, user.pw_gid)
os.chown(target.parent, user.pw_uid, user.pw_gid)
print(f"wrote {target} (mode 600)")
PY

echo "→ Writing LaunchAgent plist to ${LAUNCH_AGENT_PLIST}"
sed "s|__HOME__|${HOME}|g" "${TEMPLATE_PLIST}" > "${LAUNCH_AGENT_PLIST}"

echo "→ (Re)loading the LaunchAgent"
launchctl bootout gui/$(id -u) "${LAUNCH_AGENT_PLIST}" 2>/dev/null || true
launchctl bootstrap gui/$(id -u) "${LAUNCH_AGENT_PLIST}"
launchctl enable "gui/$(id -u)/ai.cyberarmor.clipboard-helper"
launchctl kickstart -k "gui/$(id -u)/ai.cyberarmor.clipboard-helper"

sleep 2
echo
echo "Helper PID:"
launchctl print "gui/$(id -u)/ai.cyberarmor.clipboard-helper" 2>/dev/null | grep -E "pid|state" | head -4 || true

echo
echo "Tail of helper log:"
tail -n 10 "${LOG_DIR}/cyberarmor-clipboard-helper.log" 2>/dev/null || echo "(no output yet)"

echo
echo "Install complete. Test by copying a fake SSN (e.g. printf '123-45-6789' | pbcopy)"
echo "and tailing ~/Library/Logs/cyberarmor-clipboard-helper.log"
