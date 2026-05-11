#!/usr/bin/env bash
# Uninstall the per-user clipboard helper LaunchAgent installed by
# install_clipboard_helper.sh. Run as the user (NOT sudo) — the script
# only touches files in $HOME. The system LaunchDaemon is unaffected.

set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
    echo "Run this as your user (without sudo)." >&2
    exit 1
fi

LABEL="ai.cyberarmor.clipboard-helper"
PLIST="${HOME}/Library/LaunchAgents/${LABEL}.plist"
CONFIG="${HOME}/.config/cyberarmor/helper.json"
LOGS=( "${HOME}/Library/Logs/cyberarmor-clipboard-helper.log" "${HOME}/Library/Logs/cyberarmor-clipboard-helper.err" )

echo "→ Stopping ${LABEL}"
launchctl bootout "gui/$(id -u)" "${PLIST}" 2>/dev/null || true

if [[ -f "${PLIST}" ]]; then
    echo "→ Removing ${PLIST}"
    rm -f "${PLIST}"
fi

if [[ -f "${CONFIG}" ]]; then
    echo "→ Removing ${CONFIG}"
    rm -f "${CONFIG}"
fi

for log in "${LOGS[@]}"; do
    [[ -f "${log}" ]] && { echo "→ Removing ${log}"; rm -f "${log}"; }
done

echo "Done. The system LaunchDaemon (ai.cyberarmor.endpoint) is untouched."
echo "To remove the daemon as well: sudo /usr/local/cyberarmor/.venv/bin/python3 /usr/local/cyberarmor/installer.py uninstall"
