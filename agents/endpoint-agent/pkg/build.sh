#!/usr/bin/env bash
# Build a macOS .pkg installer for the CyberArmor Endpoint Agent.
#
# Output: ./dist/cyberarmor-endpoint-agent-${VERSION}.pkg
#
# What the resulting .pkg does on install:
#   1. preinstall: bounce any existing daemon so files aren't busy
#   2. payload  : drop /usr/local/cyberarmor/{agent.py, monitors/, .venv, ...}
#                 and helper assets (clipboard_helper.py, wrapper, scripts)
#   3. postinstall:
#        - python3 -m venv /usr/local/cyberarmor/.venv
#        - pip install -r requirements.txt  (includes pyperclip, setproctitle)
#        - redeem bootstrap token if /etc/cyberarmor/install.env contains one
#          (admins can pre-bake an install.env into the package payload)
#        - write /Library/LaunchDaemons/ai.cyberarmor.endpoint.plist
#        - launchctl bootstrap + kickstart the daemon
#        - su to the active console user and run install_clipboard_helper.sh
#          so the per-user LaunchAgent is wired up in one shot
#
# Optional signing — set DEVELOPER_ID="Developer ID Installer: Your Co" and
# the script will productsign the result. Notarisation is left to your CI
# flow (xcrun notarytool submit + staple).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
AGENT_DIR="$REPO_ROOT/agents/endpoint-agent"
PKG_DIR="$AGENT_DIR/pkg"
BUILD_DIR="$PKG_DIR/build"
PAYLOAD_ROOT="$BUILD_DIR/payload"
DIST_DIR="$PKG_DIR/dist"
VERSION="${VERSION:-1.0.0}"
IDENTIFIER="ai.cyberarmor.endpoint"
PRODUCT_NAME="CyberArmor Endpoint Agent"

DEVELOPER_ID="${DEVELOPER_ID:-}"   # optional, for productsign

echo "→ Building ${PRODUCT_NAME} v${VERSION}"

rm -rf "$BUILD_DIR"
mkdir -p "$PAYLOAD_ROOT/usr/local/cyberarmor"
mkdir -p "$BUILD_DIR/scripts"
mkdir -p "$DIST_DIR"

echo "→ Staging payload"
# Copy the agent source tree (Python only — no .venv, no __pycache__).
rsync -a \
  --exclude '.venv' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude 'pkg' \
  --exclude 'tests' \
  --exclude 'Dockerfile' \
  "$AGENT_DIR/" "$PAYLOAD_ROOT/usr/local/cyberarmor/"

echo "→ Staging install/postinstall scripts"
cp "$PKG_DIR/scripts/preinstall" "$BUILD_DIR/scripts/preinstall"
cp "$PKG_DIR/scripts/postinstall" "$BUILD_DIR/scripts/postinstall"
chmod +x "$BUILD_DIR/scripts/preinstall" "$BUILD_DIR/scripts/postinstall"

COMPONENT_PKG="$BUILD_DIR/cyberarmor-endpoint-agent-component.pkg"
echo "→ pkgbuild → $COMPONENT_PKG"
pkgbuild \
  --root "$PAYLOAD_ROOT" \
  --scripts "$BUILD_DIR/scripts" \
  --identifier "$IDENTIFIER" \
  --version "$VERSION" \
  --install-location "/" \
  "$COMPONENT_PKG"

OUT_PKG="$DIST_DIR/cyberarmor-endpoint-agent-${VERSION}.pkg"
echo "→ productbuild → $OUT_PKG"
productbuild \
  --distribution "$PKG_DIR/distribution.xml" \
  --resources "$PKG_DIR/resources" \
  --package-path "$BUILD_DIR" \
  --version "$VERSION" \
  "$OUT_PKG"

if [[ -n "$DEVELOPER_ID" ]]; then
  echo "→ productsign with '$DEVELOPER_ID'"
  SIGNED="$DIST_DIR/cyberarmor-endpoint-agent-${VERSION}-signed.pkg"
  productsign --sign "$DEVELOPER_ID" "$OUT_PKG" "$SIGNED"
  mv "$SIGNED" "$OUT_PKG"
fi

echo
echo "Built: $OUT_PKG"
echo "Install: sudo installer -pkg \"$OUT_PKG\" -target /"
