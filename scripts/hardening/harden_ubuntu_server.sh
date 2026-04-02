#!/usr/bin/env bash
set -euo pipefail

# CyberArmor server hardening helper for Ubuntu 24.04+.
#
# What this script does:
# - updates package metadata and installs baseline security tools
# - enables unattended security updates
# - configures a basic firewall with SSH, HTTP, and HTTPS only
# - installs and enables fail2ban for SSH protection
# - disables password SSH auth and root SSH login
# - turns on basic kernel/network hardening sysctls
# - tightens file permissions on SSH-related paths
#
# What this script does NOT do:
# - manage cloud firewalls at the provider level
# - provision TLS certificates
# - install Docker or application dependencies
# - rotate secrets or back up your databases
#
# Review before use. Run as root on a fresh Ubuntu server:
#   sudo bash scripts/hardening/harden_ubuntu_server.sh

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root."
  exit 1
fi

SSH_PORT="${SSH_PORT:-22}"
ADMIN_USER="${ADMIN_USER:-cyberarmor}"

echo "== CyberArmor Ubuntu hardening =="
echo "SSH port: ${SSH_PORT}"
echo "Admin user: ${ADMIN_USER}"

echo
echo "1) Updating package index and installing security utilities"
# Install core hardening tools:
# - ufw: host firewall
# - fail2ban: brute-force protection
# - unattended-upgrades: automatic security updates
# - needrestart: reminds/restarts affected services after package updates
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ufw \
  fail2ban \
  unattended-upgrades \
  apt-listchanges \
  needrestart \
  ca-certificates \
  curl \
  jq \
  vim

echo
echo "2) Enabling automatic security updates"
# Configure unattended-upgrades so the server keeps receiving Ubuntu security fixes.
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

systemctl enable unattended-upgrades
systemctl restart unattended-upgrades || true

echo
echo "3) Hardening SSH daemon settings"
# Disable the most common weak SSH patterns:
# - no root login over SSH
# - no password authentication
# - no keyboard-interactive auth fallback
# - no empty passwords
# - limit authentication attempts
mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-cyberarmor-hardening.conf <<EOF
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers ${ADMIN_USER}
EOF

sshd -t
systemctl restart ssh

echo
echo "4) Tightening SSH file permissions"
# Enforce conservative permissions on SSH directories and keys for the admin user.
if id "${ADMIN_USER}" >/dev/null 2>&1; then
  USER_HOME="$(getent passwd "${ADMIN_USER}" | cut -d: -f6)"
  if [[ -n "${USER_HOME}" && -d "${USER_HOME}/.ssh" ]]; then
    chown -R "${ADMIN_USER}:${ADMIN_USER}" "${USER_HOME}/.ssh"
    chmod 700 "${USER_HOME}/.ssh"
    find "${USER_HOME}/.ssh" -type f -exec chmod 600 {} \;
  fi
fi

echo
echo "5) Configuring UFW firewall"
# Default-deny inbound traffic, then explicitly allow the ports we expect:
# - SSH for administration
# - HTTP/HTTPS for reverse proxy traffic
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp"
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
ufw status verbose

echo
echo "6) Enabling fail2ban"
# fail2ban watches logs and temporarily blocks repeated failed SSH attempts.
cat >/etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
logpath = %(sshd_log)s
banaction = ufw
maxretry = 5
findtime = 10m
bantime = 1h
EOF

systemctl enable fail2ban
systemctl restart fail2ban

echo
echo "7) Applying basic kernel and network hardening"
# These sysctls reduce spoofing risk, disable redirects, and tighten kernel leakage.
cat >/etc/sysctl.d/99-cyberarmor-hardening.conf <<'EOF'
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF

sysctl --system >/dev/null

echo
echo "8) Verifying service status"
systemctl --no-pager --full status ssh fail2ban unattended-upgrades | sed -n '1,80p' || true

echo
echo "Hardening complete."
echo "Next recommended steps:"
echo "- Install Docker and deploy CyberArmor behind Nginx"
echo "- Add TLS certificates"
echo "- Keep internal service ports bound to localhost or Docker network only"
echo "- Replace all default application secrets before exposure"
