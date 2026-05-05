#!/usr/bin/env bash
set -euo pipefail

# Harden a fresh Ubuntu host intended to run the CyberArmor demo stack and
# companion marketing site.
#
# Run as root on Ubuntu 24.04+:
#   sudo bash scripts/deployment/hetzner_harden_ubuntu_demo_host.sh

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root."
  exit 1
fi

ADMIN_USER="${ADMIN_USER:-cyberarmor}"
SSH_PORT="${SSH_PORT:-22}"

echo "== CyberArmor Hetzner Ubuntu hardening =="
echo "Admin user: ${ADMIN_USER}"
echo "SSH port: ${SSH_PORT}"

echo
echo "1) Installing security baseline packages"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ufw \
  fail2ban \
  unattended-upgrades \
  apt-listchanges \
  needrestart \
  ca-certificates \
  curl \
  git \
  jq \
  nginx \
  rsync \
  unzip \
  vim

echo
echo "2) Enabling unattended security updates"
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable unattended-upgrades
systemctl restart unattended-upgrades || true

echo
echo "3) Hardening SSH daemon"
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
if id "${ADMIN_USER}" >/dev/null 2>&1; then
  USER_HOME="$(getent passwd "${ADMIN_USER}" | cut -d: -f6)"
  if [[ -n "${USER_HOME}" && -d "${USER_HOME}/.ssh" ]]; then
    chown -R "${ADMIN_USER}:${ADMIN_USER}" "${USER_HOME}/.ssh"
    chmod 700 "${USER_HOME}/.ssh"
    find "${USER_HOME}/.ssh" -type f -exec chmod 600 {} \;
  fi
fi

echo
echo "5) Configuring UFW"
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
echo "7) Applying kernel/network hardening"
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
echo "8) Final status snapshot"
systemctl --no-pager --full status ssh fail2ban unattended-upgrades nginx | sed -n '1,120p' || true

echo
echo "Hardening complete."
echo "Next:"
echo "- deploy Docker, Node.js, Certbot, the CyberArmor demo stack, and the marketing site"
echo "- add DNS for cyberarmor.ai, www.cyberarmor.ai, app.cyberarmor.ai, and admin.cyberarmor.ai"
echo "- run scripts/deployment/deploy_hetzner_demo_and_marketing.sh"
