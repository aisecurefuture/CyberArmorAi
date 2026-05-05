#!/usr/bin/env bash
set -euo pipefail

mkdir -p /var/jenkins_home/workspace
mkdir -p /var/jenkins_home/init.groovy.d
cp /usr/share/jenkins/ref/init.groovy.d/seed-security-job.groovy /var/jenkins_home/init.groovy.d/seed-security-job.groovy
chown -R jenkins:jenkins /var/jenkins_home

host_work_root="${HOST_JENKINS_WORK_ROOT:-/tmp/cyberarmor-jenkins}"
mkdir -p "$host_work_root"
if ! chown -R jenkins:jenkins "$host_work_root"; then
  echo "[start-jenkins-security] warning: could not fully chown $host_work_root; Jenkins will continue starting, but you should repair the host workdir ownership." >&2
fi
if ! find "$host_work_root" -type d -exec chmod 0775 {} +; then
  echo "[start-jenkins-security] warning: could not fully chmod directories under $host_work_root" >&2
fi
if ! find "$host_work_root" -type f -exec chmod 0664 {} +; then
  echo "[start-jenkins-security] warning: could not fully chmod files under $host_work_root" >&2
fi

if [[ -S /var/run/docker.sock ]]; then
  docker_gid="$(stat -c '%g' /var/run/docker.sock)"
  if ! getent group "$docker_gid" >/dev/null 2>&1; then
    groupadd -for -g "$docker_gid" docker-host
  fi
  docker_group="$(getent group "$docker_gid" | cut -d: -f1)"
  usermod -aG "$docker_group" jenkins
fi

exec su -s /bin/bash jenkins -c /usr/local/bin/jenkins.sh
