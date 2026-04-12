#!/usr/bin/env bash
set -euo pipefail

mkdir -p /var/jenkins_home/workspace
mkdir -p /var/jenkins_home/init.groovy.d
cp /usr/share/jenkins/ref/init.groovy.d/seed-security-job.groovy /var/jenkins_home/init.groovy.d/seed-security-job.groovy
chown -R jenkins:jenkins /var/jenkins_home

if [[ -S /var/run/docker.sock ]]; then
  docker_gid="$(stat -c '%g' /var/run/docker.sock)"
  if ! getent group "$docker_gid" >/dev/null 2>&1; then
    groupadd -for -g "$docker_gid" docker-host
  fi
  docker_group="$(getent group "$docker_gid" | cut -d: -f1)"
  usermod -aG "$docker_group" jenkins
fi

exec su -s /bin/bash jenkins -c /usr/local/bin/jenkins.sh
