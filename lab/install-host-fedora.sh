#!/usr/bin/env bash
# Run explicitly in your terminal after reviewing this file.
# Installs VM tooling; does not run traffic or change host firewall rules.
set -euo pipefail
if [[ "$EUID" -ne 0 ]]; then echo 'Run this setup with sudo in your own terminal.' >&2; exit 1; fi
. /etc/os-release
if [[ "$ID" != fedora ]]; then echo 'This script is for Fedora. See lab/README.md for other hosts.' >&2; exit 1; fi
dnf install -y qemu-kvm libvirt libvirt-daemon-config-network vagrant vagrant-libvirt
if systemctl is-active --quiet libvirtd.service; then
  systemctl enable --now libvirtd.service
elif systemctl list-unit-files virtqemud.socket --no-legend | grep -q '^virtqemud.socket'; then
  systemctl enable --now virtqemud.socket virtnetworkd.socket virtstoraged.socket virtlogd.socket virtlockd.socket
else
  systemctl enable --now libvirtd.service
fi
echo 'VM tooling installed. Run ./lab/init.sh as your normal user from the project folder.'
