#!/usr/bin/env bash
set -euo pipefail
for binary in python3 nft tc ip netplan; do
  if ! command -v "$binary" >/dev/null; then echo "Missing guest prerequisite: $binary" >&2; exit 1; fi
done
install -d -m 755 /opt/flowlab/vendor
tar -xzf /tmp/flowlab-scapy.tar.gz -C /opt/flowlab/vendor
install -m 700 /tmp/flowlab-agent.py /usr/local/sbin/flowlab-agent
install -m 600 /tmp/flowlab-token /etc/flowlab-token
rm -f /tmp/flowlab-token
lab_ip="$1"
case "$lab_ip" in 192.168.56.11|192.168.56.12|192.168.56.13|192.168.56.14) ;; *) exit 1 ;; esac
# Resume-safe configuration of the experiment NIC, without changing eth0 routing or DNS.
cat > /etc/netplan/99-flowlab.yaml <<EOF
network:
  version: 2
  ethernets:
    eth1:
      dhcp4: false
      addresses: [$lab_ip/24]
      optional: true
EOF
chmod 600 /etc/netplan/99-flowlab.yaml
netplan apply
lab_interface=""
for attempt in {1..40}; do
  lab_interface="$(ip -o -4 addr show | awk -v ip="$lab_ip" '$4 ~ ("^" ip "/") {print $2; exit}')"
  if [[ -n "$lab_interface" ]]; then break; fi
  sleep 0.25
done
if [[ -z "$lab_interface" ]]; then echo 'Peer interface not found' >&2; exit 1; fi
cat > /etc/systemd/system/flowlab-agent.service <<EOF
[Unit]
Description=FlowLab isolated VM agent
After=network-online.target
Wants=network-online.target
[Service]
Environment=FLOWLAB_IP=$lab_ip
Environment=FLOWLAB_INTERFACE=$lab_interface
Environment=PYTHONPATH=/opt/flowlab/vendor
ExecStart=/usr/bin/python3 /usr/local/sbin/flowlab-agent
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now flowlab-agent
systemctl restart flowlab-agent
