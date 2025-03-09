#!/bin/bash

# Script to install Promtail on a Docker instance
# Usage: ./install-promtail.sh <loki_hostname_or_ip>

set -e

LOKI_HOST=${1:-loki}
PROMTAIL_VERSION="2.9.1"
INSTALL_DIR="/opt/promtail"
CONFIG_FILE="/opt/promtail/promtail-config.yml"
SERVICE_FILE="/etc/systemd/system/promtail.service"

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Create installation directory
mkdir -p $INSTALL_DIR

# Download Promtail
echo "Downloading Promtail..."
wget -q -O /tmp/promtail.zip "https://github.com/grafana/loki/releases/download/v${PROMTAIL_VERSION}/promtail-linux-amd64.zip"
unzip -o /tmp/promtail.zip -d $INSTALL_DIR
chmod +x $INSTALL_DIR/promtail-linux-amd64
ln -sf $INSTALL_DIR/promtail-linux-amd64 /usr/local/bin/promtail

# Create Promtail configuration
cat > $CONFIG_FILE << EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /opt/promtail/positions.yaml

clients:
  - url: http://${LOKI_HOST}:3100/loki/api/v1/push

scrape_configs:
  - job_name: docker
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
        refresh_interval: 5s
    relabel_configs:
      - source_labels: ['__meta_docker_container_name']
        regex: '/(.*)'
        target_label: 'container'

  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: system
          __path__: /var/log/*.log

  - job_name: docker_logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: docker
          __path__: /var/lib/docker/containers/*/*.log
EOF

# Create systemd service file
cat > $SERVICE_FILE << EOF
[Unit]
Description=Promtail Log Collector
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/promtail -config.file=${CONFIG_FILE}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable promtail
systemctl start promtail

echo "Promtail installed and configured to send logs to ${LOKI_HOST}:3100"
echo "Check status with: systemctl status promtail" 