# Centralized Logging System

This directory contains the necessary configuration files to set up a centralized logging system for the CloudServ5 Message Board application using Loki, Promtail, and Grafana.

## Components

1. **Loki**: A lightweight log storage system.
2. **Promtail**: A log collector that ships logs to Loki.
3. **Grafana**: A unified interface to query logs and metrics.

## Setup Instructions

### 1. Ensure the network exists

The docker-compose file assumes there's a monitoring network called `monitor_monitoring-network`. If it doesn't exist, you can create it:

```bash
docker network create monitor_monitoring-network
```

### 2. Start the logging services

```bash
cd hsfuldablog/monitoring/Logging
docker-compose up -d
```

### 3. Configure Grafana to use Loki as a data source

If you're using the provided Grafana, add the Loki data source by copying the datasource configuration:

```bash
mkdir -p ../grafana/provisioning/datasources
cp grafana-loki-datasource.yml ../grafana/provisioning/datasources/
```

### 4. Import the provided dashboard

1. Log in to Grafana (default credentials: admin/admin)
2. Go to Dashboards > Import
3. Upload the `grafana-dashboard.json` file or paste its contents

## How It Works

- **Promtail** collects logs from the Docker instances and forwards them to Loki
- **Loki** stores and indexes the logs
- **Grafana** provides a user interface to search, filter, and visualize the logs

## Log Sources

The system collects logs from:

1. All Docker containers running on the monitoring instance
2. System logs from the monitoring instance
3. Logs from the three Docker instances running the application

## Troubleshooting

If you don't see logs in Grafana:

1. Check if Loki and Promtail are running: `docker ps | grep "loki\|promtail"`
2. Verify Promtail can access the log files: `docker logs promtail`
3. Ensure Loki is properly configured as a data source in Grafana
4. Check if there are any network connectivity issues between Promtail and Loki

## Customization

You can modify the `promtail-config.yml` file to add more log sources or change the scraping configuration. 