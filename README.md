<p align="center">
  <img src="https://raw.githubusercontent.com/YurilLAB/QPot/main/doc/qpot_wallpaper.png" alt="QPot Wallpaper" width="800">
</p>

<h1 align="center">QPot</h1>
<p align="center">
  <strong>Advanced Honeypot Platform</strong><br>
  <em>Developed by Yuril Security Team</em><br>
</p>

<p align="center">
  <a href="https://github.com/YurilLAB/QPot/releases"><img src="https://img.shields.io/github/v/release/YurilLAB/QPot?style=flat-square&color=blue" alt="Release"></a>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.23+-00ADD8.svg?style=flat-square" alt="Go Version"></a>
  <a href="https://docker.com"><img src="https://img.shields.io/badge/Docker-Required-2496ED.svg?style=flat-square" alt="Docker"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License"></a>
</p>

---

## Overview

**QPot** is an enterprise-grade honeypot platform developed by YurilLAB. Built on the solid foundation of T-Pot CE, QPot adds modern security features, enhanced sandboxing, and seamless integration with the Yuril Security ecosystem.

> **Part of the Yuril Security Suite**  
> QPot works alongside [YurilAntivirus](https://github.com/YurilLAB/YurilSecurity/tree/main/YurilAntivirus) and [YurilTracking](https://github.com/YurilLAB/YurilSecurity/tree/main/YurilTracking) to provide comprehensive threat detection and response capabilities.

---

## Why QPot?

### Comparison with T-Pot

| Feature | T-Pot | QPot |
|---------|-------|------|
| Attack Map | Yes | Yes - Enhanced with QPot ID |
| Kibana Dashboard | Yes | Yes - With ClickHouse support |
| 20+ Honeypots | Yes | Yes - Same proven images |
| Per-Honeypot Resources | No | Yes - CPU/Mem/PID limits |
| gVisor/Kata Sandboxing | No | Yes - Container isolation |
| ClickHouse Database | No | Yes - High-performance analytics |
| QPot ID Tracking | No | Yes - Instance identification |
| Stealth Mode | No | Yes - Anti-fingerprinting |
| Yuril Integration | No | Yes - Native ecosystem support |
| Database Migrations | No | Yes - Versioned schema management |
| Data Retention Policies | No | Yes - Automated S3 archival |
| Read Replicas | No | Yes - High availability |
| Cluster Management | No | Yes - Multi-instance with password auth |

### Key Advantages

**Defense in Depth**  
Every honeypot runs in its own sandbox with gVisor, Kata, or Firecracker isolation. Resource limits prevent container escape and resource exhaustion attacks.

**Modern Data Architecture**  
Optional ClickHouse backend provides columnar storage for fast analytics, while the ClickHouse-Kibana connector maintains compatibility with existing Kibana dashboards.

**Unique Instance Tracking**  
Every QPot deployment receives a unique QPot ID (`qp_*`) for multi-instance management, threat correlation, and integration with YurilTracking.

**Stealth Operations**  
Built-in anti-fingerprinting features including fake hostnames, randomized response delays, and MAC address randomization make honeypots harder to detect.

---

## Architecture

```
+-------------------------------------------------------------+
|                        QPot Platform                        |
|                                                             |
|  +-----------------------------------------------------+   |
|  |            Nginx Reverse Proxy (64297)              |   |
|  |  +----------+----------+----------+-------------+    |   |
|  |  | Landing  |  Attack  |  Kibana  |  QPot API   |    |   |
|  |  |  Page    |   Map    | Analytics|   Server    |    |   |
|  |  +----------+----------+----------+-------------+    |   |
|  +-----------------------------------------------------+   |
|                            |                                |
|  +-------------------------+-----------------------------+  |
|  |                         |                             |  |
|  v                         v                             v  |
|  ClickHouse           Honeypots                     Web UI  |
|  (Analytics)        (Docker Containers)            (React)  |
|                                                             |
|  +-----------------------------------------------------+   |
|  |                   Security Features                 |   |
|  |  - gVisor/Kata sandboxing  - Read-only filesystems  |   |
|  |  - Resource limits         - Custom seccomp profiles|   |
|  |  - Network isolation       - MAC randomization      |   |
|  |  - Stealth/deception       - No privileged containers|   |
|  +-----------------------------------------------------+   |
+-------------------------------------------------------------+
```

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/YurilLAB/QPot.git
cd QPot

# Build the QPot CLI
go build -o qpot ./cmd/qpot

# Or use Make
make build
```

### Create and Start Instance

```bash
# Create a new instance (generates unique QPot ID)
./qpot instance create production
# Output: [OK] Created QPot instance 'production'
#         QPot ID: qp_e2imzc43lisklwokb7vlspi7

# Start the instance
./qpot up --instance production
```

### Access Dashboard

| Service | URL | Description |
|---------|-----|-------------|
| Landing Page | https://localhost:64297 | QPot branded entry point |
| Attack Map | https://localhost:64297/map | Real-time attack visualization |
| Kibana | https://localhost:64297/kibana | Log analytics |
| QPot API | https://localhost:64297/api | Management API |

---

## QPot ID System

Every QPot instance receives a unique identifier for tracking and integration:

```bash
# View QPot ID
./qpot id --instance production
# QPot ID: qp_e2imzc43lisklwokb7vlspi7

# The QPot ID is displayed in:
# - GUI popup on startup
# - Web UI header (click to copy)
# - Attack map interface
# - API responses
```

### Integration with YurilTracking

QPot instances can feed threat data directly into YurilTracking for centralized analysis:

```yaml
# qpot.yml
integrations:
  yuril_tracking:
    enabled: true
    endpoint: https://tracking.yuril.local/api/v1/events
    api_key: ${YURIL_API_KEY}
    qpot_id: ${QPOT_ID}
```

---

## Configuration

### Per-Honeypot Resource Limits

```yaml
honeypots:
  cowrie:
    enabled: true
    resources:
      use_custom_limits: true
      max_cpu_percent: 30
      max_memory_mb: 256
      max_pids: 50
      max_file_descriptors: 1024
```

### Database Backend Options

**ClickHouse (Recommended)**
```yaml
database:
  type: clickhouse
  host: localhost
  port: 9000
  database: qpot
```

**TimescaleDB**
```yaml
database:
  type: timescaledb
  host: localhost
  port: 5432
```

**Elasticsearch (Legacy)**
```yaml
database:
  type: elasticsearch
  host: localhost
  port: 9200
```

### Stealth Mode

```yaml
stealth:
  enabled: true
  fake_hostname: webserver-prod-01
  fake_os: "Ubuntu 22.04.3 LTS"
  fake_kernel: "5.15.0-91-generic"
  randomize_response_time: true
  add_artificial_delay: true
  delay_range_ms: 50-200
  block_scanner_probes: true
```

### Database Migrations

QPot supports versioned schema migrations for ClickHouse and TimescaleDB:

```yaml
database:
  type: clickhouse
  auto_migrate: true  # Automatically apply migrations on startup
  target_version: 0   # 0 = latest, or specify specific version
```

View migration status:
```bash
./qpot db migrate status
./qpot db migrate up      # Apply pending migrations
./qpot db migrate down    # Rollback one migration
```

### Data Retention Policies

Automated data lifecycle management with hot/warm/cold tiers:

```yaml
database:
  retention_policies:
    - id: default
      name: "90-Day Retention"
      enabled: true
      hot_retention: 2160h      # Keep in hot storage for 90 days
      warm_retention: 4320h     # Move to warm storage for 180 days
      cold_retention: 8760h     # Archive for 365 days
      archive_type: s3          # s3, gcs, or filesystem
      archive_config:
        endpoint: s3.amazonaws.com
        region: us-east-1
        bucket: qpot-archives
        prefix: honeypot-data/
        access_key_id: ${AWS_ACCESS_KEY_ID}
        secret_access_key: ${AWS_SECRET_ACCESS_KEY}
      compression: gzip
      schedule: "0 2 * * *"     # Run daily at 2 AM
```

### Connection Pooling & Read Replicas

Advanced database connection management:

```yaml
database:
  pool:
    max_open_conns: 25
    max_idle_conns: 10
    conn_max_lifetime: 1h
    conn_max_idle_time: 30m
    health_check_interval: 5m
    acquire_timeout: 30s
  
  read_replicas:
    - name: replica-1
      host: 10.0.0.5
      port: 9000
      priority: 1
      weight: 50
      region: us-east-1
    - name: replica-2
      host: 10.0.0.6
      port: 9000
      priority: 2
      weight: 50
      region: us-west-2
```

---

## Security Features

| Feature | Implementation | Status |
|---------|---------------|--------|
| Sandboxing | gVisor, Kata, Firecracker | Production |
| Resource Limits | CPU, Memory, PIDs, FDs | Production |
| Filesystem | Read-only root, tmpfs overlays | Production |
| Capabilities | Drop ALL, minimal add | Production |
| Seccomp | Custom profiles per honeypot | Production |
| Network | Isolated per-honeypot networks | Production |
| MAC Address | Randomized per container | Production |
| Hostname | Unique per instance | Production |

---

## CLI Reference

```bash
# Instance management
qpot instance create <name>      # Create new instance with QPot ID
qpot instance list               # List all instances
qpot instance remove <name>      # Remove instance

# Lifecycle
qpot up [--instance <name>]      # Start instance
qpot down [--instance <name>]    # Stop instance
qpot status [--instance <name>]  # Show status

# Honeypot management
qpot honeypot list               # List available honeypots
qpot honeypot enable <name>      # Enable honeypot
qpot honeypot disable <name>     # Disable honeypot

# Utilities
qpot logs [honeypot]             # View logs
qpot id [--instance <name>]      # Show QPot ID
qpot config [--instance <name>]  # Edit configuration
```

---

## Cluster Management

QPot supports multi-instance clustering with password authentication for distributed honeypot deployments.

### Initialize a Cluster

Create a new cluster on your central server:

```bash
./qpot cluster init --name production --password "SecurePass123!"

# Output:
# [OK] Cluster initialized successfully
#      Cluster ID:   qc_a1b2c3d4e5f6...
#      Cluster Name: production
#      Node ID:      qn_1234567890ab...
#      Bind Address: 0.0.0.0:7946
#
# [IMPORTANT] Save your Cluster ID and Password!
#             Other nodes will need both to join.
```

### Join a Cluster

Add sensor nodes to the cluster:

```bash
./qpot cluster join \
  --id qc_a1b2c3d4e5f6... \
  --password "SecurePass123!" \
  --seed 192.168.1.10:7946 \
  --node-name sensor-01 \
  --node-addr 192.168.1.20

# Multiple seeds for redundancy:
./qpot cluster join \
  --id qc_a1b2c3d4e5f6... \
  --password "SecurePass123!" \
  --seed 192.168.1.10:7946 \
  --seed 192.168.1.11:7946 \
  --node-name sensor-02
```

### Cluster Operations

```bash
# View cluster status
./qpot cluster status

# Output:
# Cluster ID:    qc_a1b2c3d4e5f6...
# Cluster Name:  production
# Status:        running
# 
# Nodes:
#   Total:       5
#   Healthy:     5
#   Suspect:     0
#   Failed:      0
# 
# Events:        1,234,567 total

# List all nodes
./qpot cluster nodes

# Output:
# NODE ID      NAME            ADDRESS          STATUS     EVENTS
# -----------  --------------  ---------------  ---------  --------
# qn_123456..  leader          192.168.1.10:79  healthy    567890
# qn_789abc..  sensor-01       192.168.1.20:79  healthy    333777
# qn_def012..  sensor-02       192.168.1.21:79  healthy    333000

# Leave cluster (run on the node leaving)
./qpot cluster leave
```

### Cluster Features

| Feature | Description |
|---------|-------------|
| Password Auth | All nodes require cluster ID + password to join |
| Automatic Discovery | Nodes discover each other via gossip protocol |
| Health Monitoring | Automatic detection of failed nodes |
| Event Aggregation | Centralized view of attacks across all nodes |
| Encrypted Communication | TLS encryption between cluster members |
| Read Replicas | Database reads distributed across replicas |

---

## Integration with Yuril Security

QPot is designed to work seamlessly with the Yuril Security ecosystem:

### YurilAntivirus Integration

When YurilAntivirus detects a threat on an endpoint, it can:
- Query QPot for related attack patterns
- Trigger honeypot redeployment with updated signatures
- Share IOCs with the honeypot deception layer

### YurilTracking Integration

QPot feeds real-time attack data to YurilTracking:
- Source IP geolocation and reputation
- Attack patterns and TTPs
- Correlated threat intelligence

### Lockdown Integration

Automatic system hardening when attacks are detected:
```yaml
response:
  on_attack_detected:
    - notify_yuril_tracking
    - trigger_lockdown_hardening
    - isolate_attacker_ip
```

---

## Deployment Modes

### HIVE (Central Server)

Full installation with web UI, analytics, and sensor management:

```bash
./install.sh -t h -u admin -p 'SecurePass123!'
```

### SENSOR (Distributed)

Lightweight sensor for remote deployment:

```bash
./install.sh -t s
```

### MINI (Resource-Constrained)

Minimal footprint for edge deployments:

```bash
./install.sh -t i -u admin -p 'SecurePass123!'
```

---

## Development

```bash
# Build from source
make build

# Run tests
make test

# Build for all platforms
make build-all

# Create release
make release

# Run locally
make dev
```

---

## Project Structure

```
QPot/
├── cmd/qpot/              # CLI entry point
├── internal/
│   ├── cluster/          # Multi-instance cluster management
│   ├── config/           # Configuration management
│   ├── database/         # Database drivers (CH, TSDB, ES)
│   │   ├── migration.go         # Schema migrations
│   │   ├── retention.go         # Data retention & archival
│   │   └── pool.go              # Connection pooling
│   ├── security/         # Sandboxing and isolation
│   ├── instance/         # Instance lifecycle
│   └── server/           # API server
├── docker/
│   ├── attack-map/       # QPot-branded attack map
│   ├── clickhouse-kibana/# ES-compatible CH connector
│   └── nginx/            # Reverse proxy config
├── web/                  # Web UI
├── docs/                 # Documentation
└── scripts/              # Install/update scripts
```

---

## License

MIT License - See [LICENSE](LICENSE)

---

## Acknowledgments

QPot builds upon the excellent work of:

- **[T-Pot CE](https://github.com/telekom-security/tpotce)** by Deutsche Telekom Security - The foundation honeypot platform
- **The Honeynet Project** - Honeypot research and development

QPot adds enterprise features, enhanced security, and integration with the Yuril Security ecosystem.

---

## Support

- **Issues**: [GitHub Issues](https://github.com/YurilLAB/QPot/issues)
- **Enterprise Support**: Contact via GitHub

---

## Contributors

- **Yuril** - Project lead and primary developer

---

<p align="center">
  <strong>Built by Yuril Security</strong><br>
  <em>Australian-made cybersecurity</em>
</p>
