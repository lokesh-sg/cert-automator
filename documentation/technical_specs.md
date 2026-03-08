# Technical Specifications - CertAutomator

**Version**: v1.2.0.20260308.01
**Date**: 2026-03-08
**Author**: Lokesh G

## 1. Project Structure
```text
/cert-automate/
├── dev/                     # Source of Truth
│   ├── app/
│   │   ├── static/          # CSS/JS (Cyber Vault Theme)
│   │   ├── templates/       # HTML
│   │   ├── server.py        # Flask App / Entrypoint
│   │   ├── cert_manager.py  # Logic Core (Scheduler & Orchestration)
│   │   ├── acme_source.py   # Native ACME Client (v1.2.0)
│   │   ├── npm_source.py    # NPM Pull Integration (v1.2.0)
│   │   └── *_handler.py     # Service Adapters (Proxmox, TrueNAS, etc.)
│   ├── config.yaml          # Service & Source Configuration
│   ├── Dockerfile           # Python 3.13-slim Base
│   └── docker-compose.yml   # Multi-environment Orchestration
├── certs/                   # Active Certificates (Unified Volume)
├── backups/                 # Encrypted Config & Cert Backups
├── documentation/           # System Docs & Guides
└── run_dev.sh               # Local Development Launcher
```

## 2. Certificate Lifecycle Architecture (v1.2.0)
CertAutomator has evolved from a push-only tool to a **Source-Storage-Sink** architecture.

### 2.1 Sources (Inbound)
- **Native ACME**: Automated issuance via Let's Encrypt/ZeroSSL using DNS-01 (Cloudflare).
- **Nginx Proxy Manager**: Automated certificate pulling from active NPM instances.
- **Manual Upload**: Multi-part PEM upload via Dashboard.

### 2.2 Storage (Core)
- **Encryption**: Private keys are stored as `privkey.enc` using AES-256 symmetric encryption.
- **Deduplication**: Pulse-check logic calculates CRC/Serial of inbound certs vs local storage to prevent redundant service reloads.

### 2.3 Sinks (Outbound)
- **Service Handlers**: Deployment adapters for Proxmox, TrueNAS, OPNsense, ClearPass, OMV, Wazuh, Portainer, etc.
- **SSH/Webhooks**: Generic handlers for custom Linux/Web integrations.

## 3. Security Specifications
- **At-Rest Encryption**: 
    - **Config**: Fernet (AES-128) with PBKDF2 (100k iterations).
    - **Keys**: AES-256 for private keys.
- **Network Security**: Forced 10/30s timeouts on all external API requests to mitigate DoS vulnerabilities.
- **Runtime**:
    - **Base Image**: Python 3.13 (Secure Slim).
    - **Non-Root**: Container runs as `appuser` (UID 1000).
    - **CVE Hygiene**: Production builds include mandatory `apt-get upgrade` cycles.

## 4. API Reference (Port 5050)
### Core Endpoints
- **GET** `/api/status`: Returns system health, source status, and service states.
- **POST** `/api/renew/all`: Iterates through all configured sources and pushes to enabled services.
- **POST** `/api/upload`: Direct certificate injection.
- **GET** `/api/logs`: Real-time log streaming.

## 5. Environment Setup
### Prerequisites
- Docker & Docker Compose
- Python 3.13 (for local dev)

### Local Dev
```bash
./run_dev.sh
```

### Production Build
```bash
docker build -t cert-automator:latest -f dev/Dockerfile dev/
```
