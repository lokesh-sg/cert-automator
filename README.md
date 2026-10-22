# CertAutomator - v1.2.1
> Enterprise-grade Certificate Management Solution

**The Centralized Vault for Automated SSL Certificate Management.**

![Main Dashboard](assets/images/CertAutomator%20Dashboard.png)

> [!NOTE]
> **Project Status**: This is a free, open-source hobby project designed to eliminate the manual toil of managing certificates across homelabs and small networks.

---

## What is CertAutomator?
**CertAutomator** is a secure, self-hosted web application that acts as a single source of truth for your SSL certificates. Instead of manually logging into Proxmox, TrueNAS, Portainer, and OPNsense to update expiring certificates, you upload them **once** to CertAutomator. It then automatically handles the distribution, format conversion (PEM/PFX), and service restarts for you.

## Key Features

### Secure by Design
- **Dual-Envelope Encryption**: Private keys and vault configurations are encrypted with a 256-bit Master Vault Key (`MVK`), wrapped in dual password and recovery envelopes.
- **Zero-Data-Loss Recovery**: Reset forgotten Master Passwords using your 32-character Emergency Recovery Key without wiping target service configs or SSL private keys.
- **Hardened Execution**: Runs as non-root (UID 1000), includes global CSRF protection, HttpOnly cookies, and strict session hardening.

### Automation & Intelligence
- **Zero-Touch Startup**: Verifies health of all services immediately on launch.
- **Nightly Watchdog**: Checks for expiring certificates every night at 12:30 AM UTC.
- **Smart Renewals**: Only pushes updates when certificates are actually different.

### Supported Integrations
CertAutomator speaks the native API languages of your favorite services:
- **Virtualization**: Proxmox VE
- **Storage**: TrueNAS (SCALE & CORE), OpenMediaVault (OMV)
- **Network**: OPNsense, Aruba ClearPass
- **Containers**: Portainer
- **Generic**: SSH/SCP support for Syncthing, Wazuh, Heimdall, and Linux servers.

---

## Screenshots

| Dashboard | Service Manager |
|:---:|:---:|
| ![Cert Manager](assets/images/Certificate%20Manager.png) | ![Service List](assets/images/Service%20Manager.png) |
| **Monitor Expirations** | **Manage Integrations** |

---

## Quick Start

### 1. Run with Docker Compose
Create a `docker-compose.yml`:

```yaml
version: '3.8'

services:
  cert-automator:
    image: lokeshsg/cert-automator:latest
    container_name: cert-automator
    restart: unless-stopped
    ports:
      - "5050:5050"
    volumes:
      - ./config.yaml:/app/config.yaml
      - ./auth.json:/app/auth.json
      - ./certs:/certs
      - ./backup:/backup
      - ./logs:/app/logs
    environment:
      - FLASK_SECRET=GenerateASecretStringHere
      # Unattended auto-unlock on container/host restart (optional):
      # - MASTER_PASSWORD=YourVaultPassword
      # - RECOVERY_KEY=YourEmergencyRecoveryKey
      # Note: CERT_DIR and BACKUP_DIR env vars are optional.
      # The app automatically detects if '/certs' or '/backup' are mounted.
```

### 2. Set Permissions
**Crucial**: CertAutomator runs as a secure user (UID 1000).
```bash
# On your host
touch config.yaml auth.json
mkdir -p certs backup logs
chown -R 1000:1000 config.yaml auth.json certs backup logs
```

### 3. Launch
```bash
docker compose up -d
```
Visit `http://localhost:5050` to initialize your vault!

### 4. Configuration & Environment Variables
For a full list of all supported environment variables, including unattended auto-unlock, session lifetimes, custom paths, and debugging, see the **[Environment Variables Reference](documentation/ENVIRONMENT_VARIABLES.md)**.

---

## What's New in v1.2.1?
- **Background Watchdog & Startup Scheduler**: Activates automatic background health checks and 12:30 AM nightly pulls and renewals under Gunicorn WSGI.
- **Portainer & Distroless Hardening**: Resolves `ls` command missing errors by inspecting host bind mounts directly and uses stable container names for restarts with self-healing recovery.
- **SSH Sudo Refinement**: Directly supplies sudo passwords via `sudo -S` when required, eliminating noisy false error logs.
- **In-App Emergency Recovery Key Generator**: Authenticated users can generate or rotate their 32-character Emergency Recovery Key directly from Settings.
- **Dual-Envelope Cryptography (Zero-Loss Recovery)**: Master Vault Key (`MVK`) architecture with independent password and recovery envelopes.
- **Production Hardened**: Python 3.13-slim-bookworm base image with latest security updates (`cryptography>=50.0.2`, `urllib3>=2.8.0`, `setuptools>=84.0.0`, `certifi>=2026.10.19`).
- See [CHANGELOG.md](documentation/changelog.md) for full version history.

---

## Community
Issues and Pull Requests are welcome!
*Built for privacy and homelab automation.*
