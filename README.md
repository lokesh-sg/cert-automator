# Cert Automator
> Enterprise-grade Certificate Management Solution

**The Centralized "Vault" for Automated SSL Certificate Management.**

![Main Dashboard](assets/images/CertAutomator%20Dashboard.png)

> [!NOTE]
> **Project Status**: This is a free, open-source hobby project designed to eliminate the manual toil of managing certificates across homelabs and small networks.

---

## What is CertAutomator?
**CertAutomator** is a secure, self-hosted web application that acts as a single source of truth for your SSL certificates. Instead of manually logging into Proxmox, TrueNAS, Portainer, and OPNsense to update expiring certificates, you upload them **once** to CertAutomator. It then automatically handles the distribution, format conversion (PEM/PFX), and service restarts for you.

## Key Features

### Secure by Design
- **Encryption-at-Rest**: Private keys are AES-256 encrypted (`privkey.enc`) using a master password.
- **Strict Permissions**: Fallback to 0600 permissions if encryption is disabled.
- **Hardened**: Runs as non-root (UID 1000), includes CSRF protection, and uses HttpOnly cookies.
- **Emergency Access**: Generates a one-time-use emergency token for lockout recovery.

### Automation & Intelligence
- **Zero-Touch Startup**: Verifies health of all services immediately on launch.
- **Nightly Watchdog**: Checks for expiring certificates every night at 12:30 AM UTC.
- **Smart Renewals**: Only pushes updates when certificates are actually different.

### Supported Integrations
CertAutomator speaks the native API languages of your favorite services:
- **Virtualization**: Proxmox VE
- **Storage**: TrueNAS (SCALE & CORE)
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

---

## What's New in v1.1.0?
- **Live Timers**: Real-time renewal countdowns.
- **Production Ready**: Switched to Gunicorn WSGI server.
- **Auto-Heal**: UI automatically refreshes status after campaigns.
- See [CHANGELOG.md](documentation/changelog.md) for full details.

---

## Community
Issues and Pull Requests are welcome!
*Built with ❤️ for privacy and automation.*
