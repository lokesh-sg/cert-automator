# CertAutomator

**The Centralized "Vault" that Solves the Pain of Certificate Renewals.**

> [!NOTE]
> This is a personal hobby project of mine, built to eliminate the manual toil and frustration of managing SSL certificates across different platforms.

CertAutomator is a powerful, secure, and user-friendly web application designed to eliminate the manual "pain" of SSL certificate management. It provides a single point of upload for your certificates and automatically distributes them to a wide range of services across your network.

---

## Key Features

### Secure by Design
- **Encrypted Local Vault**: All credentials, configs, and **Private Keys** (`privkey.enc`) are AES-encrypted on disk.
- **Hardened Sessions**: Built-in CSRF protection, HttpOnly cookies, and strict session management.
- **Emergency Access**: Every deployment generates a unique one-time Emergency Reset Token in the logs.

### Intelligent Automation
- **Zero-Touch Startup**: Automatically verifies the health of all local and remote certificates immediately upon launch.
- **Nightly Health Checks**: Runs a global verification engine every night at 12:30 AM to catch expiring certificates before they cause outages.
- **UTC-Aware Accuracy**: Precision expiration tracking synced to global UTC time.

### Broad Integration Support
CertAutomator speaks the language of your favorite local and enterprise services:
- **API Drivers**: Proxmox, TrueNAS (SCALE/CORE), OPNsense, Portainer.
- **SSH/SCP Tunneling**: Syncthing, Wazuh, Heimdall, Generic Linux.
- **Advanced Conversion**: Aruba ClearPass (PEM to PFX auto-conversion).
- **Extensible**: Generic Webhooks and custom handler support.

---

## What's New in v1.1.3? (Project Aegis)
- **"Cyber Vault" UI Overhaul**: Stunning high-contrast technical aesthetic with precision geometry and neon accents.
- **CyberSelect™ Engine**: Custom dropdown system that bypasses macOS/Linux system limitations for perfect `JetBrains Mono` rendering.
- **Stable Log Handling**: Intelligent anchor-based scroll locking for real-time monitoring.
- **Broad Integration**: Native support for Proxmox, TrueNAS, OMV, Portainer, OPNsense, and Wazuh.
- **Health Intelligence**: Dynamic status badges that analyze certificate health across your entire network.

---

## Quick Start

### 1. Create a `docker-compose.yml`
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
```

### 2. Initialize & Launch
```bash
# Create persistent storage files
touch config.yaml auth.json
mkdir -p certs backup logs

# Fire it up
docker compose up -d
```

### 3. Setup
Visit `http://[server-ip]:5050` to set your administrator credentials and initialize your encrypted vault!

---

## How it Works
1. **Upload**: You upload a certificate pack (Cert + Key + optional Chain) once.
2. **Assign**: You map that certificate to your services (e.g., "Proxmox Cluster").
3. **Automate**: CertAutomator handles the transmission, format conversion, and service restarts for you.
4. **Monitor**: The dashboard shows you two statuses: **Local Pack** (is the file ready?) and **Deployed** (is the service actually using it?).

---

## Community & Support
CertAutomator is built for the community. If you encounter issues or want to suggest a new handler, please check the logs or reach out on [GitHub](https://github.com/lokesh-sg/cert-automator)! 

*Built with ❤️ for privacy and automation.*
