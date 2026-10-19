# Environment Variables Reference — CertAutomator

This document provides a complete reference for all supported environment variables accepted by CertAutomator, their default values, purposes, and security implications.

---

## Quick Reference Table

| Variable | Default Value | Required? | Category | Description |
| :--- | :--- | :--- | :--- | :--- |
| `FLASK_SECRET` | `'dev-fallback-secret-key-non-secure'` | **Yes** (in Prod) | Security | Session signing key for cookies & CSRF tokens. |
| `NODE_ENV` | `None` | Optional | Runtime | Set to `'production'` to enforce strict security checks. |
| `USE_HTTPS` | `'false'` | Optional | Security | Set to `'true'` when accessed directly via HTTPS or behind an SSL-terminating reverse proxy with forwarded SSL. |
| `MASTER_PASSWORD` | `None` | Optional | Vault | Unattended auto-unlock for background watchdog on container reboot. |
| `RECOVERY_KEY` | `None` | Optional | Vault | Unattended auto-unlock using 32-character Emergency Recovery Key. |
| `CONFIG_PATH` | `'config.yaml'` (`/app/config.yaml` in Docker) | Optional | Storage | Path to encrypted vault service definitions. |
| `AUTH_PATH` | `'auth.json'` (`/app/auth.json` in Docker) | Optional | Storage | Path to user database and dual-envelope credentials. |
| `CERT_DIR` | `'certs'` (`/certs` in Docker) | Optional | Storage | Path to managed SSL certificate packs. |
| `BACKUP_DIR` | `'backups'` (`/backup` in Docker) | Optional | Storage | Path to rolling historical backups of `config.yaml`. |
| `LOG_FILE` | `/app/logs/cert_automate.log` or `<LOG_DIR>/cert_automate.log` | Optional | Logging | Explicit path to application rotating log file. |
| `LOG_DIR` | `'logs'` | Optional | Logging | Directory for log files if `LOG_FILE` is unset. |
| `TZ` | Container default (UTC) | Optional | System | Sets container timezone (e.g., `America/Los_Angeles`). |

---

## Detailed Variable Specifications

### 1. Security & Web Session

#### `FLASK_SECRET`
* **Default**: `'dev-fallback-secret-key-non-secure'`
* **Type**: String (cryptographically random recommended)
* **Function**: Cryptographic secret key used by Flask to sign session cookies and generate CSRF prevention tokens.
* **Best Practice**: Generate a 32+ character random string (e.g. `openssl rand -hex 32`) and provide it in your `docker-compose.yml` or `.env`.
* **Behavior in Production**: If `NODE_ENV=production` is set and `FLASK_SECRET` is omitted, the application will refuse to start to protect against session forgery.

#### `USE_HTTPS`
* **Default**: `'false'`
* **Type**: Boolean string (`'true'` / `'false'`)
* **Function**: When set to `'true'`, enforces the `Secure` flag on session cookies (`SESSION_COOKIE_SECURE = True`), ensuring browsers only transmit cookies over encrypted HTTPS connections.
* **Usage**: Set `USE_HTTPS=true` if you access CertAutomator through a domain with HTTPS (e.g., Cloudflare Tunnel, Nginx Proxy Manager, Traefik, or reverse proxy).

#### `NODE_ENV`
* **Default**: `None`
* **Type**: String (`'production'` or unset)
* **Function**: Controls runtime strictness. When set to `production`, `FLASK_SECRET` becomes mandatory.

---

### 2. Vault Auto-Unlock (Unattended Reboot Automation)

CertAutomator uses **Dual-Envelope Cryptography**. When the container starts, it begins in a locked state in memory. By default, background pulls and renewals wait until a user logs in via the web dashboard. For headless / automated servers, you can provide an auto-unlock secret:

#### `MASTER_PASSWORD`
* **Default**: `None`
* **Type**: String
* **Function**: Unlocks the vault internally at startup by unwrapping the `password_envelope` in `auth.json`. This activates the background watchdog scheduler so that Let's Encrypt / NPM pulls and downstream renewals continue automatically without requiring interactive browser login after host reboots.
* **Web UI Safety**: Even with `MASTER_PASSWORD` set in `.env`, the web dashboard **still requires standard username + password authentication** to view or manage certificates.

#### `RECOVERY_KEY`
* **Default**: `None`
* **Type**: String (32-character hex)
* **Function**: Unlocks the vault internally using your **Emergency Recovery Key** by unwrapping `recovery_envelope` in `auth.json`.
* **Security Advantage**: If you prefer **not** to put your personal Master Password in a plain-text configuration file or environment variable, provide `RECOVERY_KEY` instead. Both envelopes unlock the exact same Master Vault Key (`MVK`).

---

### 3. Storage Paths & Mount Points

CertAutomator features **Smart Fallback Path Resolution**: it prioritizes explicit environment variables, automatically checks standard Docker root mount points (`/certs`, `/backup`), and falls back to local relative paths for bare-metal development.

#### `CONFIG_PATH`
* **Default**: `config.yaml` (Local Dev) / `/app/config.yaml` (Docker Compose)
* **Function**: Path to the AES-256 encrypted configuration file containing target service credentials, API tokens, and certificate sources.

#### `AUTH_PATH`
* **Default**: `auth.json` (Local Dev) / `/app/auth.json` (Docker Compose)
* **Function**: Path to the administrative authentication database containing the username, `password_envelope`, and `recovery_envelope`.

#### `CERT_DIR`
* **Default**: Auto-detects `/certs` (if mounted in Docker), otherwise `certs/`
* **Function**: Root directory where managed certificate packs (`fullchain.pem` and encrypted `privkey.enc`) are stored.

#### `BACKUP_DIR`
* **Default**: Auto-detects `/backup` (if mounted in Docker), otherwise `backups/`
* **Function**: Location where timestamped rolling backups (`config.YYYYMMDD-HHMMSS.yaml.bak`) are stored. CertAutomator maintains the last 20 backups automatically.

---

### 4. Logging & System

#### `LOG_FILE`
* **Default**: Unset (defaults to `LOG_DIR/cert_automate.log` or `/app/logs/cert_automate.log`)
* **Function**: Explicit file path for the rotating log file. Rotates up to 5 backups at 10 MB each.

#### `LOG_DIR`
* **Default**: `logs` (Local) / `/app/logs` (Docker)
* **Function**: Directory where `cert_automate.log` is created if `LOG_FILE` is not explicitly defined.

#### `TZ`
* **Default**: UTC
* **Type**: Olson timezone identifier (e.g., `America/Los_Angeles`, `America/New_York`, `Europe/London`, `Asia/Kolkata`)
* **Function**: Configures the container's system clock. This determines the exact local time when the **12:30 AM nightly scheduler** triggers.

---

## Production `docker-compose.yml` Example

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
      # Mandatory Security Key
      - FLASK_SECRET=a8f9c2d1e4b70635198246dfac7819324e908b1a7c5d3f2e1b4c6a8d0f2e4b6a
      - USE_HTTPS=true
      - TZ=America/Los_Angeles

      # Optional: Unattended Auto-Unlock on Server Reboot
      # - RECOVERY_KEY=a1b2c3d4e5f60718293a4b5c6d7e8f90
      # OR:
      # - MASTER_PASSWORD=YourMasterPasswordHere

    healthcheck:
      test: [ "CMD", "curl", "-f", "http://localhost:5050/api/health" ]
      interval: 1m
      timeout: 10s
      retries: 3
    network_mode: bridge
```
