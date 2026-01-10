# Technical Specifications - Certificate Automation Tool

**Version**: v1.1.1.20260109.11
**Date**: 2026-01-06
**Author**: Lokesh G

## 1. Project Structure
```text
/cert-automate/
├── dev/                     # Development Source
│   ├── app/
│   │   ├── static/          # CSS/JS
│   │   ├── templates/       # HTML
│   │   ├── server.py        # Flask App (Contains Smart Path Resolution)
│   │   ├── wsgi.py          # Production Entrypoint
│   │   ├── cert_manager.py  # Logic Core
│   │   └── *_handler.py     # Service Adapters
│   ├── config.yaml          # Service Configuration
│   ├── Dockerfile           # Multi-stage build (Non-root, Gunicorn, WORKDIR /app)
│   └── docker-compose.yml   # Orchestration
├── prod/                    # Stable Deployment Target
├── code_backup/             # Unzipped archives of previous builds
├── input_certificates/      # Hot-folder for certs
└── build_scripts/
    └── build.py             # Packaging Logic

## 2. Path Configuration Logic
The application employs "Smart Path Resolution" to seamlessly handle both Local Development and Docker environments without manual configuration.

**Priority Order:**
1.  **Environment Variable** (e.g., `CERT_DIR=/custom/path`) - Highest priority.
2.  **Docker Mounts** (Auto-Detection) - Checks if standard mounts `/certs` or `/backup` exist and are writable.
3.  **Local Relative** (Fallback) - Uses `./certs` or `./backups` relative to the application root.

This ensures that mapping volumes to `/certs` in `docker-compose.yml` works out-of-the-box, while local `run_dev.sh` uses local folders.
```

## 3. Security Specifications
- **Private Key Storage**: Private keys are stored as `privkey.enc` (AES-256 encrypted) in the certificate pack directory.
- **Config Storage**: Service credentials in `config.yaml` are encrypted using Fernet (AES-128).
- **Runtime Security**: Decryption occurs only in memory during validation or renewal.

## 4. API Reference
The application exposes a REST API on port `5050`.

### Status
- **GET** `/api/status`
- **Response**:
```json
{
  "certs_ready": true,
  "services": [
    { "name": "proxmox", "type": "proxmox", "host": "192.168.1.100" }
  ]
}
```

### Renewal
- **POST** `/api/renew/all`
    - Triggers renewal for all enabled services.
- **POST** `/api/renew/<service_name>`
    - Target specific service.
- **Response**:
```json
{
  "success": true,
  "message": "Renewed successfully"
}
```

### Upload
- **POST** `/api/upload`
- **Body**: `multipart/form-data` (`fullchain`, `privkey`)
- **Response**: `{"success": true}`

### Logs
- **GET** `/api/logs`
- **Response**: Returns last 100 lines of application log.

## 5. Handler Implementation Guide
To add a new service `MyService`:
1.  Create `dev/app/myservice_handler.py`.
2.  Inherit from `CertificateHandler`.
3.  Implement `renew(self, cert_path, key_path) -> bool`.
4.  Register in `HANDLERS` dict in `dev/app/cert_manager.py`.

## 6. Environment Setup
### Prerequisites
- Python 3.11+
- Docker & Docker Compose

### Local Dev
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r dev/app/requirements.txt
export CONFIG_PATH=dev/config.yaml

# Run with Gunicorn (Production Parity)
gunicorn -w 1 --threads 4 -b 0.0.0.0:5050 app.server:app
```

### Production Build
```bash
cd build_scripts
python3 build.py
# This creates a backup in code_backup/ and updates prod/
```
