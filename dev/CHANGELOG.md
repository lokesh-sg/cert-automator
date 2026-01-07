# Changelog

## [1.1.0] - 2026-01-06
### Security Hardening (Docker Scout Policy Compliance)
- **Non-Root User**: Container now runs as `appuser` (UID 1000) instead of root, enforcing least privilege permissions.
- **CVE Patching**: Dockerfile now includes `apt-get upgrade -y` to install latest Debian security patches.
- **Supply Chain**: Added SBOM (Software Bill of Materials) and Provenance attestations to Docker images.

## [1.1.0_build2] - 2026-01-06
### Fixed
- **UI Refresh**: Fixed "Renew All" button not automatically refreshing health/status badges upon completion.
- **Timestamps**: Corrected "NaNs ago" display issue by improving timezone parsing logic in `index.html`.
- **UI Bug**: Fixed individual "Renew" button failure caused by missing DOM element ID.

### Added
- **Live Timers**: "Last Renewal" timestamp now updates dynamically (ticks every 10s) without requiring a page refresh.

### Production Readiness
- **WSGI Server**: Replaced Flask development server with Gunicorn (Green Unicorn) for production-grade performance and stability.
- **Config**: Gunicorn configured with 4 threads and 1 worker (to maintain scheduler integrity).
- **Health Checks**: Added `curl` to the image to support Docker health check probes.
- **Documentation**: Updated READMEs with crucial `chown 1000:1000` volume permission instructions for non-root deployment.

## [1.0.0_build18] - 2026-01-06
### Added
- **Documentation**: Created `MAINTENANCE.md` covering Docker updates, data persistence, and config evolution.
- **Documentation**: Added "Updating CertAutomator" section to `RECOVERY_GUIDE.md`.

## [1.0.0_build17] - 2026-01-03
### Changed
- **Cleanup**: Removed temporary debug logging from `server.py` for production readiness.

## [1.0.0_build15] - 2026-01-03
### Fixed
- **UI Layout**: Fixed version display positioning on Login and Setup screens (centered below the card).
- **Template Variables**: Standardized version variable naming to `app_version` across all templates.

## [1.0.0_build14] - 2026-01-03
### Added
- **UI Consistency**: Expanded version display to login and setup pages.
- **Backend Refactoring**: Centralized version retrieval logic in `server.py`.

## [1.0.0_build13] - 2026-01-03
### Added
- **UI Enhancement**: Added version display to the app footer for easier build tracking.
- **Path Resolution**: Fixed backend pathing logic for `version.json` to support different working directories.

## [1.0.0_build12] - 2026-01-03
### Security Hardening (Deep Audit Build)
- **CSRF Protection**: Integrated `Flask-WTF` for global Cross-Site Request Forgery protection.
- **Session Security**: Enforced `HttpOnly`, `SameSite=Lax`, and `Secure` cookie flags.
- **Secret Management**: Implemented fail-fast check for `FLASK_SECRET` in production mode.
- **Authentication**: Secured `reset_system` with master password or Emergency Log Token.
- **API Hardening**: Moved `health_check` behind auth; restricted whitelist to core login flow.
- **Input Validation**: Integrated `secure_filename` and path traversal checks for file operations.
- **Frontend Refinement**: Implemented `secureFetch` wrapper for all state-changing API requests.

## [1.0.0_build9] - 2026-01-03

### Added
- **Deployment**: Integrated Docker health checks and `.dockerignore`.
- **Infrastructure**: Standardized production `docker-compose.yml` for volume persistence.

## [1.0.0_build8] - 2026-01-03

### Added
- **Resiliency**: Configurable backup directory via `BACKUP_DIR` for Docker persistence.
- **Docker**: Updated compose templates for production-ready state management.

## [1.0.0_build7] - 2026-01-03

### Fixed
- **TrueNAS Scale**: Resolved renewal failures by implementing asynchronous Job ID waiting and name-based resolution.
- **UI Refresh**: Added "System Locked" status and improved 401 Unauthorized handling for better user feedback.
- **Badge Logic**: Fixed "Certificates Missing" badge to correctly include the Default certificate pack.
- **Corruption Protection**: Added rolling timestamped backups (last 20) for `config.yaml`.
- **Infrastructure**: Hardened session security and updated WebSocket protocols.

## [1.0.0_build6] - 2026-01-03
### Added
- **Multi-Certificate**: UI for managing multiple certificate packs.
- **Renewal Tracking**: Persisting and displaying last renewal status.

## [1.0.0] - 2026-01-02

### Added
- **ClearPass Integration**: Full support for Aruba ClearPass certificate updates.
    - Cluster-aware updates (updates all nodes in cluster).
    - Support for multiple certificate usages (HTTPS, RADIUS, RadSec, etc.).
    - Legacy PFX support (RC2 encryption) for compatibility.
    - Automatic password generation (alphanumeric).
- **Portainer Auto-Detect**: SSH-based detection for both certificate and key paths (`--sslcert`, `--sslkey`).
- **Config Backup**: Automatic `config.yaml.bak` creation on every save.
- **Security**: Thread-safe temporary file registry for downloads using Flask `current_app`.

### Fixed
- **ClearPass Download**: Fixed 404/422 errors by correct URL formatting (`/clearpass.pfx`) and MIME type (`application/x-pkcs12`).
- **Portainer UI**: Fixed variable typo preventing key path from displaying after detection.
- **Config Corruption**: Resolved issue where config file could become corrupted/empty; added backup mechanism.

### Changed
- **API Security**: Whitelisted `/api/download` endpoint to allow ClearPass to fetch certificates without session cookies (relies on one-time token).
- **Backend Architecture**: Unified `ConfigManager` to handle encryption transparently.
