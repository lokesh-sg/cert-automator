# Changelog

All notable changes to the "Certificate Automation Tool" will be documented in this file.

## [1.1.0_build4] - 2026-01-06
### Fixed
- **ClearPass Renewal**: Fixed critical renewal failure (422/404) by adjusting security middleware to safely allow certificate downloads via one-time tokens.

## [1.1.0_build2] - 2026-01-06
### Fixed
- **UI Refresh**: Fixed "Renew All" button not automatically refreshing health/status badges upon completion.
- **Timestamps**: Corrected "NaNs ago" display issue by improving timezone parsing logic in `index.html`.
- **UI Bug**: Fixed individual "Renew" button failure caused by missing DOM element ID.

### Added
- **Live Timers**: "Last Renewal" timestamp now updates dynamically (ticks every 10s) without requiring a page refresh.

## [1.1.0] - 2026-01-06
### Security Hardening (Docker Scout Policy Compliance)
- **Non-Root User**: Container now runs as `appuser` (UID 1000) instead of root, enforcing least privilege permissions.
- **CVE Patching**: Dockerfile now includes `apt-get upgrade -y` to install latest Debian security patches.
- **Supply Chain**: Added SBOM (Software Bill of Materials) and Provenance attestations to Docker images.

### Production Readiness
- **WSGI Server**: Replaced Flask development server with Gunicorn (Green Unicorn) for production-grade performance and stability.
- **Config**: Gunicorn configured with 4 threads and 1 worker (to maintain scheduler integrity).
- **Health Checks**: Added `curl` to the image to support Docker health check probes.
- **Documentation**: Updated READMEs with crucial `chown 1000:1000` volume permission instructions for non-root deployment.

## [v1.0_build18] - 2026-01-06
### Added
- **Lifecycle Management**: Created `MAINTENANCE.md` covering Docker upgrade procedures, configuration persistence through volume mounts, and automatic backup policies.
- **Recovery Documentation**: Integrated update procedures into `RECOVERY_GUIDE.md` for better administrative visibility.

## [v1.0_build17] - 2026-01-03
### Changed
- **Cleanup**: Removed temporary debug logging and "TEST_VISIBLE" markers from `server.py` for cleaner production logs.

## [v1.0_build15] - 2026-01-03
### Fixed
- **UI Layout**: Fixed version display positioning on Login and Setup screens. Used `flex-direction: column` to center the version number directly below the authentication cards.
- **Template Variables**: Standardized version variable naming to `app_version` across index, login, and setup templates.

## [v1.0_build14] - 2026-01-03
### Added
- **UI Consistency**: Expanded build version display to the Login and Setup pages for consistent tracking across the entire application.
- **Backend Refactoring**: Centralized version retrieval logic in `server.py` using a dedicated `get_version()` helper with robust path resolution.

## [v1.0_build12] - 2026-01-03
### Security Hardening (Deep Sweep)
- **Global CSRF Protection**: All state-changing API calls (POST/DELETE) now require a valid CSRF token.
- **Session Hardening**: Cookies now use `HttpOnly`, `SameSite=Lax`, and `Secure` (where applicable) to prevent hijacking.
- **Secret Enforcement**: The system will now refuse to start in production if `FLASK_SECRET` is not set or using the default.
- **Emergency Recovery**: Added a log-based `EMERGENCY_RESET_TOKEN` to allow factory resets if the master password is lost.
- **API Lockdown**: Minimized the unauthenticated whitelist; whitelisted logs and health checks are now strictly authenticated.
- **Input Sanitization**: Integrated `secure_filename` for all file-related inputs to prevent path traversal.

## [v1.0_build11] - 2026-01-03
### Fixed
- **Authentication Recovery**: Restored system access by recovering corrupted `config.yaml` from timestamped backups.
- **Logging**: Reverted verbose debug logging to standard informational levels for production stability.

## [v1.0_build9] - 2026-01-03
### Added
- **Production Readiness**:
    - Added `.dockerignore` to streamline production image builds and prevent accidental leak of sensitive local files (venv, logs, backups).
    - Implemented a dedicated `/api/health` endpoint for Docker health monitoring.
    - Updated `docker-compose.yml` with production-grade settings: healthchecks, volume persistence for `auth.json`, and automatic container restarts.

## [v1.0_build8] - 2026-01-03
### Added
- **Production Resiliency**: Introduced `BACKUP_DIR` environment variable support for configurable, persistent configuration backups, optimized for Docker volume mounts.
- **Docker Orchestration**: Updated `docker-compose.yml` with dedicated volumes and environment mappings for persistent logs and backups.

## [v1.0_build7] - 2026-01-03
### Fixed
- **TrueNAS Integration Stability**:
    - Resolved "Please specify a valid certificate which exists in the system" error by handling asynchronous Job IDs and waiting for completion via `core.job_wait`.
    - Implemented **Name-Based ID Resolution** to ensure certificates are truly available in the system before activation, bypassing middlewared indexing lags.
    - Updated WebSocket URI to `/api/current` and ensured full JSON-RPC 2.0 compliance for modern TrueNAS Scale versions.
- **UI & UX**:
    - Added **"System Locked"** status badge to explicitly show when the vault is locked after a restart.
    - Improved API error handling to return `401 Unauthorized` for all `/api` routes, providing clear redirects to the Login page.
    - Fixed "Certificates Missing" badge to correctly check the Default certificate pack.
- **Reliability**:
    - Implemented timestamped rolling backups for `config.yaml`, retaining the last 20 versions.
    - Added defensive parsing for REST API Job results to prevent crashes.

### Changed
- **Code Cleanup**: Removed verbose debug logging and dead code from `truenas_handler.py` and `server.py` for production readiness.
- **Middleware**: Hardened `check_auth` to enforce session security across all backend API endpoints.

## [v1.0_build5] - 2026-01-03
### Added
- **Multi-Certificate Support**:
    - **Certificate Manager**: New UI to upload, list, inspect, and delete multiple certificate packs.
    - **Service Editor**: "Certificate Source" dropdown allows selecting specific packs per service.
    - **Backend**: API endpoints for managing packs (`/api/certificates/*`) and inspecting on-disk certs.
- **Renewal Status Tracking**:
    - **Backend Persistence**: Stores the result (Success/Failure) and timestamp of the last renewal attempt.
    - **Dashboard**: "Last Renewal" column displays status icons (✅/❌) and relative time (e.g., "5m ago").
- **UI Improvements**:
    - **Service Editor**: Fixed unresponsive buttons and dropdown bugs.
    - **Certificate Inspection**: "View Default Certificate" button now shows detailed chain info (Leaf/Inter/Root).

### Changed
- **Certificate Validation**: Added strict validation using `cryptography` library.
    - Ensures Private Key matches Certificate.
    - Validates X.509 format.
- **Auto-Chaining**: Backend automatically combines Certificate and Chain if uploaded separately.

## [v1.0_build4] - 2026-01-02
### Changed
- **Build System**: Switched backup strategy from ZIP archives to uncompressed folders (`code_backup/`) for easier reference.
- **Workflow**: Disabled auto-packaging. Builds are now triggered manually via `build.py`.
- **Network**: Changed default port from `5000` to `5050` to avoid conflicts with MacOS AirPlay Receiver.

## [v1.0_build3] - 2026-01-02
### Changed
- **Folder Structure**: Renamed `versions/` directory to `code_backup/`.
- **Sanitization**: Improved build script to exclude `__pycache__` and `.DS_Store` from production builds.

## [v1.0_build2] - 2026-01-02
### Added
- **Web GUI**: Launched Flask-based Dashboard.
    - Drag & Drop Certificate Upload.
    - Real-time Service Status.
    - Live Logs Console.
    - "Renew All" button.
- **Docker**: Updated `Dockerfile` to expose port 5000 and run `app.server`.

## [v1.0_build1] - 2026-01-02
### Added
- **Core**: Initial CLI implementation of `CertAutomator`.
- **Handlers**: Added support for:
    - Proxmox (API)
    - TrueNAS (API)
    - OPNSense (API)
    - Syncthing (SSH)
    - Wazuh (SSH)
    - Heimdall (SSH)
    - Aruba ClearPass (PFX Conversion)
- **Infrastructure**: Established `dev`/`prod` folder structure.
