## [v1.1.3.20260127.14] - 2026-01-27
### UI Modernization ("Cyber Vault" Overhaul)
- **Login Screen**: Completely rewrote the login experience with a "Cyber Glass" aesthetic, featuring a pulsing animated logo, neon Cyan borders, and a "System Locked" status indicator.
- **Branding**: Deployed a new High-Visibility App Icon (54px) designed for maximum contrast in dark mode, replacing the legacy SVG.
- **Typography**: Standardized on `Inter` for UI elements and `JetBrains Mono` for all technical data inputs and logs.

### UX Improvements
- **Dynamic Certificate Modals**: The Certificate Details modal now intelligently changes theme based on status:
    - **Green Glow**: Valid certificate & healthy chain.
    - **Red Glow**: Expired certificate, broken chain, or key mismatch.
- **Sidebar**: Enhanced visual hierarchy with larger branding and refined navigation spacing.

### Security & Stability
- **Dependency Hardening**: Pinned all core dependencies (`Flask`, `Cryptography`, `Paramiko`, `Requests`) to their latest secure versions in `requirements.txt` to mitigate known CVEs.

## [v1.1.2.20260127.13] - 2026-01-27
### Added
- **Wazuh Dashboard Integration**: Full automated support for Wazuh Dashboard certificate renewals.
    - **Robust Upload**: Uses safe `sudo` fallback (upload to `/tmp`, move to `/etc/wazuh-dashboard/certs/`) to handle strict directory permissions.
    - **Permission Management**: Automatically applies correct ownership (`wazuh-dashboard:wazuh-dashboard`) and permissions (`0500`/`0440`) to certificates and directories.
    - **Config Auto-Correction**: Intelligent regex-based scanner that reads `/etc/wazuh-dashboard/opensearch_dashboards.yml` and updates `server.ssl.key` / `server.ssl.certificate` paths if they mismatch, preserving all other configuration.

## [v1.1.2.20260109.12] - 2026-01-09
### Added
- **OpenMediaVault Native Integration**: Introduced a fully automated, zero-configuration handler for OMV.
    - **Zero-Touch**: No longer requires manual script installation. The handler auto-deploys a secure helper script via SSH.
    - **Auto-Tagging**: Certificates are now tagged in the OMV database with "CertAutomator Renewed: [Timestamp]" for easy tracking.
    - **"Split Brain" Protection**: Automatically detects and resolves scenarios where OMV's database and the actual Nginx files become out of sync.
    - **Verification**: Strict post-renewal verification reads the remote file back to ensure the serial number matches the new certificate.

## [v1.1.1.20260109.11] - 2026-01-09
### Security
- **Encryption-at-Rest**: Private keys are now stored using AES-256 encryption (`privkey.enc`) instead of plain text (`privkey.pem`). Keys are decrypted only in memory during renewal or inspection.
- **Strict Fallback**: If encryption fails, keys fall back to `0600` permissions (Owner Read/Write only).

### Fixed
- **Certificate Inspector**: Fixed an issue where the "Magnifying Glass" tool failed to view certificates due to the missing `privkey.pem` file. It now transparently decrypts and inspects the key.

## [v1.1.0.20260109.09] - 2026-01-09
- **Core Update (Smart Path Resolution)**: Implemented "Smart Path Detection" logic which automatically prioritizes Docker Volume mounts (`/certs`, `/backup`) if present, even if environment variables are missing. This solves path mismatch issues between local dev (relative `certs/`) and production Docker (absolute `/certs`).
- **Documentation**: Updated `technical_specs.md` and `README.md` to document the new path resolution hierarchy.

## [v1.1.0.20260109.08] - 2026-01-09
- **Bug Fix (ClearPass)**: Fixed a logic error in multi-node updates where the file download token was consumed by the first node (Publisher), causing subsequent Subscribers to fail with 422 errors. The system now generates a unique, fresh download URL for each node in the cluster.

## [v1.1.0.20260109.07] - 2026-01-09
- **Bug Fix (ClearPass)**: Fixed `Invalid URL` error by automatically sanitizing host inputs. The system now prepends `https://` to IPs/Hostnames if the scheme is missing.
- **Infrastructure**: Normalized global directory paths (`CERT_DIR`, `LOG_DIR`, `BACKUP_DIR`) to enforce absolute path resolution. This fixes path mismatches in certain Docker Compose volume configurations.
- **Logging**: Application now explicitly respects the `LOG_FILE` environment variable.

## [v1.1.0.20260109.06] - 2026-01-09
- **Release Fix**: Re-build of v1.1.0.20260109.05 to ensure Docker Hub registry propagation. Contains the fix for fresh install crashes.

## [v1.1.0.20260109.05] - 2026-01-09
- **Bug Fix**: Resolved a critical crash on fresh installations where `auth.json` or `config.yaml` were empty/invalid (e.g. created via `touch`). The system now correctly identifies this state as "Not Configured" and redirects to the Setup page.

## [v1.1.0.20260109.04] - 2026-01-09
- **Feature (ClearPass)**: Added Multi-Node Support. Users can now specify "Additional Nodes" (IPs/Hosts) in the service configuration. The system will iterate through all configured nodes during certificate renewal to ensure cluster-wide updates.
- **UI**: Added "Additional Nodes" input field to the ClearPass service editor.

## [v1.1.0.20260109.03] - 2026-01-09
- **Bug Fix**: Fixed Startup Health Check not updating the UI. The scheduler now waits for the system to unlock (user login) before running the initial certificate check.

## [v1.1.0.20260109.02] - 2026-01-09
- **Optimization**: Implemented Log Rotation for `cert_automate.log` (Max 10MB, 5 backups) to prevent disk usage issues.

## [v1.1.0.20260109.01] - 2026-01-09
- **Bug Fix**: Fixed application logging path. Logs are now correctly written to `/app/logs/` (mounted volume) instead of the container root.
- **Security**: Upgraded Docker base image to `python:3.11-slim-bookworm` (Debian 12) to resolve high-severity CVEs.

## [v1.1.0.20260107.16] - 2026-01-07
- **Feature (Portainer)**: Dynamic Path Detection. "Auto Detect" now inspects the container filesystem to identify active certificate filenames (`cert.pem`, `portainer.crt`, etc.).
- **Bug Fix (Portainer)**: Resolved SSH "Permission denied" errors using a robust sudo fallback mechanism (via `/tmp`).
- **Bug Fix (TrueNAS)**: Fixed GUI activation failure by adding an explicit UI restart (Nginx reload) after certificate updates.
- **Improvement (TrueNAS)**: Enhanced activation verification to cross-check both certificate ID and Name.
- **Cleanup**: Refactored `PortainerHandler` and `SyncthingHandler` for better consistency using `BaseSSHHandler`.
- **UI**: Added help context and improved path pre-filling for SSH-based services.

## [v1.1.0 Build 11] (Emergency Fix) - 2026-01-07
- **Critical Fix**: Restored missing `system.general.update` calls in TrueNAS handler (regression from Build 10 plan).
- **Improvement**: Added robust handling for "Connection Drop" during TrueNAS Nginx reloads. The handler now treats a connection loss immediately after activation as a tentative success.
- **Improvement**: Added post-activation sleep and best-effort re-verification for TrueNAS.
- **Improvement**: Enhanced Portainer restart logging with warnings for unstable ID-based commands.
- **Bug Fix**: Improved TrueNAS activation reliability. Added a 10-second wait after certificate activation to ensure Nginx reloads correctly, followed by a verification check.
- **Bug Fix**: Enhanced Portainer renewal with strict SSH upload verification. The handler now verifies that certificate and key files were successfully transferred before attempting a restart.
- **Improvement**: Added detailed logging for restart command results in the Portainer handler.

## v1.1.0 Build 7
- **Improvement**: Standardized Development Environment directory structure to match Production logic. Use `./run_dev.sh` to start the dev server.
- **Cleanup**: Removed redundant `input_certificates` directory. Certificates are now unified in `certs/` (Project Root).
- **Fix**: Resolved `auth.json` and `config.yaml` path resolution issues in Dev mode.

## v1.1.0 Build 6
- **Bug Fix**: Fixed an issue where selecting a custom Certificate Pack in the service editor was ignored during renewal (Backend expected `cert_pack`, Frontend sent `cert_pack_id`).
- **Improvement**: Added debug logging to confirm which Certificate Pack is being used during renewal.

## v1.1.0 Build 5
- **Hotfix (ClearPass)**: Added `callback_host` configuration field to Service Editor. This allows manual override of the callback IP, fixing `422 Unprocessable Entity` errors when the container's internal IP is not reachable from the ClearPass server.
- **Verification**: Verified end-to-end flow of configuration persistence.

## [1.1.0_build4] - 2026-01-06
### Fixed
- **ClearPass Renewal**: Resolved `422 Unprocessable Entity` and `404 Not Found` errors.
    - Reverted to URL-based callback method for reliability.
    - Whitelisted `/api/download` endpoint in global security middleware to prevent `401 Unauthorized`.
    - Added mandatory expiry timestamp to temporary download tokens to satisfy new security constraints.

## [1.1.0] - 2026-01-06
### Security Hardening (Docker Scout Policy Compliance)
- **Non-Root User**: Container now runs as `appuser` (UID 1000) instead of root, enforcing least privilege permissions.
- **CVE Patching**: Dockerfile now includes `apt-get upgrade -y` to install latest Debian security patches.
- **Supply Chain**: Added SBOM (Software Bill of Materials) and Provenance attestations to Docker images.

## [v1.1.0 Build 13] - 2026-01-07
- **Feature**: Dynamic Portainer Path Detection. "Auto Detect" now inspects the container filesystem to identify the correct certificate filenames (`cert.pem`, `portainer.crt`, etc.).
- **Improved**: Cleaned up `PortainerHandler.renew` to use configured paths instead of hardcoded overrides.

## [v1.1.0 Build 12] - 2026-01-07
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
