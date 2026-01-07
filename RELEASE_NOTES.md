# Release v1.1.0 Build 4 🚀

> [!IMPORTANT]
> This release includes critical security patches and functional fixes. Immediate upgrade is recommended.

## 🌟 Major Updates

### 🐛 Critical Fix: ClearPass Renewal
We have resolved the `422 Unprocessable Entity` and `404 Not Found` errors affecting Aruba ClearPass integrations.
- **Fixed**: Reverted to the reliable URL-based callback flow.
- **Fixed**: Whitelisted `/api/download` in the global security middleware to prevent `401 Unauthorized` errors.
- **Secure**: Implemented a mandatory **10-minute expiry** on temporary download tokens.

### 🛡️ Security Hardening (Docker Scout Policy)
- **⚡ Non-Root Execution**: container now runs as `appuser` (UID 1000) by default.
- **📦 Supply Chain**: Added **SBOM** and **Provenance** attestations (SLSA Compliance).
- **🔒 CVE Patching**: Base image now auto-upgrades all system packages during build.

### ⚡ Production Readiness
- **Server**: Replaced Flask development server with **Gunicorn** (4 threads) for production stability.
- **Timestamps**: "Last Renewal" and "Expires In" timers now update live in the UI.

---

## 🚀 Deployment

### Pull from Docker Hub
```bash
docker pull lokeshsg/cert-automator:v1.1.0
```

### 📦 Verify Attestations
```bash
docker scout cves lokeshsg/cert-automator:v1.1.0
```
