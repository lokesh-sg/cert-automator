# v1.1.0 Build 20260107.15 🚀

This release brings significant improvements to **Portainer** and **TrueNAS** integrations, focusing on smarter automation, improved security, and more robust certificate activation.

## 🌟 What's New

### 🤖 Smart Automation (Portainer)
- **Dynamic Path Detection**: The "Auto Detect" feature now intelligently probes the Portainer container to identify active certificate filenames (e.g., `cert.pem` vs `portainer.crt`). 
- **Simplified Setup**: New Portainer services now correctly map paths automatically without manual intervention.

### 🛠️ Critical Bug Fixes
- **Portainer SSH Permissions**: Fixed "Permission denied" errors during renewal. The handler now utilizes a robust `sudo` fallback mechanism for secure file transfers.
- **TrueNAS GUI Activation**: Resolved issues where certificates were uploaded but not served by the GUI. Added an explicit **UI Restart** (Nginx reload) to force the GUI to pick up new certificates immediately.
- **Improved Verification**: Activation checks now cross-verify both Certificate IDs and Names for both WebSocket and REST pathways.

### 🧹 Maintenance & Security
- **Unified Handlers**: Standardized SSH-based handlers (Portainer, Syncthing) for better stability using the `BaseSSHHandler` logic.
- **Sanitized Releases**: Verified that the production and public source code are purged of sensitive logs and temporary configurations.
- **Multi-Arch Support**: Multi-architecture images (AMD64/ARM64) are now live on Docker Hub.

## 📦 How to Update
Pull the latest image from Docker Hub:
```bash
docker pull lokeshsg/cert-automator:latest
```

---
*Built with ❤️ for privacy and automation.*
