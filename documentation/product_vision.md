# Product Vision - Certificate Automation Tool

**Version**: 1.0  
**Date**: 2026-01-02  
**Author**: Product Lifecycle Management Team

## 1. Executive Summary
The **Certificate Automation Tool** is a centralized, on-premise solution designed to eliminate the manual toil and risk associated with SSL certificate renewals across various heterogeneous environments. By providing a single "pane of glass" for certificate injection, we reduce downtime, improve security posture, and standardize certificate management.

## 2. Problem Statement
In the current manual workflow, the administrator must:
1.  Obtain new certificates (PEM/KEY).
2.  Log in to 8+ different services (Proxmox, TrueNAS, OPNSense, etc.), each with unique UIs and upload procedures.
3.  Manually convert formats (e.g., PEM to PFX) for legacy systems.
4.  Restart services manually.
*Risk*: Expired certificates lead to service outages and security warnings. Manual file manipulation increases the risk of key leakage or misconfiguration.

## 3. Product Goals
1.  **Centralization**: One upload point for all certificates.
2.  **Automation**: One-click renewal for all configured services.
3.  **Extensibility**: Modular architecture to easily add new services in the future.
4.  **Visibility**: Real-time status dashboard and logging.

## 4. Key Features (v1.0)
- **Web Dashboard**: Modern, dark-mode GUI for ease of use.
- **Broad Integration Support**:
    - **API Integration**: Proxmox, TrueNAS, OPNSense.
    - **SSH/SCP Integration**: Syncthing, Wazuh, Heimdall.
    - **Format Conversion**: Aruba ClearPass (PEM -> PFX).
- **Dockerized Deployment**: Portable, self-contained run-time.
- **Deployment Safety**: "Code Backup" strategy ensures previous versions are archived before new deployments.

## 5. Roadmap
| Version | Focus | Key Features |
| :--- | :--- | :--- |
| **v1.0** | **MVP & Stability** | web GUI, 7+ core handlers, basic logging. |
| **v1.1** | **Scheduler** | Cron-based auto-renewal (no user interaction). |
| **v1.2** | **Notifications** | Email/Slack alerts on success/failure. |
| **v2.0** | **Enterprise** | Multi-user RBAC, Audit trails, Vault integration. |

## 6. Versioning Strategy
- **Format**: `vMajor.Minor_build<ID>`
- **Cadence**:
    - **Build Number**: Increments on every packaging event.
    - **Minor Version**: Increments on new feature sets.
    - **Major Version**: Increments on breaking changes or architectural rewrites.
