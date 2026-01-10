# OpenMediaVault (OMV) Integration Guide

This guide describes how to configure **CertAutomator** to renew certificates for OpenMediaVault servers.

## Overview
Unlike other integrations (e.g., Proxmox, TrueNAS) which use an API, OpenMediaVault integration relies on **SSH** to surgically replace the underlying certificate files and reload the Nginx web server.

-   **Type**: `omv`
-   **Method**: SSH / SCP
-   **Port**: 22 (Standard SSH)

## Prerequisites
1.  **SSH Access**: You must have SSH access to your OMV server with a user capable of running `sudo`.
2.  **Existing Certificate**: You should have already configured **one** SSL certificate in the OMV Web UI ("System" > "Certificates" > "SSL") and assigned it to the General Settings ("System" > "Workbench").

## How It Works
CertAutomator uses an intelligent "Zero Config" approach:
1.  **Connects via SSH**: Uses the provided credentials (root or sudoer).
2.  **Auto-Deploys Helper**: Automatically uploads a safe helper script to `/tmp/omv_cert_helper.sh`.
3.  **Discovers UUID**: Finds the currently active SSL certificate from `config.xml` (or falls back to the most recent file).
4.  **Updates Database**: Executes the helper script to securely update the OMV configuration database (`omv-confdbadm`) and deploy changes (`omv-salt`).
5.  **Clean Up**: Removes temporary files.

## Configuration Steps
Add a new service in CertAutomator with the following details:

-   **Service Name**: (e.g., `My NAS`)
-   **Type**: `omv` (Select "OpenMediaVault" from dropdown)
-   **Host**: IP address or hostname of your OMV server.
-   **User**: SSH Username (e.g., `root` or a user with sudo privileges).
-   **Password**: SSH Password.
-   **UUID** (Optional): If auto-discovery fails, you can manually specify the certificate UUID here.

**No manual script installation is required.** CertAutomator handles everything automatically.

### Auto-Tagging & Verification
- **Comment Tagging**: CertAutomator automatically updates the `comment` field of the certificate in OMV with `CertAutomator Renewed: YYYY-MM-DD HH:MM:SS`. This gives you visible confirmation in the OMV UI.
- **Strict Verification**: After deployment, the system reads the actual certificate file from the OMV server's disk and compares its Serial Number with the local one to guarantee the update was successful.

### Note on Dashboard Status
OMV stores certificate metadata (expiration date) in its internal database. CertAutomator updates both the database record and the physical files. You may need to refresh the OMV dashboard to see the updated comment and expiration date. The web interface (`nginx`) typically reloads immediately.
