# Wazuh Dashboard Integration

This guide describes how to configure CertAutomator to renew SSL certificates for the **Wazuh Dashboard**.

- **Type**: `wazuh`
- **Port**: 22 (SSH)
- **Method**: File Copy + Service Restart

## Prerequisites
1.  **SSH Access**: You need a user with `sudo` privileges on the Wazuh server.
2.  **Permissions**: The user must be able to write to `/etc/wazuh-dashboard/certs/` (or use sudo) and verify/restart the service.

## Configuration Defaults
CertAutomator uses the standard Wazuh Dashboard paths by default. You typically **do not** need to override these unless you have a custom installation.

-   **Certificate**: `/etc/wazuh-dashboard/certs/fullchain.pem`
-   **Private Key**: `/etc/wazuh-dashboard/certs/privkey.pem`
-   **Service Name**: `wazuh-dashboard`

## adding the Service
1.  **Host**: IP/Hostname of Wazuh Server.
2.  **Type**: `Wazuh`
3.  **User**: SSH Username (e.g. `root` or `admin` with sudo).
4.  **Password**: SSH Password.
5.  *(Optional)* **Cert Path**: Override if your cert is elsewhere.
6.  *(Optional)* **Key Path**: Override if your key is elsewhere.

## How it Works
1.  **Connect**: CertAutomator connects via SSH.
2.  **Upload**: It uploads the new `fullchain.pem` and `privkey.pem` to a temporary location (`/tmp/`).
3.  **Deploy**: It uses `sudo mv` to move them to `/etc/wazuh-dashboard/certs/`.
4.  **Permissions**:
    -   `chown wazuh-dashboard:wazuh-dashboard` (Files & Directory)
    -   `chmod 500` (Directory) / `chmod 440` (Files)
5.  **Config Check**: Automatically scans `/etc/wazuh-dashboard/opensearch_dashboards.yml` and updates SSL paths via regex if they don't match.
6.  **Restart**: It runs `sudo systemctl restart wazuh-dashboard`.
