# Maintenance & Lifecycle Guide

This document outlines how to manage, update, and maintain CertAutomator in a production environment.

## Docker Update Procedure

CertAutomator is designed to be easily updated without losing your configuration.

1.  **Stop the App**:
    ```bash
    docker compose down
    ```
2.  **Pull the Latest Image** (If using a registry):
    ```bash
    docker compose pull
    ```
    *If building from source, simply replace the `app/` files and rebuild:*
    ```bash
    docker compose up -d --build
    ```
3.  **Start the App**:
    ```bash
    docker compose up -d
    ```

---

## Data Persistence & Permissions

All critical data is stored in **Docker Volumes** on your host machine.

> [!IMPORTANT]
> **UID 1000 Requirement**: The container runs as a secure non-root user (`appuser`, UID 1000). Ensure your host volumes are owned by this user:
> `chown -R 1000:1000 ./app ./certs ./backup`

| File/Folder | Purpose | Host Location (Default) |
| :--- | :--- | :--- |
| `config.yaml` | Encrypted service settings | `./app/config.yaml` |
| `auth.json` | Admin user database | `./app/auth.json` |
| `certs/` | Downloaded certificates | `./certs/` |
| `backup/` | Automatic config backups | `./backup/` |

---

## Configuration Backups

CertAutomator performs **automatic rolling backups** of your `config.yaml` every time you save a change.

- **Retention**: The app keeps the last **20 backups** in `./backup/config/`.
- **Strategy**: Before applying any internal schema changes (in future updates), the app always ensures the current config is backed up first.
- **Manual Backup**: It is highly recommended to occasionally copy the entire `./backup/` folder to a separate machine/cloud storage.

---

## Schema Evolution & Compatibility

Future updates to CertAutomator may introduce new features or configuration settings.

- **Forward Compatibility**: New versions of the app are programmed to handle missing optional settings from older `config.yaml` files by applying safe defaults.
- **Migration**: If a critical structural change is needed, the app will automatically migrate your `config.yaml` on the first startup of the new version. Your original file will be backed up as `config.pre-migration.yaml.bak` for safety.

---

## Portable Deployment (Sharing)

If you need to deploy CertAutomator on a new server or share it with others:

1.  **Generate the Package**:
    - Go to the `dist/` folder in the source code.
    - Run `./package_for_sharing.sh`. This creates `cert-automator-v1.tar`.
2.  **Transport**: Transfer `cert-automator-v1.tar` and `docker-compose.yml` to the target server.
3.  **Import & Run**:
    - On the new server, run: `docker load < cert-automator-v1.tar`
    - Start the container: `docker compose up -d`

---

## Log Maintenance

Logs are stored in `./app/logs/cert_automate.log`.
- To view logs: `docker compose logs -f`
- To clear logs: `truncate -s 0 ./app/logs/cert_automate.log` (No restart required).
