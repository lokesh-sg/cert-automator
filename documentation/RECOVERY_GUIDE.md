# Production Recovery Guide - CertAutomator

This guide explains how to recover your system in case of configuration corruption, lost passwords, or migration issues.

## 📁 Data Locations
In a standard Docker deployment, your persistent data is located in these mapped volumes on your host:

- **Config**: `./app/config.yaml`
- **Auth**: `./app/auth.json`
- **Automatic Backups**: `./backup/config/`
- **Certificates**: `./certs/`

---

## 🛠️ Scenario 1: Configuration Corruption
**Symptoms:** "Invalid Password" (when you are sure it's correct), "Decryption Failed", or the app appears completely empty.

1.  **Stop the Container**:
    ```bash
    docker compose down
    ```
2.  **Verify the Corruption**: Check the file size of `./app/config.yaml`. If it is unusually small (e.g., < 200 bytes), it has likely been reset.
3.  **Find a Healthy Backup**: List your backups to find the most recent one with a realistic file size:
    ```bash
    ls -lh ./backup/config/
    ```
4.  **Restore the Backup**:
    ```bash
    cp ./backup/config/config.YYYYMMDD-HHMMSS.yaml.bak ./app/config.yaml
    ```
5.  **Restart the App**:
    ```bash
    docker compose up -d
    ```

---

## 🛡️ Scenario 2: Forgotten Master Password
**Symptoms:** You cannot log in and do not have a working backup of the configuration.

CertAutomator includes an **Emergency Reset Token** generated on every startup for your protection.

1.  **Get the Token**: Check your Docker logs:
    ```bash
    docker compose logs | grep "EMERGENCY RESET TOKEN"
    ```
2.  **Reset via UI**:
    - Go to the Login page.
    - Click "Forgot Password" or "Reset System".
    - Enter the 32-character token from your logs.
3.  **Result**: The system will back up your current (inaccessible) config and return to the **Setup Screen**, allowing you to choose a new username and password.

---

## 🚀 Scenario 3: Migrating from Dev to Prod
To move your setup from a development machine to a production server:

1.  **Stop the Dev App**.
2.  **Transfer these files/folders** to your server:
    - `dev/auth.json`
    - `dev/config.yaml`
    - `dev/certs/` (The whole folder)
3.  **Place them** in your production mapped directories (e.g., `./app/` and `./certs/`).
4.  **Fix Permissions**: Run `chown -R 1000:1000 ./app ./certs`.
5.  **Ensure `FLASK_SECRET`** is set in your production `docker-compose.yml`.

---

## 🔄 Scenario 4: Updating CertAutomator
Updating to a newer version is designed to be seamless.

1.  **Backup**: Ensure you have a recent backup of `./app/config.yaml`.
2.  **Pull & Restart**:
    ```bash
    docker compose down
    ```
    Replace your source files or pull the latest image, then:
    ```bash
    docker compose up -d
    ```
3.  **Verify**: Your settings and services should remain intact.
    > [!TIP]
    > For more detailed maintenance procedures, see the [Maintenance Guide](file:///Volumes/Downloads/cert-automate/documentation/MAINTENANCE.md).

---

## ⚠️ Critical Warnings
- **The Master Password is the Encryption Key**: If you lose your password and don't have the Emergency Token, your `config.yaml` can NEVER be decrypted.
- **Backup your Backups**: Occasionally download the `./backup/` folder to a separate machine for ultimate safety.
