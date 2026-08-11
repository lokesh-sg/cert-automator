# Production & Recovery Guide - CertAutomator

This guide explains data architecture, password recovery via **Dual-Envelope Cryptography**, system backups, and migration procedures.

---

## Persistent Data Structure

In a standard Docker deployment (or dev setup), persistent state is maintained across these mapped host paths:

| Component | Path | Description |
| :--- | :--- | :--- |
| **Authentication** | `auth.json` | Stores username, `password_envelope`, and `recovery_envelope`. |
| **Vault Config** | `config.yaml` | AES-256 encrypted service configurations, SSH targets, and API tokens. |
| **Certificates** | `certs/` | Managed TLS certificates and encrypted private keys (`privkey.enc`). |
| **Backups** | `backups/` | Rolling historical backups of `config.yaml` (up to 20 historical copies). |

---

## Dual-Envelope Cryptography Overview

CertAutomator uses **Dual-Envelope Encryption** to ensure zero data loss:

1. **Master Vault Key (`MVK`)**: A random 256-bit key generated at initial setup. All vault data (`config.yaml`) and private SSL keys (`privkey.enc`) are encrypted using `MVK`.
2. **Password Envelope**: Encrypts `MVK` using a key derived from your Master Password (PBKDF2HMAC SHA-256 + Fernet AES-256).
3. **Recovery Envelope**: Encrypts `MVK` using a key derived from your **32-character Emergency Recovery Key**.

> [!NOTE]
> Because `MVK` is wrapped separately by both your Master Password and Emergency Recovery Key, **recovering your vault with the Emergency Recovery Key resets your password without erasing any configurations, targets, or private keys**.

---

## Recovery Scenarios

### Scenario 1: Reset Master Password Using Emergency Recovery Key (Zero Data Loss)
If you forget your Master Password but have your 32-character Emergency Recovery Key:

1. **Open Login Page**: Go to `http://<your-server>:5050/login`.
2. **Open Recovery Modal**: Click **RECOVER PASSWORD WITH KEY**.
3. **Enter Details**:
   - Paste your **32-character Emergency Recovery Key**.
   - Enter your **New Master Password** (and confirm it).
4. **Submit**: Click **Update Password & Unlock**.
5. **Outcome**: The system unwraps `MVK` using your recovery key, re-encrypts `MVK` into a new `password_envelope`, unlocks your vault, and logs you in. **All services, configurations, and SSL certificates remain 100% intact.**

---

### Scenario 2: Automatic Upgrade for Legacy Vaults
If you are upgrading from a legacy version of CertAutomator (single-password mode):

1. **Log In**: Enter your existing username and Master Password on `/login`.
2. **Automatic Migration**: The system transparently generates a 256-bit `MVK`, re-wraps your configuration, creates a 32-character Emergency Recovery Key, and updates `auth.json` to Dual-Envelope mode.
3. **Save Key**: A one-time security alert modal pops up on your dashboard presenting your **Emergency Recovery Key**. Copy and store this key securely in your password manager.

---

### Scenario 3: Restoring Configuration from Historical Backup
If your `config.yaml` becomes corrupted or accidentally modified:

1. **Stop the App / Container**:
   ```bash
   docker compose down
   ```
2. **Find Most Recent Backup**:
   ```bash
   ls -lh backups/
   ```
3. **Restore Backup File**:
   ```bash
   cp backups/config.YYYYMMDD-HHMMSS.yaml.bak config.yaml
   ```
4. **Restart Container**:
   ```bash
   docker compose up -d
   ```

---

### Scenario 4: Dev to Prod Migration
To migrate your configuration and certificates to a new host or production environment:

1. **Stop Source Instance**: Ensure all pending renewals finish cleanly.
2. **Transfer Persistent Artifacts**:
   - `auth.json`
   - `config.yaml`
   - `certs/` directory
3. **Permissions**: Set proper file ownership on the target server (`chown -R 1000:1000 app certs`).
4. **Launch Production Container**:
   ```bash
   docker compose up -d
   ```

---

## Critical Security Rules

- **Backup your Emergency Recovery Key**: Keep your 32-character Emergency Recovery Key in a safe password manager (e.g. Bitwarden, 1Password).
- **Keep Master Password & Key Safe**: If both the Master Password AND Emergency Recovery Key are lost, encrypted vault data cannot be recovered without a historical backup.
