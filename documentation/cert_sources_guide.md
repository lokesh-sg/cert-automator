# User Guide: Certificate Sources (v1.2.0)

CertAutomator 1.2.0 introduces automated certificate sourcing. Instead of manually uploading certificates, the system can now fetch them from **ACME Providers (Let's Encrypt)** or pull them from an **Nginx Proxy Manager (NPM)** instance.

## 1. Native ACME (Let's Encrypt / ZeroSSL)
The ACME source allows the system to automatically request and renew certificates using the DNS-01 challenge.

### Prerequisites
- A **Cloudflare** account managing your domain.
- A Cloudflare **API Token** with `Zone:DNS:Edit` and `Zone:Zone:Read` permissions.

### Setup Steps
1. Navigate to **Sources** in the Dashboard.
2. Select **Add ACME Source**.
3. **Email**: Provide the email for ACME account registration (Let's Encrypt notifications).
4. **Provider**: Choose `cloudflare`.
5. **Config**: Provide your `api_token`.
6. **Domains**: Enter a comma-separated list of domains (e.g., `*.example.com, example.com`).
7. **Production vs Staging**: Toggle based on whether you want live certificates or test ones.

---

## 2. Nginx Proxy Manager (NPM) Integration
The NPM source "pulls" certificates from an existing Nginx Proxy Manager setup. This is ideal if you already have NPM managing your SSLs and want to distribute them to other services (like TrueNAS or Proxmox) automatically.

### Setup Steps
1. Navigate to **Sources** -> **Add NPM Source**.
2. **Path**: Point to your NPM data directory (e.g., `/mnt/data/nginx-proxy-manager`).
3. **Database**: If using SQLite, ensure the path to `database.sqlite` is reachable.
4. **Certificate Selection**: You can filter by domain name to pull specific certificates.

### How it Works (Pulse Check)
CertAutomator will periodically "pulse" the NPM source. It checks the serial number of the certificate in NPM against the one it has in its local vault. 
- **No Change**: No action is taken. Upstream services are **not** restarted.
- **New Certificate Detected**: CertAutomator pulls the new files, encrypts them, and triggers a renewal for all services linked to that certificate pack.

---

## 3. Linking Sources to Services
Once a source is configured, it creates a **Certificate Pack** (prefixed with `src-`).
1. Go to **Services**.
2. Edit a service (e.g., your Proxmox node).
3. In the **Certificate Pack** dropdown, select the new source (e.g., `src-cloudflare-live`).
4. Save.

Now, whenever the ACME source renews or the NPM source pulls a new cert, the service will be updated automatically.
