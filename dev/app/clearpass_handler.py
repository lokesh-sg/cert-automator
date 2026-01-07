import subprocess
import os
import requests
import socket
import logging
import uuid
from .base_handler import CertificateHandler

class ArubaClearPassHandler(CertificateHandler):
    def renew(self, cert_path: str, key_path: str) -> bool:
        # 1. Config
        host = self.config.get('host')
        client_id = self.config.get('client_id')
        client_secret = self.config.get('client_secret')
        # Fix: config.get returns "" if key exists but empty. Use 'or' to force fallback.
        pfx_password = self.config.get('pfx_password') or self._generate_random_password()
        
        if not all([host, client_id, client_secret]):
            self.logger.error("Missing ClearPass config (host, client_id, client_secret)")
            return False

        # Ensure Scheme
        if "://" not in host:
            host = f"https://{host}"

        # 2. Generate PFX
        pfx_path = self._create_pfx(cert_path, key_path, pfx_password)
        if not pfx_path:
            return False
            
        try:
            # 3. Register for Download
            download_url = self._register_download(pfx_path)
            self.logger.info(f"Staged PFX for download at: {download_url}")
            
            # 4. Get Access Token
            token = self._get_access_token(host, client_id, client_secret)
            if not token:
                return False
                
            # 5. Import Certificate
            if self._import_certificate(host, token, download_url, pfx_password):
                self.logger.info("ClearPass Import Successful")
                return True
            else:
                return False
                
        finally:
            # 6. Cleanup
            if os.path.exists(pfx_path):
                os.remove(pfx_path)

    def _generate_random_password(self):
        import secrets
        import string
        # Use simpler alphanumeric password to avoid shell/parsing issues
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for i in range(16))

    def _create_pfx(self, cert_path, key_path, pfx_password):
        try:
            timestamp = uuid.uuid4().hex[:8]
            output_dir = os.path.dirname(cert_path)
            pfx_path = os.path.join(output_dir, f"clearpass_{timestamp}.pfx")
            
            cmd = [
                'openssl', 'pkcs12', '-export',
                '-out', pfx_path,
                '-inkey', key_path,
                '-in', cert_path,
                '-passout', f'pass:{pfx_password}',
                '-legacy' # Ensure compatibility with older ClearPass/Java versions
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return pfx_path
        except Exception as e:
            self.logger.error(f"PFX Creation Failed: {e}")
            return None

    def _register_download(self, file_path):
        """Registers the file in the server's temp registry and returns a URL."""
        try:
            from flask import current_app
            
            # Use current_app (thread-safe, context-aware)
            if not hasattr(current_app, 'temp_registry'):
                current_app.temp_registry = {}
            
            import time
            token = str(uuid.uuid4())
            current_app.temp_registry[token] = {
                'path': file_path,
                'expires': time.time() + 600 # 10 mins expiry
            }
            
            # Determine callback IP
            # Prefer config 'callback_host' -> local IP
            cb_host = self.config.get('callback_host')
            if not cb_host:
                cb_host = self._get_local_ip()
                
            port = 5050 # Hardcoded or config? default to 5050
            
            port = 5050 # Hardcoded or config? default to 5050
            
            # Append pseudo-filename for strict validators
            return f"http://{cb_host}:{port}/api/download/{token}/clearpass.pfx"
        except ImportError:
            self.logger.error("Could not import server app context")
            return None

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def _get_access_token(self, host, client_id, client_secret):
        url = f"{host}/api/oauth"
        payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret
        }
        try:
            r = requests.post(url, json=payload, verify=False, timeout=10)
            if r.status_code == 200:
                return r.json().get('access_token')
            self.logger.error(f"Auth Failed: {r.text}")
            return None
        except Exception as e:
            self.logger.error(f"Auth Exception: {e}")
            return None

    def _import_certificate(self, host, token, download_url, pfx_password):
        # The correct flow (based on cppm-certsync) is:
        # 1. Get Cluster Server UUIDs
        # 2. PUT to /api/server-cert/name/{uuid}/{usage}
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        # 1. Get Server UUIDs
        # Endpoint: /api/cluster/server
        server_uuids = {} 
        try:
            r = requests.get(f"{host}/api/cluster/server", headers=headers, verify=False, timeout=10)
            if r.status_code == 200:
                data = r.json()
                items = data.get('_embedded', {}).get('items', [])
                for item in items:
                    name = item.get('name')
                    uuid_val = item.get('server_uuid')
                    if name and uuid_val:
                        server_uuids[name] = uuid_val
            else:
                self.logger.error(f"Failed to get cluster servers: {r.text}")
                return False
        except Exception as e:
            self.logger.error(f"Cluster Server Lookup Failed: {e}")
            return False
            
        if not server_uuids:
            self.logger.error("No servers found in ClearPass cluster.")
            return False
            
        # 2. Update Cert for EACH server (or just the target one? Usually all in cluster)
        # For now, let's try to update ALL servers in simple loop, or just the one matching 'host' if we can resolve it?
        # Ideally, we update all because certificates are usually cluster-wide VIPs.
        
        usage = self.config.get('cert_usage', 'https') # https-rsa, https-ecc, radius, radsec
        
        success_count = 0
        for name, uuid_val in server_uuids.items():
            # Construct Endpoint
            # /api/server-cert/name/{uuid}/{usage}
            # Note: Usage might be 'HTTPS' (case sensitive?) -> script says "HTTPS" etc.
            # let's map common usages
            usage_map = {
                'https': 'HTTPS', # Legacy
                'https(rsa)': 'HTTPS(RSA)',
                'https(ecc)': 'HTTPS(ECC)',
                'radius': 'RADIUS',
                'radsec': 'RadSec',
                'database': 'Database'
            }
            # Fallback to usage provided if not in map (e.g. if user matches exact case)
            mapped_usage = usage_map.get(usage.lower(), usage)
            
            url = f"{host}/api/server-cert/name/{uuid_val}/{mapped_usage}"
            
            payload = {
                "pkcs12_file_url": download_url,
                "pkcs12_passphrase": pfx_password
            }
            
            self.logger.info(f"Updating {name} ({uuid_val}) usage {mapped_usage}...")
            
            try:
                # Script uses PUT
                r = requests.put(url, json=payload, headers=headers, verify=False, timeout=30)
                if r.status_code == 200:
                    self.logger.info(f"Success for {name}")
                    success_count += 1
                else:
                    self.logger.error(f"Failed for {name} [{r.status_code}]: {r.text}")
            except Exception as e:
                self.logger.error(f"Exception updating {name}: {e}")
                
        return success_count > 0
