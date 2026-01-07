import requests
import json
import base64
import time
from .base_handler import CertificateHandler
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OPNSenseHandler(CertificateHandler):
    def renew(self, cert_path: str, key_path: str) -> bool:
        host = self.config.get('host')
        api_key = self.config.get('api_key')
        api_secret = self.config.get('api_secret')
        
        if not all([host, api_key, api_secret]):
            self.logger.error("Missing required config for OPNSense (host, api_key, api_secret)")
            return False

        try:
            with open(cert_path, 'r') as f:
                cert_content = f.read()
            with open(key_path, 'r') as f:
                key_content = f.read()
        except Exception as e:
            self.logger.error(f"Failed to read certificate files: {e}")
            return False

        base_url = f"https://{host}/api"
        auth = (api_key, api_secret)

        # 1. Add Certificate
        self.logger.info(f"OPNsense: Uploading certificate to {host}...")
        
        # Endpoint: /api/trust/cert/add (MVC)
        add_url = f"{base_url}/trust/cert/add" 
        
        # Payload must be wrapped in 'cert' (based on introspection of existing certs)
        # Fields: descr, crt, prv
        # ACTION: import (required to use the provided content)
        # CONTENT: Trying Raw PEM (since Base64 failed with 500) and extracting properties.
        
        # Helper to extract the first PEM block only (Leaf cert)
        def get_first_pem_block(content, marker):
            start = content.find(f"-----BEGIN {marker}-----")
            if start == -1: return content # Fallback
            end = content.find(f"-----END {marker}-----", start)
            if end == -1: return content
            return content[start:end+len(f"-----END {marker}-----")]

        lean_cert = get_first_pem_block(cert_content, "CERTIFICATE")
        lean_key = get_first_pem_block(key_content, "PRIVATE KEY")

        # TRY: Raw PEM in crt_payload (standard JSON string)
        # Previous Base64 attempt failed "Invalid X509", maybe it expects raw string.
        data = {
            "cert": {
                "action": "import",
                "crt_payload": lean_cert,
                "prv_payload": lean_key,
                "descr": f"AutoRenew-{cert_path[-10:]}" 
            }
        }

        try:
            # DEBUG: Log payload structure (truncated keys)
            debug_data = json.loads(json.dumps(data))
            if 'cert' in debug_data:
                debug_data['cert']['crt'] = '...pem data...'
                debug_data['cert']['prv'] = '...pem data...'
            self.logger.info(f"OPNsense Req: {json.dumps(debug_data)}")

            resp = requests.post(add_url, json=data, auth=auth, verify=False)
            
            self.logger.info(f"OPNsense Resp Status: {resp.status_code}")
            
            if resp.status_code == 200:
                result = resp.json()
                self.logger.info(f"OPNsense Resp Body: {json.dumps(result)}")
                
                if result.get('result') == 'saved':
                     new_uuid = result.get('uuid')
                     self.logger.info(f"Certificate imported successfully. UUID: {new_uuid}")
                     self.logger.warning("IMPORTANT: OPNsense API does not support automatic WebGUI certificate activation.")
                     
                     # Check for expired certificates
                     expired_certs = self._get_expired_certs()
                     expired_count = len(expired_certs)
                     
                     msg = "Certificate imported. Manual Activation Required in System > Settings > Administration."
                     if expired_count > 0:
                         msg += f" Found {expired_count} expired certificates."

                     return {
                         "success": True,
                         "message": msg,
                         "manual_activation": True,
                         "uuid": new_uuid,
                         "expired_count": expired_count
                     }
                else:
                     self.logger.error(f"OPNsense API Error (Add Cert): {result}")
                     return {"success": False, "message": f"OPNsense Error: {result}"}
            else:
                 self.logger.error(f"Failed to add certificate. Status: {resp.status_code}, Body: {resp.text}")
                 return {"success": False, "message": f"HTTP Error {resp.status_code}"}
        except Exception as e:
            self.logger.exception(f"Exception uploading to OPNSense: {e}")
            return {"success": False, "message": str(e)}

    def cleanup_expired(self) -> dict:
        """Deletes expired AutoRenew content."""
        host = self.config.get('host')
        if not host: return {"success": False, "message": "No host config"}
        
        expired_certs = self._get_expired_certs()
        if not expired_certs:
            return {"success": True, "message": "No expired certificates found", "count": 0}
            
        base_url = f"https://{host}/api"
        # Re-init auth? Handler calls are stateless but we can reuse config.
        # But `renew` sets up auth local variable. I need a helper for auth or just recreate it.
        api_key = self.config.get('api_key')
        api_secret = self.config.get('api_secret')
        auth = (api_key, api_secret)
        
        deleted_count = 0
        errors = []
        
        for cert in expired_certs:
            uuid = cert['uuid']
            descr = cert.get('descr', 'Unknown')
            # Endpoint: /api/trust/cert/del/UUID
            del_url = f"{base_url}/trust/cert/del/{uuid}"
            try:
                self.logger.info(f"Deleting expired cert: {descr} ({uuid})")
                resp = requests.post(del_url, json={}, auth=auth, verify=False)
                if resp.status_code == 200:
                    res_json = resp.json()
                    if res_json.get('result') == 'deleted':
                        deleted_count += 1
                    else:
                        errors.append(f"Failed to delete {descr}: {res_json}")
                else:
                    errors.append(f"HTTP {resp.status_code} deleting {descr}")
            except Exception as e:
                errors.append(f"Exception deleting {descr}: {e}")
        
        msg = f"Deleted {deleted_count} expired certificates."
        if errors:
            msg += f" Errors: {'; '.join(errors)}"
            
        return {"success": True, "message": msg, "count": deleted_count}

    def _get_expired_certs(self):
        """Helper to find expired certs matching our pattern."""
        host = self.config.get('host')
        api_key = self.config.get('api_key')
        api_secret = self.config.get('api_secret')
        
        if not all([host, api_key, api_secret]): return []
        
        base_url = f"https://{host}/api"
        auth = (api_key, api_secret)
        search_url = f"{base_url}/trust/cert/search"
        
        try:
            # Search all
            payload = {"current": 1, "rowCount": 999, "searchPhrase": ""}
            resp = requests.post(search_url, json=payload, auth=auth, verify=False)
            if resp.status_code != 200:
                self.logger.error(f"Failed to search certs: {resp.status_code}")
                return []
                
            data = resp.json()
            rows = data.get('rows', [])
            
            expired = []
            now = time.time()
            
            for row in rows:
                # Structure: uuid, descr, valid_to (timestamp in seconds)
                # Filter by name "AutoRenew-" AND validity
                descr = row.get('descr', '')
                valid_to = float(row.get('valid_to', 0))
                
                # Check 1: Is it expired? (with some buffer? No, strict is fine or 1 day grace)
                # Check 2: Is it one of ours? (AutoRenew rule) OR general?
                # The user asked "expired certificate if the tool finds one". 
                # Safety first: Only delete "AutoRenew-" ones.
                if "AutoRenew-" in descr and valid_to < now:
                    expired.append(row)
                    
            return expired
            
        except Exception as e:
            self.logger.error(f"Error checking expired certs: {e}")
            return []

    @staticmethod
    def provision_api_key(host, user, password):
        """
        Scrapes OPNsense WebGUI to generate an API key for the user.
        Returns: (api_key, api_secret)
        """
        session = requests.Session()
        session.verify = False
        base_url = f"https://{host}"
        
        session = requests.Session()
        session.verify = False
        base_url = f"https://{host}"
        
        # 1. Get CSRF Token & Init Session
        try:
            resp_init = session.get(base_url)
            csrf_token = resp_init.headers.get('X-CSRFToken') or resp_init.cookies.get('X-CSRFToken')
            
            # If standard API login failed (404), likely we need to do Form Login to root
            # Modern OPNsense often uses 'usernamefld' and 'passwordfld' posted to /
            
            headers = {
                 "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            if csrf_token:
                headers['X-CSRFToken'] = csrf_token
            
            # Attempt Form Login (Legacy/Standard UI)
            # We don't use JSON here, we use Form Data
            login_data = {
                "usernamefld": user, 
                "passwordfld": password, 
                "login": "Login" 
            }
            
            # We perform a POST to the root URL
            login_resp = session.post(base_url + '/', data=login_data, headers=headers)
            
            # Start of check: Did we get redirected to dashboard or is there indication of success?
            # A successful login usually redirects or returns the dashboard HTML.
            if "login" in login_resp.url and "dashboard" not in login_resp.url:
                 # If we are still at a url with 'login' or response text contains "Username" field again, it failed.
                 if "Username" in login_resp.text and "Password" in login_resp.text:
                     raise Exception("Login failed (Invalid Credentials or Form mismatch)")

            # Update CSRF from login response if present (cookies/headers might update)
            if 'X-CSRFToken' in login_resp.headers:
                headers['X-CSRFToken'] = login_resp.headers['X-CSRFToken']
            # Re-add JSON content type for subsequent API calls
            headers['Content-Type'] = 'application/json'

            # 2. Find User UUID
            # Try Modern API first
            user_uuid = None
            search_url = f"{base_url}/api/core/user/searchUser"
            search_payload = {"current": 1, "rowCount": -1, "searchPhrase": user}
            
            try:
                user_resp = session.post(search_url, json=search_payload, headers=headers)
                if user_resp.status_code == 200:
                    rows = user_resp.json().get('rows', [])
                    for r in rows:
                        if r['name'] == user:
                            user_uuid = r['uuid']
                            break
            except Exception:
                pass # Fallback to legacy
            
            # Fallback: Legacy Scraping if API failed or didn't find user
            if not user_uuid:
                # Scrape /system_usermanager.php
                import re
                legacy_url = f"{base_url}/system_usermanager.php"
                leg_resp = session.get(legacy_url)
                if leg_resp.status_code == 200:
                    # Regex to find the user row and extracting UUID
                    # Pattern: href="system_usermanager.php?act=edit&amp;userid=..." ... >username<
                    # This is tricky without BS4, but let's try a robust regex.
                    # We look for the username in the text, then look backwards for the userid link? 
                    # Or finding all rows.
                    
                    # Typical structure: 
                    # <a href="system_usermanager.php?act=edit&amp;userid=5f1d...">root</a>
                    
                    # Regex: href="system_usermanager\.php\?act=edit&(?:amp;)?userid=([a-fA-F0-9-]+)"[^>]*?>\s*USER_NAME\s*<
                    # Where USER_NAME is the variable.
                    
                    pattern = r'href="system_usermanager\.php\?act=edit&(?:amp;)?userid=([a-fA-F0-9-]+)"[^>]*?>\s*' + re.escape(user) + r'\s*<'
                    match = re.search(pattern, leg_resp.text, re.IGNORECASE)
                    if match:
                        user_uuid = match.group(1)
            
            if not user_uuid:
                raise Exception(f"User '{user}' not found (tried API and Legacy scraping).")
                
            # 3. Generate API Key
            # Try Modern API first
            key_url = f"{base_url}/api/core/user/createApiKey"
            
            # This endpoint returns a FILE (apikey.txt)
            key_resp = session.post(key_url, json={"uuid": user_uuid}, headers=headers)
            
            if key_resp.status_code == 200:
                content = key_resp.text
            else:
                # Fallback: Legacy Key Generation
                # /system_usermanager.php?act=newapikey&userid=...
                legacy_key_url = f"{base_url}/system_usermanager.php?act=newapikey&userid={user_uuid}"
                key_resp = session.get(legacy_key_url)
                if key_resp.status_code == 200:
                    content = key_resp.text
                else:
                    raise Exception(f"Failed to create API key via API ({key_resp.status_code}) or Legacy.")
            
            # Response content is the file download (text/plain)
            # Format:
            # key=...
            # secret=...
            api_key = None
            api_secret = None
            
            for line in content.splitlines():
                if line.startswith('key='):
                    api_key = line.split('=')[1].strip()
                if line.startswith('secret='):
                    api_secret = line.split('=')[1].strip()
                    
            if not api_key or not api_secret:
                raise Exception("Failed to parse API key/secret from response. (Are permissions correct?)")
                
            return api_key, api_secret

        except Exception as e:
            raise Exception(f"OPNsense Provisioning Error: {e}")
