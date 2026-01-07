import requests
from .base_handler import CertificateHandler
import urllib3

# Suppress insecure request warnings for self-signed or internal certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ProxmoxHandler(CertificateHandler):
    def renew(self, cert_path: str, key_path: str) -> bool:
        node = self.config.get('node', 'pve')
        host = self.config.get('host')
        token_id = self.config.get('token_id')
        token_secret = self.config.get('token_secret')
        
        if not all([host, token_id, token_secret]):
            self.logger.error("Missing required config for Proxmox (host, token_id, token_secret)")
            return False

        try:
            with open(cert_path, 'r') as f:
                cert_content = f.read()
            with open(key_path, 'r') as f:
                key_content = f.read()
        except Exception as e:
            self.logger.error(f"Failed to read certificate files: {e}")
            return False

        url_base = f"https://{host}:8006/api2/json"
        
        # 1. Dynamic Node Detection
        # The 'node' in config might be wrong (default 'pve').
        # We query the API to find the actual local node name.
        detected_node = None
        headers = {
            "Authorization": f"PVEAPIToken={token_id}={token_secret}"
        }
        
        try:
            nodes_resp = requests.get(f"{url_base}/nodes", headers=headers, verify=False)
            if nodes_resp.status_code == 200:
                nodes = nodes_resp.json().get('data', [])
                # Find the node marked as local
                for n in nodes:
                    if n.get('ssl_fingerprint') or n.get('status') == 'online': 
                        # Proxmox doesn't always explicitly say 'local' in /nodes list public output safely?
                        # Actually it usually does if authenticated.
                        # But simpler: if we are hitting this IP, and it returns a list of nodes,
                        # and we want to update the cert FOR THIS NODE, usually we want the one that matches.
                        # If single node, it's just the first one.
                        # Let's look for one that is 'online'.
                        if n.get('local', 0) == 1:
                            detected_node = n['node']
                            break
                            
                if not detected_node and nodes:
                     # Fallback: take the first one
                     detected_node = nodes[0]['node']
                     
        except Exception as e:
            self.logger.warning(f"Failed to auto-detect node name: {e}")

        # Use detected node if found, otherwise config fallback
        final_node = detected_node if detected_node else node
        if detected_node and detected_node != node:
            self.logger.info(f"Auto-detected node name '{detected_node}' (Config was '{node}'). Using detected name.")

        url = f"{url_base}/nodes/{final_node}/certificates/custom"
        
        data = {
            "certificates": cert_content,
            "key": key_content,
            "force": 1, # Force overwrite
            "restart": 1 # Restart proxy to apply
        }

        try:
            self.logger.info(f"Uploading certificate to Proxmox node {node} at {host}...")
            response = requests.post(url, headers=headers, data=data, verify=False)
            
            if response.status_code == 200:
                # Proxmox API returns 200 even on some failures, check 'data'
                resp_json = response.json()
                # Usually returns the task UPID in 'data'
                if resp_json.get('data'):
                     self.logger.info("Certificate uploaded successfully. API returned ID: " + str(resp_json['data']))
                     return True
                else:
                     self.logger.error(f"Proxmox API returned 200 but unexpected body: {resp_json}")
                     return False
            else:
                self.logger.error(f"Failed to upload certificate. Status: {response.status_code}, Response: {response.text}")
                return False

        except Exception as e:
            self.logger.exception(f"Exception during Proxmox certificate update: {e}")
            return False

            self.logger.exception(f"Exception during Proxmox certificate update: {e}")
            return False

    def check_remote_expiry(self) -> dict:
        from .network_utils import check_ssl_expiry
        host = self.config.get('host')
        return check_ssl_expiry(host, port=8006)

    @staticmethod
    def provision_token(host, user, password, node='pve'):
        """
        Authenticates with Username/Password to generate a long-lived API Token.
        Returns: (token_id, token_secret) or Raises Exception
        """
        base_url = f"https://{host}:8006/api2/json"
        
        # 1. Authenticate to get Ticket & CSRF
        try:
            auth_resp = requests.post(f"{base_url}/access/ticket", data={
                "username": user,
                "password": password
            }, verify=False)
            
            if auth_resp.status_code != 200:
                raise Exception(f"Authentication failed: {auth_resp.text}")
                
            auth_data = auth_resp.json()['data']
            ticket = auth_data['ticket']
            csrf = auth_data['CSRFPreventionToken']
            
            # 1.5 Fetch Node List (Auto-detect node name)
            node_name = node # Default
            try:
                nodes_resp = requests.get(f"{base_url}/nodes", cookies=cookies, verify=False)
                if nodes_resp.status_code == 200:
                    nodes_data = nodes_resp.json()['data']
                    if nodes_data and len(nodes_data) > 0:
                        # Pick the first online node or just the first one
                        node_name = nodes_data[0]['node']
            except Exception as e:
                pass # Fallback to default provided

            # 2. Generate new Token
            # Token ID: cert-auto-{timestamp}
            import time
            token_name = f"cert-auto-{int(time.time())}"
            user_id = user # e.g. root@pam
            
            # API expects: POST /access/users/{userid}/token/{tokenid}
            # Headers: CSRFPreventionToken
            # Cookie: PVEAuthCookie=ticket
            
            token_url = f"{base_url}/access/users/{user_id}/token/{token_name}"
            
            headers = {"CSRFPreventionToken": csrf}
            cookies = {"PVEAuthCookie": ticket}
            
            token_resp = requests.post(token_url, headers=headers, cookies=cookies, data={
                "privsep": 0 # Don't need privilege separation for certs usually, or 1? 0 is safer default for single node.
            }, verify=False)
            
            if token_resp.status_code != 200:
                 raise Exception(f"Token generation failed: {token_resp.text}")
                 
            token_data = token_resp.json()['data']
            # token_data contains 'full-tokenid' (user!token) and 'value' (secret)
            
            return token_data['full-tokenid'], token_data['value'], node_name
            
        except Exception as e:
            raise Exception(f"Proxmox Provisioning Error: {e}")
