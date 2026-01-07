import json
import ssl
import time
import uuid
import requests
import urllib3
from websocket import create_connection
from .base_handler import CertificateHandler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TrueNASHandler(CertificateHandler):
    def renew(self, cert_path: str, key_path: str) -> bool:
        # Try WebSocket First (Future Proof)
        self.logger.info("Attempting renewal via WebSocket (JSON-RPC)...")
        if self._renew_websocket(cert_path, key_path):
            return True
            
        self.logger.warning("WebSocket renewal failed. Falling back to REST API (Legacy)...")
        return self._renew_rest(cert_path, key_path)

    def _renew_websocket(self, cert_path: str, key_path: str) -> bool:
        host = self.config.get('host')
        api_key = self.config.get('api_key')
        
        if not all([host, api_key]):
            self.logger.error("Missing required config for TrueNAS (host, api_key)")
            return False

        try:
            with open(cert_path, 'r') as f:
                cert_content = f.read()
            with open(key_path, 'r') as f:
                key_content = f.read()
        except Exception as e:
            self.logger.error(f"Failed to read certificate files: {e}")
            return False

        ws = None
        try:
            # 1. Connect
            ws_url = f"wss://{host}/api/current"
            self.logger.info(f"Connecting to TrueNAS WebSocket: {ws_url}")
            
            # TrueNAS might require Origin match or Host header
            ws = create_connection(ws_url, sslopt={"cert_reqs": ssl.CERT_NONE, "check_hostname": False}, origin=f"https://{host}", timeout=10)
            ws.settimeout(10)
            
            # 2. Auth
            self.logger.info("Authenticating...")
            auth_res = self._call(ws, "auth.login_with_api_key", [api_key])
            if not auth_res:
                self.logger.error("Authentication failed.")
                return False
                
            # 3. Import Certificate
            cert_name = f"auto-cert-{int(time.time())}"
            self.logger.info(f"Uploading certificate '{cert_name}'...")
            
            payload = {
                "create_type": "CERTIFICATE_CREATE_IMPORTED",
                "name": cert_name,
                "certificate": cert_content,
                "privatekey": key_content
            }
            
            new_cert = self._call(ws, "certificate.create", [payload])
            if not new_cert:
                self.logger.error("Failed to upload certificate.")
                return False
                
            # TrueNAS Scale returns a JOB ID for certificate.create
            if isinstance(new_cert, int):
                job_id = new_cert
                self.logger.info(f"Certificate creation started (Job ID: {job_id}). Waiting for completion...")
                
                # Wait for job to finish
                job_res = self._call(ws, "core.job_wait", [job_id])
                
                # Defensively handle job_res which is the 'result' of core.job_wait
                if isinstance(job_res, dict):
                    if job_res.get('state') != 'SUCCESS':
                        self.logger.error(f"Certificate Job failed: {job_res}")
                        return False
                    final_result = job_res.get('result')
                else:
                    # If core.job_wait returns the result directly (some versions)
                    final_result = job_res
                
                # Extract the actual Certificate ID
                if isinstance(final_result, dict):
                    new_cert_id = final_result.get('id')
                else:
                    new_cert_id = final_result
            else:
                # Direct return (unlikely but possible)
                new_cert_id = new_cert.get('id')
                
            if not new_cert_id:
                self.logger.error(f"Failed to resolve real Certificate ID from job result: {new_cert}")
                return False

            self.logger.info(f"Certificate uploaded successfully. Real ID: {new_cert_id}")

            # 4. Get Current Config to find old cert
            config = self._call(ws, "system.general.config")
            old_cert_id = None
            if config and 'ui_certificate' in config:
                curr = config['ui_certificate']
                if isinstance(curr, dict): old_cert_id = curr.get('id')
                else: old_cert_id = curr
                
            # POLLING: Wait for certificate to be queryable by NAME (more robust than ID index initially)
            self.logger.info(f"Waiting for certificate '{cert_name}' to be available...")
            for i in range(15): # 15 * 2s = 30s
                # Query for this specific cert NAME
                check = self._call(ws, "certificate.query", [[["name", "=", cert_name]]])
                if check and len(check) > 0:
                     cert_obj = check[0]
                     new_cert_id = cert_obj.get('id')
                     self.logger.info(f"Certificate confirmed available. Resolved ID by Name: {new_cert_id}")
                     break
                self.logger.warning(f"Poll {i+1}/15: Certificate '{cert_name}' not found yet. Result: {check}")
                time.sleep(2)
            else:
                self.logger.error(f"Timed out waiting for certificate '{cert_name}' to be available.")
                return False

            # 5. Update GUI Certificate
            self.logger.info(f"Activating certificate {new_cert_id}...")
            update_res = self._call(ws, "system.general.update", [{"ui_certificate": new_cert_id}])
            
            # Use 'web.reload' or just wait? Usually changing cert restarts nginx automatically.
            # But let's check result.
            if update_res is None: # update returns config or None on error
                 # Actually _call returns result or None. If update works it returns the config object.
                 self.logger.error("Failed to activate certificate.")
                 return False
                 
            self.logger.info("Certificate activated.")

            # 6. Delete Old Certificate
            if old_cert_id and old_cert_id != new_cert_id:
                self.logger.info(f"Deleting old certificate {old_cert_id}...")
                self._call(ws, "certificate.delete", [old_cert_id])

            return True

        except Exception as e:
            self.logger.exception(f"TrueNAS WebSocket Error: {e}")
            return False
        finally:
            if ws: ws.close()

    def _renew_rest(self, cert_path: str, key_path: str) -> bool:
        host = self.config.get('host')
        api_key = self.config.get('api_key')
        
        try:
            with open(cert_path, 'r') as f:
                cert_content = f.read()
            with open(key_path, 'r') as f:
                key_content = f.read()
        except Exception as e:
            self.logger.error(f"Failed to read certificate files: {e}")
            return False

        base_url = f"https://{host}/api/v2.0"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        # 1. Upload new certificate
        cert_name = f"auto-cert-{int(time.time())}"
        upload_data = {
            "create_type": "CERTIFICATE_CREATE_IMPORTED",
            "name": cert_name,
            "certificate": cert_content,
            "privatekey": key_content
        }

        self.logger.info(f"Uploading new certificate '{cert_name}' to TrueNAS (REST)...")
        try:
            resp = requests.post(f"{base_url}/certificate", headers=headers, json=upload_data, verify=False, timeout=10)
            if resp.status_code != 200:
                self.logger.error(f"Failed to upload certificate. Status: {resp.status_code}, Body: {resp.text}")
                return False
        except Exception as e:
            self.logger.error(f"REST Upload Error: {e}")
            return False
            
        try:
            # We need the ID. Often it's in the response.
            response_data = resp.json()
            
            # 1. Handle Job ID in REST
            if isinstance(response_data, int):
                job_id = response_data
                self.logger.info(f"Certificate creation started via REST (Job ID: {job_id}). Waiting for completion...")
                
                # Poll for Job completion
                new_cert_id = None
                for i in range(15): # 30 seconds
                    job_resp = requests.get(f"{base_url}/job/id/{job_id}", headers=headers, verify=False, timeout=5)
                    if job_resp.status_code == 200:
                        job_info = job_resp.json()
                        state = job_info.get('state')
                        if state == 'SUCCESS':
                            self.logger.info("REST Job completed successfully.")
                            # Extract result
                            result = job_info.get('result')
                            if isinstance(result, dict):
                                new_cert_id = result.get('id')
                            else:
                                new_cert_id = result
                            break
                        elif state in ['FAILED', 'ABORTED']:
                            self.logger.error(f"REST Job failed with state: {state}. Info: {job_info}")
                            return False
                    time.sleep(2)
                else:
                    self.logger.error("Timed out waiting for REST Job completion.")
                    return False
                
                # After Job success, double check the ID by NAME
                self.logger.info(f"Job finished. Resolving Certificate ID by Name '{cert_name}'...")
                for j in range(5):
                    chk_resp = requests.get(f"{base_url}/certificate", headers=headers, params={"name": cert_name}, verify=False, timeout=5)
                    if chk_resp.status_code == 200:
                        certs = chk_resp.json()
                        if isinstance(certs, list) and len(certs) > 0:
                            new_cert_id = certs[0].get('id')
                            self.logger.info(f"Resolved Cert ID: {new_cert_id}")
                            break
                    time.sleep(2)
                else:
                    self.logger.error(f"Could not find certificate '{cert_name}' even after job success.")
                    return False
            else:
                new_cert_id = response_data.get('id')
            
            if not new_cert_id:
                self.logger.error(f"Failed to obtain certificate ID from REST response: {response_data}")
                return False

            # 2. Get current certificate ID
            old_cert_id = None
            gen_resp = requests.get(f"{base_url}/system/general", headers=headers, verify=False, timeout=10)
            if gen_resp.status_code == 200:
                settings = gen_resp.json()
                current_ui_cert = settings.get('ui_certificate')
                if isinstance(current_ui_cert, dict): old_cert_id = current_ui_cert.get('id')
                else: old_cert_id = current_ui_cert

            # 3. Final sanity check and activation
            try:
                new_cert_id = int(new_cert_id)
            except:
                pass
                
            self.logger.info(f"Activating certificate ID {new_cert_id}...")
            update_resp = requests.put(f"{base_url}/system/general", headers=headers, json={"ui_certificate": new_cert_id}, verify=False, timeout=10)
            if update_resp.status_code != 200:
                self.logger.error(f"Failed to activate. Status: {update_resp.status_code}, Body: {update_resp.text}")
                return False

            # 4. Delete Old
            if old_cert_id and old_cert_id != new_cert_id:
                self.logger.info(f"Deleting old certificate ID {old_cert_id}...")
                requests.delete(f"{base_url}/certificate/id/{old_cert_id}", headers=headers, verify=False, timeout=10)

            return True

        except Exception as e:
            self.logger.exception(f"REST Renewal Error: {e}")
            return False

    def _call(self, ws, method, params=None):
        req_id = str(uuid.uuid4())
        req = {
            "jsonrpc": "2.0",
            "id": req_id,
            "msg": "method",
            "method": method,
            "params": params or []
        }
        ws.send(json.dumps(req))
        
        while True:
            res = self._recv(ws)
            if not res: return None
            
            if res.get('id') == req_id:
                if 'error' in res:
                    self.logger.error(f"RPC Error {method}: {res['error']}")
                    return None
                return res.get('result')
                
    def _recv(self, ws):
        try:
            msg = ws.recv()
            data = json.loads(msg)
            if data.get('msg') == 'connect':
                return data
            if data.get('msg') == 'result':
                return data
            return data # Return anything for loop handling
        except Exception as e:
            self.logger.error(f"WS Recv Error: {e}")
            return None

    @staticmethod
    def provision_api_key(host, user, password):
        # We can use REST just for this initial setup if needed, or WS.
        # But for simplicity, let's keep the user/pass flow capable.
        # Actually provisioning keys via WS is cleaner.
        import json
        import ssl
        from websocket import create_connection

        ws_url = f"wss://{host}/api/current"
        try:
             # Short timeout for initial connect
             ws = create_connection(ws_url, sslopt={"cert_reqs": ssl.CERT_NONE, "check_hostname": False}, origin=f"https://{host}", timeout=10)
             ws.settimeout(10)
             
             # Connect msg
             # ws.recv() # Skip waiting for connect message to avoid deadlock
             # Auth
             req_id = "auth_req"
             ws.send(json.dumps({
                 "id": req_id,
                 "msg": "method",
                 "method": "auth.login",
                 "params": [user, password]
             }))
             
             while True:
                 res = json.loads(ws.recv())
                 if res.get('id') == req_id:
                     if 'error' in res: raise Exception(f"Auth Failed: {res['error']}")
                     if res.get('result') is True: break

             # Create Key
             req_id = "key_req"
             key_name = f"cert-auto-prov-{int(time.time())}"
             ws.send(json.dumps({
                 "id": req_id,
                 "msg": "method",
                 "method": "auth.generate_api_key",
                 "params": [{"name": key_name}]
             }))
             
             while True:
                 res = json.loads(ws.recv())
                 if res.get('id') == req_id:
                      if 'error' in res: raise Exception(f"Key Gen Failed: {res['error']}")
                      ws.close()
                      return res['result']

        except Exception as e:
             # Fallback to REST API
             # Try to create API Key via REST using Basic Auth
             import requests
             base_url = f"https://{host}/api/v2.0"
             key_name = f"cert-auto-prov-{int(time.time())}"
             
             try:
                 resp = requests.post(
                     f"{base_url}/api_key", 
                     auth=(user, password), 
                     json={"name": key_name, "username": user}, 
                     verify=False, 
                     timeout=10
                 )
                 if resp.status_code == 200:
                     # Docs: RETURNS: { "id": 1, "key": "...", "name": "..." }
                     # We need 'key'
                     return resp.json().get('key')
                 else:
                     raise Exception(f"REST Fallback Failed {resp.status_code}: {resp.text}")
             except Exception as rest_e:
                 raise Exception(f"Connection Failed (WS: {e}, REST: {rest_e})")
        

