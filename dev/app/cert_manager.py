import logging
import os
import tempfile
import time
from .config_manager import ConfigManager
from .proxmox_handler import ProxmoxHandler
from .truenas_handler import TrueNASHandler
from .opnsense_handler import OPNSenseHandler
from .syncthing_handler import SyncthingHandler
from .wazuh_handler import WazuhHandler
from .heimdall_handler import HeimdallHandler
from .clearpass_handler import ArubaClearPassHandler
from .portainer_handler import PortainerHandler
from .linux_handler import GenericLinuxHandler
from .webhook_handler import GenericWebhookHandler

HANDLERS = {
    'proxmox': ProxmoxHandler,
    'truenas': TrueNASHandler,
    'opnsense': OPNSenseHandler,
    'syncthing': SyncthingHandler,
    'wazuh': WazuhHandler,
    'heimdall': HeimdallHandler,
    'clearpass': ArubaClearPassHandler,
    'portainer': PortainerHandler,
    'linux': GenericLinuxHandler,
    'webhook': GenericWebhookHandler
}

class CertManager:
    def __init__(self, config_path, cert_dir, master_password=None, backup_dir=None):
        self.config_path = config_path
        self.cert_dir = cert_dir
        self.logger = logging.getLogger("CertAutomator.Manager")
        self.config_mgr = ConfigManager(config_path, master_password=master_password, backup_dir=backup_dir)
        from .cert_validator import CertValidator
        self.validator = CertValidator()

    @property
    def is_locked(self):
        return self.config_mgr.is_locked

    def unlock(self, password):
        return self.config_mgr.unlock(password)


    def get_handler(self, service_data):
        """
        Instantiates the appropriate handler for a service.
        Resolves aliases via ConfigManager service_types.
        """
        svc_type = service_data.get('type')
        if not svc_type:
            raise ValueError("Service has no type defined.")

        # 1. Resolve Alias via Config
        service_types_map = self.config_mgr.get_service_types()
        base_type = service_types_map.get(svc_type)

        # Fallback: Validation logic
        # If the user typed a built-in name that was DELETED from the map, we might still want to support it if it matches a handler key directly?
        # But strictly speaking, if it's not in the map, it's not a valid type exposed to the system.
        # However, for robustness, if map lookup fails BUT it exists in HANDLERS, we could use it?
        # Plan says: "User Config defines the mapping".
        # Let's be strict: Must be in the map. Wait, initialization populates defaults. So it should be there.
        # If I added a new handler in code but didn't add to defaults, it might break.
        
        if not base_type:
             # Fallback: If it matches a raw handler key directly, let's use it (Development safety net)
             if svc_type in HANDLERS:
                 base_type = svc_type
             else:
                 raise ValueError(f"Unknown service type: {svc_type}")

        # 2. Get Handler Class
        handler_class = HANDLERS.get(base_type)
        if not handler_class:
            raise ValueError(f"No handler implementation found for base type: {base_type}")
            
        return handler_class(service_data)

    def get_cert_paths(self, cert_pack_name=None):
        """
        Returns (cert_path, key_path) for the specified pack.
        If cert_pack_name is None, 'default', or empty, uses the root cert_dir (legacy mode).
        """
        if not cert_pack_name or cert_pack_name == 'default':
            base_dir = self.cert_dir
        else:
            base_dir = os.path.join(self.cert_dir, cert_pack_name)
            
        return (
            os.path.join(base_dir, "fullchain.pem"),
            os.path.join(base_dir, "privkey.pem")
        )

    def validate_certs(self, cert_pack_name=None):
        cert_path, key_path = self.get_cert_paths(cert_pack_name)
        # Check for standard PEM key OR Encrypted key
        base_dir = os.path.dirname(cert_path)
        has_key = os.path.exists(key_path) or os.path.exists(os.path.join(base_dir, "privkey.enc"))
        return os.path.exists(cert_path) and has_key

    def list_cert_packs(self):
        """Returns a list of available certificate packs."""
        root_path = os.path.abspath(self.cert_dir)
        packs = [{"id": "default", "name": "Default (Root)", "path": root_path}]
        
        # Scan for subdirectories
        if os.path.exists(self.cert_dir):
            for item in os.listdir(self.cert_dir):
                item_path = os.path.join(self.cert_dir, item)
                if os.path.isdir(item_path) and not item.startswith('.'):
                    packs.append({
                        "id": item,
                        "name": item,
                        "path": os.path.abspath(item_path)
                    })
        return packs

    def save_cert_pack(self, name, cert_content, key_content):
        """Saves a new certificate pack."""
        # Sanitize name
        safe_name = "".join([c for c in name if c.isalnum() or c in ('-', '_')]).strip()
        if not safe_name:
            raise ValueError("Invalid pack name")
            
        pack_dir = os.path.join(self.cert_dir, safe_name)
        if not os.path.exists(pack_dir):
            os.makedirs(pack_dir)
            
        with open(os.path.join(pack_dir, "fullchain.pem"), "wb") as f:
            f.write(cert_content)
            
        # Security: Encrypt Private Key at Rest
        # We use the ConfigManager's crypto utility (AES-256)
        try:
            # Encrypt key content
            # Ensure key is string for JSON serialization inside encrypt_data
            key_str = key_content.decode('utf-8')
            encrypted_bytes = self.config_mgr.crypto.encrypt_data({"key": key_str}, self.config_mgr.master_password)
            
            with open(os.path.join(pack_dir, "privkey.enc"), "wb") as f:
                f.write(encrypted_bytes)
                
            # Cleanup legacy plain text key if exists (Migration)
            legacy_key = os.path.join(pack_dir, "privkey.pem")
            if os.path.exists(legacy_key):
                os.remove(legacy_key)
                
        except Exception as e:
            self.logger.error(f"Failed to encrypt private key: {e}. Fallback to plain text (Protected 0600).")
            # Fallback (Safety Net)
            with open(os.path.join(pack_dir, "privkey.pem"), "wb") as f:
                f.write(key_content)
            os.chmod(os.path.join(pack_dir, "privkey.pem"), 0o600)
            
        return safe_name

    def delete_cert_pack(self, name):
        """Deletes a certificate pack."""
        if name == 'default':
            raise ValueError("Cannot delete default pack")
            
        pack_dir = os.path.join(self.cert_dir, name)
        if os.path.exists(pack_dir) and os.path.isdir(pack_dir):
            import shutil
            shutil.rmtree(pack_dir)
            return True
        return False

    def get_services(self):
        return self.config_mgr.get_services()

    def renew_service(self, service_name):
        """Renews a single service by name. Returns dict result."""
        services = self.get_services()
        target = next((s for s in services if s.get('name') == service_name), None)
        
        if not target:
            return {"success": False, "message": "Service not found"}

        # Get Cert Pack (Default to cleanup global if None)
        # Fix: Frontend sends 'cert_pack_id', Backend Legacy used 'cert_pack'
        cert_pack = target.get('cert_pack_id') or target.get('cert_pack')
        
        if cert_pack:
             self.logger.info(f"Renewing {service_name} using Cert Pack: {cert_pack}")
        else:
             self.logger.info(f"Renewing {service_name} using Default Cert Pack")
        
        if not self.validate_certs(cert_pack):
            return {"success": False, "message": f"Certificates not found for pack: {cert_pack or 'Default'}"}

        svc_type = target.get('type')
        handler_cls = HANDLERS.get(svc_type)
        if not handler_cls:
            return {"success": False, "message": f"Unknown service type: {svc_type}"}

        cert_path, key_path = self.get_cert_paths(cert_pack)

        try:
            # Security: Decrypt key on-the-fly if encrypted
            temp_key_file = None
            base_dir = os.path.dirname(cert_path)
            enc_key_path = os.path.join(base_dir, "privkey.enc")
            
            try:
                if os.path.exists(enc_key_path):
                    self.logger.info("Decrypting private key for renewal session...")
                    with open(enc_key_path, 'rb') as f:
                        enc_data = f.read()
                    
                    # Decrypt
                    decrypted_json = self.config_mgr.crypto.decrypt_data(enc_data, self.config_mgr.master_password)
                    raw_key = decrypted_json.get('key')
                    
                    # Write to Secure Temp File
                    fd, temp_key_path = tempfile.mkstemp()
                    with os.fdopen(fd, 'w') as tmp:
                        tmp.write(raw_key)
                    
                    # Use this temp path as the key path
                    key_path = temp_key_path
                    temp_key_file = temp_key_path # Marker for cleanup
                
                # Legacy/Fallback: key_path remains pointing to 'privkey.pem' if 'privkey.enc' missing.
                
                handler = handler_cls(target)
                result = handler.renew(cert_path, key_path)
                
            finally:
                # Secure Cleanup
                if temp_key_file and os.path.exists(temp_key_file):
                    try:
                        os.remove(temp_key_file)
                        self.logger.info("Secure cleanup: Temporary decrypted key removed.")
                    except Exception as e:
                        self.logger.error(f"CRITICAL: Failed to delete temp key file {temp_key_file}: {e}")
                
            # Normalize return to dict
            response = {}
            if isinstance(result, bool):
                response = {
                    "success": result, 
                    "message": "Renewed successfully" if result else "Renewal failed"
                }
            elif isinstance(result, dict):
                # Ensure baseline keys
                response = result
                if 'success' not in response: response['success'] = False
                if 'message' not in response: response['message'] = "Operation completed"
            else:
                 return {"success": False, "message": f"Unexpected return type from handler: {type(result)}"}
    
            # Auto-Check after success
            if response.get('success'):
                self.logger.info(f"Renewal success for {service_name}. Checking propagation...")
                import time
                time.sleep(2) # Give service a moment to restart/reload
                
                check_res = self.check_service_expiry(service_name)
                if check_res.get('success'):
                    self.logger.info(f"Post-renewal check passed: {check_res.get('days_remaining')} days remaining.")
                else:
                    self.logger.warning(f"Post-renewal check failed: {check_res.get('message')}")
            
            # Persist Status to Config
            import datetime
            status_entry = {
                "last_run": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "Success" if response.get('success') else "Failed",
                "message": response.get('message', '')
            }
            try:
                self.config_mgr.update_service(service_name, {"last_renewal": status_entry})
            except Exception as e:
                self.logger.error(f"Failed to persist renewal status for {service_name}: {e}")
            
            return response

        except Exception as e:
            self.logger.exception(f"Error renewing {service_name}: {e}")
            
            # Persist Failure Status
            import datetime
            try:
                self.config_mgr.update_service(service_name, {"last_renewal": {
                    "last_run": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "status": "Failed",
                    "message": str(e)
                }})
            except:
                pass

            return {"success": False, "message": str(e)}

    def cleanup_service(self, service_name):
        """Clean up expired certs for a service."""
        services = self.get_services()
        target = next((s for s in services if s.get('name') == service_name), None)
        if not target: return {"success": False, "message": "Service not found"}
        
        svc_type = target.get('type')
        handler_cls = HANDLERS.get(svc_type)
        if not handler_cls: return {"success": False, "message": "Unknown type"}
        
        try:
            handler = handler_cls(target)
            return handler.cleanup_expired()
        except Exception as e:
            return {"success": False, "message": str(e)}

    def renew_all(self):
        """Renews all services."""
        if not self.validate_certs():
            return {"error": "Certificates not found"}

        results = {}
        services = self.get_services()
        for svc in services:
            name = svc.get('name')
            if not svc.get('enabled', True):
                results[name] = {"success": False, "message": "Disabled"}
                continue
                
            # Now returns a dict
            results[name] = self.renew_service(name)
        
        return results

    def check_service_expiry(self, service_name):
        """Checks the remote certificate expiry and updates the config."""
        services = self.get_services()
        target = next((s for s in services if s.get('name') == service_name), None)
        
        if not target:
            return {"success": False, "message": "Service not found"}
            
        try:
            handler = self.get_handler(target) # Uses alias resolution
            result = handler.check_remote_expiry()
            
            if result.get('success'):
                # Save status to config
                import datetime
                status_data = {
                    "last_check": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "expiry": result.get('expiry'),
                    "days_remaining": result.get('days_remaining'),
                    "issuer": result.get('issuer'),
                    "valid": True
                }
                self.config_mgr.update_service(service_name, {"ssl_status": status_data})
                
                # Merge into result for return
                result.update(status_data)
                
            return result
            
        except Exception as e:
            self.logger.exception(f"Error checking {service_name}: {e}")
            return {"success": False, "message": str(e)}

    def perform_daily_health_check(self):
        """Checks the certificate validity for all services (Local and Remote)."""
        self.logger.info("Running Global Health Check (Local + Remote)...")
        services = self.get_services()
        changes_count = 0
        import datetime
        
        for svc in services:
            try:
                name = svc.get('name')
                
                # 1. Local Check
                pack = svc.get('cert_pack_id') or svc.get('cert_pack')
                cert_path, _ = self.get_cert_paths(pack)
                cert_path, _ = self.get_cert_paths(pack)
                
                status = {
                    "valid": False,
                    "message": "Certificate file missing",
                    "status": "Error",
                    "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                }

                if os.path.exists(cert_path):
                    with open(cert_path, 'rb') as f:
                        cert_data = f.read()
                    cert_obj = self.validator.load_cert(cert_data)
                    if cert_obj:
                        details = self.validator.get_cert_details(cert_obj)
                        days = details.get('days_remaining', 0)
                        valid = days > 0
                        status_text = "Healthy"
                        if days < 0: status_text = f"Expired ({abs(days)}d ago)"
                        elif days < 30: status_text = f"Expiring, {days}d left"
                        elif not valid: status_text = "Invalid"
                        
                        status = {
                            "valid": valid,
                            "days_remaining": days,
                            "expiry": details.get('expiry'),
                            "message": f"Expires in {days} days",
                            "status": status_text,
                            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                        }
                
                self.config_mgr.update_service(name, {"health_status": status})

                # 2. Remote Check (Automatic Update)
                if svc.get('enabled', True):
                    self.logger.info(f"Auto Expiry Check for {name}...")
                    self.check_service_expiry(name)

                changes_count += 1
                
            except Exception as e:
                self.logger.error(f"Health check failed for {svc.get('name')}: {e}")
                
        self.logger.info(f"Health Check Complete. Updated {changes_count} services.")
        return True

    def check_certificates_ready(self):
        """
        Checks if certificates exist for configured services.
        Returns detailed status or boolean.
        """
        # Simple check: do we have any services?
        services = self.get_services()
        if not services: return False
        
        # Check if at least one service has a valid cert file
        # This is a loose check for the dashboard badge
        for svc in services:
             pack = svc.get('cert_pack_id') or svc.get('cert_pack')
             path, _ = self.get_cert_paths(pack)
             path, _ = self.get_cert_paths(pack)
             if os.path.exists(path): return True
        return False
