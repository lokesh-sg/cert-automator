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
from .omv_handler import OpenMediaVaultHandler

from .npm_source import NginxProxyManagerSource
from .acme_source import AcmeSource

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
    'webhook': GenericWebhookHandler,
    'omv': OpenMediaVaultHandler
}

SOURCES = {
    'npm': NginxProxyManagerSource,
    'acme': AcmeSource
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
        """Returns a list of available certificate packs with details."""
        root_path = os.path.abspath(self.cert_dir)
        packs = []
        
        # Helper to get details
        def get_pack_details(pack_id, pack_path):
            details = {
                "id": pack_id,
                "name": pack_id if pack_id != 'default' else "Default (Root)",
                "path": pack_path,
                "expiry": None,
                "days_remaining": None
            }
            
            try:
                cert_path = os.path.join(pack_path, "fullchain.pem")
                if os.path.exists(cert_path):
                    with open(cert_path, 'rb') as f:
                        cert_data = f.read()
                    
                    cert_obj = self.validator.load_cert(cert_data)
                    if cert_obj:
                        info = self.validator.get_cert_details(cert_obj)
                        details['expiry'] = info.get('expiry')
                        details['days_remaining'] = info.get('days_remaining')
            except Exception as e:
                self.logger.error(f"Failed to get details for pack {pack_id}: {e}")
                
            return details

        # 1. Default Pack
        packs.append(get_pack_details("default", root_path))
        
        # 2. Subdirectories
        if os.path.exists(self.cert_dir):
            for item in os.listdir(self.cert_dir):
                item_path = os.path.join(self.cert_dir, item)
                if os.path.isdir(item_path) and not item.startswith('.'):
                    packs.append(get_pack_details(item, os.path.abspath(item_path)))
                    
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
                self.logger.info(f"Renewal success for {service_name}. verifying propagation...")
                import time
                time.sleep(3) # Increased wait for service restart
                
                # Force a check which updates config
                check_res = self.check_service_expiry(service_name)
                
                if check_res.get('success'):
                    # Double conversion to ensure UI picks it up
                    days = check_res.get('days_remaining')
                    self.logger.info(f"Post-renewal verified: {days} days remaining.")
                else:
                    self.logger.warning(f"Post-renewal verification failed: {check_res.get('message')}")
            
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
        # Fix: Do not block on global 'Default' cert check. Let each service check its own pack.
        # if not self.validate_certs():
        #    return {"error": "Certificates not found"}

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
        self.logger.info("Running Global Health Check (Local + Remote + Sources)...")
        # 0. Process Certificate Sources First (The "Pull" Upgrade)
        sources = self.config_mgr.get_sources()
        renewed_packs = []
        for src in sources:
            src_id = src.get('id')
            self.logger.info(f"Triggering automatic pull for source: {src.get('name')} ({src_id})")
            pull_result = self.pull_certificate_from_source(src_id)
            if pull_result.get('success') and pull_result.get('changed'):
                self.logger.info(f"Source {src_id} pulled a NEW certificate!")
                if 'pack_name' in pull_result:
                    renewed_packs.append(pull_result['pack_name'])
            elif pull_result.get('success'):
                self.logger.info(f"Source {src_id} checked successfully, no changes.")
            else:
                self.logger.warning(f"Source {src_id} failed: {pull_result.get('message')}")

        # 1. Process Services
        services = self.get_services()
        changes_count = 0
        import datetime
        
        for svc in services:
            try:
                name = svc.get('name')
                
                # Auto-Sync: If this service uses a pack that was just renewed, force a push!
                pack = svc.get('cert_pack_id') or svc.get('cert_pack')
                if pack and pack in renewed_packs and svc.get('enabled', True):
                    self.logger.info(f"Auto-Sync Tracking: Pack '{pack}' was just updated. Instantly pushing to service '{name}'...")
                    self.renew_service(name)
                    changes_count += 1
                
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

    def check_certificates_status(self):
        """
        Returns a detailed status of all certificate packs.
        """
        packs = self.list_cert_packs()
        
        default_exists = False
        default_ready = False
        expired_count = 0
        total_packs = len(packs)
        
        for p in packs:
            # Existence check (must have expiry parsed)
            if p['id'] == 'default' and p.get('expiry'):
                default_exists = True
                if p.get('days_remaining', 0) > 0:
                    default_ready = True
            
            # Expiry check
            if p.get('days_remaining') is not None and p.get('days_remaining') <= 0:
                expired_count += 1
                
        # Global "ready" means default exists AND nothing is expired
        global_ready = default_ready and expired_count == 0
        
        return {
            "default_exists": default_exists,
            "default_ready": default_ready,
            "total_packs": total_packs,
            "expired_packs": expired_count,
            "ready": global_ready
        }


    def check_certificates_ready(self):
        status = self.check_certificates_status()
        return status["default_ready"]

    def pull_certificate_from_source(self, source_id):
        """Pulls a certificate from a defined source and saves it as a pack."""
        sources = self.config_mgr.get_sources()
        target = next((s for s in sources if s.get('id') == source_id), None)
        
        if not target:
            return {"success": False, "message": "Source not found", "changed": False}
            
        src_type = target.get('type')
        source_cls = SOURCES.get(src_type)
        if not source_cls:
            return {"success": False, "message": f"Unknown source type: {src_type}", "changed": False}
            
        try:
            handler = source_cls(target)
            result = handler.pull_certificate()
            
            if result.get('success'):
                # We got cert data -> save it as a pack named after the source ID
                # or domain if preferred. Let's use ID to keep it 1:1.
                pack_name = source_id if source_id.startswith('src-') else f"src-{source_id}"
                cert_data = result.get('cert_data')
                key_data = result.get('key_data')
                
                if cert_data and key_data:
                    import os, hashlib
                    pack_dir = os.path.join(self.cert_dir, pack_name)
                    existing_cert_path = os.path.join(pack_dir, "fullchain.pem")
                    
                    is_changed = True
                    if os.path.exists(existing_cert_path):
                        try:
                            with open(existing_cert_path, "rb") as f:
                                existing_cert_data = f.read()
                            if hashlib.sha256(existing_cert_data).hexdigest() == hashlib.sha256(cert_data).hexdigest():
                                is_changed = False
                        except Exception as e:
                            self.logger.warning(f"Could not read existing cert to diff: {e}")
                            
                    if is_changed:
                        saved_name = self.save_cert_pack(pack_name, cert_data, key_data)
                        self.logger.info(f"Source {source_id} saved to pack {saved_name} (New Certificate Data).")
                        result['pack_name'] = saved_name
                        result['changed'] = True
                    else:
                        self.logger.info(f"Source {source_id} certificate is identical to existing pack. Skipping auto-sync downstream.")
                        result['pack_name'] = pack_name
                        result['changed'] = False
                    
                import datetime
                status_data = {
                    "last_pull": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "status": "Success",
                    "message": result.get('message')
                }
                self.config_mgr.update_source(source_id, {"status_info": status_data})
                
            else:
                import datetime
                status_data = {
                    "last_pull": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "status": "Failed",
                    "message": result.get('message')
                }
                self.config_mgr.update_source(source_id, {"status_info": status_data})
                
            # Remove raw bytes from the response before returning to avoid JSON serialization errors
            result.pop('cert_data', None)
            result.pop('key_data', None)
            return result
        except Exception as e:
            self.logger.exception(f"Error pulling from source {source_id}: {e}")
            import datetime
            status_data = {
                "last_pull": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "Failed",
                "message": str(e)
            }
            try:
                self.config_mgr.update_source(source_id, {"status_info": status_data})
            except: pass
            
            return {"success": False, "message": str(e), "changed": False}
