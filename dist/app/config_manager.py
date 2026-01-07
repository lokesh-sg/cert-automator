import yaml
import logging
import os

from .crypto_utils import CryptoManager

class ConfigManager:
    def __init__(self, config_path: str, master_password: str = None, backup_dir: str = None):
        self.config_path = config_path
        self.master_password = master_password
        self.backup_dir = backup_dir
        self.config = {}
        self.logger = logging.getLogger("CertAutomator.ConfigManager")
        self.crypto = CryptoManager(self.logger)
        self.is_locked = True
        
        # Try to load immediately if we have a password (legacy CLI / Unit Test support)
        # OR if the file doesn't exist (new system), we are effectively "unlocked" but empty.
        if self.master_password or not os.path.exists(self.config_path):
             self.load_config()

    def unlock(self, password: str) -> bool:
        """Attempts to unlock the configuration with the given password."""
        self.master_password = password
        try:
            self.load_config()
            return not self.is_locked
        except Exception:
            self.master_password = None # Reset on failure
            self.is_locked = True
            return False

    def load_config(self) -> dict:
        """
        Loads the configuration.
        """
        if not os.path.exists(self.config_path):
            self.config = {'services': []}
            self.is_locked = False # New system is open for business (will be encrypted on save)
            return self.config

        try:
            # Check if encrypted
            if self.crypto.is_encrypted(self.config_path):
                if not self.master_password:
                    self.is_locked = True
                    self.logger.info("Config is encrypted and no password provided. System LOCKED.")
                    return {} # Return empty, system is locked
                
                with open(self.config_path, 'rb') as f:
                    content = f.read()
                
                self.config = self.crypto.decrypt_data(content, self.master_password)
                self.is_locked = False
                self.logger.info("Encrypted configuration loaded successfully.")
                return self.config
            else:
                # Load Legacy Plain YAML
                self.logger.warning("Loading PLAIN TEXT configuration (Legacy).")
                with open(self.config_path, 'r') as file:
                    self.config = yaml.safe_load(file) or {'services': []}
                
                self.is_locked = False
                
                # Auto-Migrate to Encrypted
                if self.master_password:
                    self.logger.info("Migrating plain-text config to ENCRYPTED format...")
                    self.save_config() 
                    
                return self.config

        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            self.is_locked = True
            raise # Re-raise to let caller know password was probably wrong

    def get_services(self) -> list:
        """
        Returns the list of services defined in the config.
        """
        return self.config.get('services', [])

    def get_service_types(self) -> dict:
        """
        Returns the mapping of service aliases to base handler types.
        e.g. {'My Router': 'opnsense', 'Nginx': 'linux', 'proxmox': 'proxmox'}
        """
        types = self.config.get('service_types', {})
        
        # Default Types (if empty or legacy config)
        # Ensure we always have the built-ins unless explicitly deleted by user (which we can't distinguish easily from "new config")
        # So we merge defaults if keys don't exist? Or just return defaults if empty?
        # Better: Initialize config with defaults on creation.
        # Check if we have at least one known type. If not, populate defaults.
        DEFAULT_TYPES = {
            'proxmox': 'proxmox',
            'truenas': 'truenas',
            'opnsense': 'opnsense',
            'syncthing': 'syncthing',
            'wazuh': 'wazuh',
            'heimdall': 'heimdall',
            'clearpass': 'clearpass',
            'portainer': 'portainer',
            'linux': 'linux',
            'webhook': 'webhook'
        }
        
        if not types:
            self.config['service_types'] = DEFAULT_TYPES.copy()
            self.save_config()
            return self.config['service_types']
            
        return types

    def add_service_type(self, name, base_handler):
        types = self.get_service_types()
        if name in types:
            raise ValueError(f"Service type '{name}' already exists.")
        
        types[name] = base_handler
        self.config['service_types'] = types
        self.save_config()

    def remove_service_type(self, name):
        types = self.get_service_types()
        if name not in types:
            raise ValueError(f"Service type '{name}' not found.")
            
        del types[name]
        self.config['service_types'] = types
        self.save_config()

    def save_config(self):
        """Saves the current config to disk (Encrypted if password set)."""
        try:
            if self.master_password:
                # Create Backup
                import shutil
            if self.master_password:
                # Create Backup Directory
                if self.backup_dir:
                    backup_dir = self.backup_dir
                else:
                    config_dir = os.path.dirname(os.path.abspath(self.config_path))
                    backup_dir = os.path.join(config_dir, "backups", "config")
                
                if not os.path.exists(backup_dir):
                    os.makedirs(backup_dir, exist_ok=True)

                # Create Timestamped Backup
                import shutil
                import datetime
                import glob
                
                if os.path.exists(self.config_path):
                    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                    backup_filename = f"config.{timestamp}.yaml.bak"
                    backup_path = os.path.join(backup_dir, backup_filename)
                    
                    try:
                        shutil.copy2(self.config_path, backup_path)
                        self.logger.info(f"Backup created at {backup_path}")
                        
                        # Retention Policy: Keep last 20
                        backups = sorted(glob.glob(os.path.join(backup_dir, "config.*.yaml.bak")))
                        if len(backups) > 20:
                            for old_backup in backups[:-20]:
                                try:
                                    os.remove(old_backup)
                                    self.logger.info(f"Rotated old backup: {old_backup}")
                                except Exception as e:
                                    self.logger.warning(f"Failed to delete old backup {old_backup}: {e}")
                                    
                    except Exception as e:
                        self.logger.error(f"Failed to create backup: {e}")

                # Encrypted Save
                encrypted_bytes = self.crypto.encrypt_data(self.config, self.master_password)
                with open(self.config_path, 'wb') as f:
                    f.write(encrypted_bytes)
                self.logger.info("Configuration saved (Encrypted).")
            else:
                # Fallback Plain Save (Should ideally verify this flow doesn't happen in prod)
                self.logger.warning("Saving configuration in PLAIN TEXT (No Master Password set).")
                with open(self.config_path, 'w') as f:
                    yaml.dump(self.config, f, sort_keys=False, default_flow_style=False)
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")
            raise

    def validate_service_data(self, data: dict):
        """Strict validation for service configuration data."""
        required = ['name', 'host', 'type']
        for field in required:
            if not data.get(field):
                raise ValueError(f"Missing required field: {field}")
        
        # Sanitization: Ensure name is safe for filenames just in case
        from werkzeug.utils import secure_filename
        data['name'] = secure_filename(data['name'])
        if not data['name']:
            raise ValueError("Invalid service name provided")
            
        return data

    def add_service(self, service_data):
        service_data = self.validate_service_data(service_data)
        services = self.get_services()
        # Check duplicate name
        if any(s.get('name') == service_data.get('name') for s in services):
            raise ValueError("Service name already exists")
        
        services.append(service_data)
        self.config['services'] = services
        self.save_config()

    def update_service(self, name, new_data):
        # Note: new_data might be a partial update (e.g. just status)
        # However, for API-driven updates of the core config, we want validation if the key fields are present.
        if any(k in new_data for k in ['name', 'host', 'type']):
            # We need the full object to validate properly if we are changing core fields
            # Fetch existing to merge and validate
            services = self.get_services()
            current = next((s for s in services if s.get('name') == name), None)
            if current:
                temp = current.copy()
                temp.update(new_data)
                self.validate_service_data(temp)
        
        services = self.get_services()
        found = False
        for i, s in enumerate(services):
            if s.get('name') == name:
                # Merge or Replace? User said "modify name and ip".
                # If name changes, we need to handle that carefully.
                # Assuming simple replace for now, but keeping preserved fields might be better.
                # Let's merge: update existing dict with new_data
                services[i].update(new_data)
                found = True
                break
        
        if not found:
            raise ValueError("Service not found")
        
        self.config['services'] = services
        self.save_config()

    def delete_service(self, name):
        services = self.get_services()
        initial_len = len(services)
        services = [s for s in services if s.get('name') != name]
        
        if len(services) == initial_len:
            raise ValueError("Service not found")
            
        self.config['services'] = services
        self.save_config()
