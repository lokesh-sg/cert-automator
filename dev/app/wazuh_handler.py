from .base_ssh_handler import BaseSSHHandler
import re
import os
import tempfile

class WazuhHandler(BaseSSHHandler):
    """
    Handler for Wazuh Dashboard.
    Default Paths: /etc/wazuh-dashboard/certs/
    Default Service: wazuh-dashboard
    """
    
    def renew(self, cert_path: str, key_path: str) -> bool:
        # 1. Config & Defaults
        target_cert_path = self.config.get('cert_path', '/etc/wazuh-dashboard/certs/fullchain.pem')
        target_key_path = self.config.get('key_path', '/etc/wazuh-dashboard/certs/privkey.pem')
        restart_cmd = self.config.get('restart_cmd', 'systemctl restart wazuh-dashboard')

        self.logger.info(f"Starting Wazuh Renewal for {self.config.get('host')}...")
        self.logger.info(f"Target Cert: {target_cert_path}")
        self.logger.info(f"Target Key: {target_key_path}")

        # 2. Connect
        ssh = self._get_ssh_connection()
        if not ssh:
            return False

        # 3. Upload Files (Robust Sudo)
        # We try to preserve ownership if the file exists, otherwise root:wazuh is common, 
        # but sudo cp usually preserves destination ownership or root. 
        # BaseSSHHandler auto-fixes ownership if we give it a reference, 
        # but here simply replacing them should be fine if directory permissions are correct.
        # Ideally wazuh-dashboard runs as wazuh user? 
        # Let's trust BaseSSHHandler's _upload_to_remote to handle the "how".
        
        if not self._upload_to_remote(ssh, cert_path, target_cert_path):
            self.logger.error("Failed to upload certificate.")
            return False
            
        if not self._upload_to_remote(ssh, key_path, target_key_path):
            self.logger.error("Failed to upload private key.")
            return False

        # 3.5. Fix Permissions
        # Wazuh is strict about permissions.
        # User requested: chown wazuh-dashboard:wazuh-dashboard <file> && chmod 440 <file>
        # AND directory permissions: chmod 500 /certs/
        
        cert_dir = os.path.dirname(target_cert_path)
        
        fix_cmds = [
            # Fix Directory First
            f"chown wazuh-dashboard:wazuh-dashboard {cert_dir}",
            f"chmod 500 {cert_dir}",
            # Fix Files
            f"chown wazuh-dashboard:wazuh-dashboard {target_cert_path} {target_key_path}",
            f"chmod 440 {target_cert_path} {target_key_path}"
        ]
        
        for cmd in fix_cmds:
            s, o = ssh.execute_sudo_command(cmd)
            if not s:
                 self.logger.warning(f"Failed to fix permissions ({cmd}): {o}")
            else:
                 self.logger.info(f"Fixed permissions: {cmd}")

        # 3.75 Ensure Config Matches
        if not self._ensure_config_matches(ssh, target_cert_path, target_key_path):
             self.logger.warning("Failed to auto-update configuration. Renewal might default to old paths.")

        # 4. Restart Service
        if not self._restart_service(ssh, restart_cmd):
            self.logger.error("Failed to restart Wazuh Dashboard.")
            return False

        return True

    def check_remote_expiry(self) -> dict:
        """
        Custom expiry check to ensure we default to the standard path if not configured.
        """
        if not self.config.get('remote_cert_path'):
            # Default to the same one we renew
            self.config['remote_cert_path'] = self.config.get('cert_path', '/etc/wazuh-dashboard/certs/fullchain.pem')
            
        return super().check_remote_expiry()

    def _ensure_config_matches(self, ssh, target_cert, target_key) -> bool:
        """
        Reads /etc/wazuh-dashboard/opensearch_dashboards.yml and ensures
        server.ssl.key and server.ssl.certificate point to the files we just uploaded.
        Preserves comments and structure using regex.
        """
        config_path = "/etc/wazuh-dashboard/opensearch_dashboards.yml"
        
        # 1. Read Remote Config
        s, content = ssh.execute_command(f"cat {config_path}", log_errors=False)
        if not s:
            s, content = ssh.execute_sudo_command(f"cat {config_path}")

        if not s:
            self.logger.error(f"Could not read config file {config_path}: {content}")
            return False

        original_content = content
        
        # 2. Check and Replace
        def replace_yaml_value(text, key, new_value):
            pattern = rf'(^\s*{re.escape(key)}\s*:\s*)(["\']?.*?["\']?)(?=\s*(?:#.*)?$)'
            replacement = f'\\1"{new_value}"'
            return re.sub(pattern, replacement, text, flags=re.MULTILINE)

        new_content = replace_yaml_value(content, "server.ssl.certificate", target_cert)
        new_content = replace_yaml_value(new_content, "server.ssl.key", target_key)
        
        if new_content == original_content:
            self.logger.info("Wazuh configuration already matches verified paths.")
            return True
            
        self.logger.info("Updating Wazuh configuration to match new certificate paths...")
        
        # 3. Write Back (Robustly)
        fd, local_temp = tempfile.mkstemp()
        try:
             with os.fdopen(fd, 'w') as f:
                 f.write(new_content)
             
             # Upload to remote /tmp/
             remote_tmp = "/tmp/wazuh_config_update.yml"
             if not ssh.upload_file(local_temp, remote_tmp):
                 self.logger.error("Failed to upload updated config.")
                 return False
                 
             # Move into place with sudo
             move_cmd = f"mv {remote_tmp} {config_path}"
             s, o = ssh.execute_sudo_command(move_cmd)
                 
             if not s:
                 self.logger.error(f"Failed to overwrite config: {o}")
                 return False
                 
             self.logger.info("Successfully updated opensearch_dashboards.yml")
             return True
             
        finally:
             if os.path.exists(local_temp):
                 os.remove(local_temp)
