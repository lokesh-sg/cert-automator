from .base_ssh_handler import BaseSSHHandler
import os

class SyncthingHandler(BaseSSHHandler):
    def renew(self, cert_path: str, key_path: str) -> bool:
        ssh = self._get_ssh_connection()
        if not ssh:
            return False

        # In UI, we will map 'remote_cert_path' to the Config Directory for Syncthing type
        config_dir = self.config.get('remote_cert_path') 
        restart_cmd = self.config.get('restart_cmd')

        if not config_dir or not restart_cmd:
            self.logger.error("Missing config_dir or restart_cmd for Syncthing.")
            return False

        # Syncthing expects https-cert.pem and https-key.pem in the config dir
        remote_cert_file = os.path.join(config_dir, "https-cert.pem")
        remote_key_file = os.path.join(config_dir, "https-key.pem")

        self.logger.info(f"Uploading Syncthing certificates to {config_dir}...")
        
        # Upload Cert
        if not self._upload_to_remote(ssh, cert_path, remote_cert_file, owner_reference_path=config_dir):
            return False
            
        # Upload Key
        if not self._upload_to_remote(ssh, key_path, remote_key_file, owner_reference_path=config_dir):
            return False

        # Restart
        return self._restart_service(ssh, restart_cmd)

        # Syncthing expects https-cert.pem and https-key.pem in the config dir
        remote_cert_file = os.path.join(config_dir, "https-cert.pem")
        remote_key_file = os.path.join(config_dir, "https-key.pem")

        self.logger.info(f"Uploading Syncthing certificates to {config_dir}...")
        
        if not self._upload_to_remote(ssh, cert_path, remote_cert_file, config_dir):
            return False
            
        if not self._upload_to_remote(ssh, key_path, remote_key_file, config_dir):
            return False

        # Restart Service/Container
        self.logger.info(f"Restarting Syncthing: {restart_cmd}")
        # Try direct
        success, output = ssh.execute_command(restart_cmd)
        
        # If failed, try sudo -n (non-interactive)
        if not success:
             self.logger.info("Restart failed, trying sudo -n...")
             success, output = ssh.execute_command(f"sudo -n {restart_cmd}")
        
        # If failed and password required, try sudo -S (stdin password)
        if not success and ("password" in output.lower() or "permission" in output.lower()) and password:
             self.logger.info("Restart failed, trying sudo -S (with password)...")
             success, output = ssh.execute_command(f"sudo -S -p '' {restart_cmd}", stdin_input=password)

        if success:
             self.logger.info(f"Restart Output: {output.strip()}")
        else:
             self.logger.error(f"Restart Failed: {output.strip()}")
        
        return success

    def check_remote_expiry(self) -> dict:
        config_dir = self.config.get('remote_cert_path')
        if not config_dir:
             return {"success": False, "message": "No config_dir configured for Syncthing"}
             
        remote_cert = os.path.join(config_dir, "https-cert.pem")
        return self._check_via_ssh(remote_cert)

