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

        return success

    def check_remote_expiry(self) -> dict:
        config_dir = self.config.get('remote_cert_path')
        if not config_dir:
             return {"success": False, "message": "No config_dir configured for Syncthing"}
             
        remote_cert = os.path.join(config_dir, "https-cert.pem")
        return self._check_via_ssh(remote_cert)

