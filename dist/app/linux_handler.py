from .base_ssh_handler import BaseSSHHandler
import os

class GenericLinuxHandler(BaseSSHHandler):
    """
    Handler for Generic Linux Servers via SSH.
    Allows specifying exact remote paths for Cert and Key.
    """
    def renew(self, cert_path: str, key_path: str) -> bool:
        ssh = self._get_ssh_connection()
        if not ssh:
            return False

        remote_cert = self.config.get('remote_cert_path')
        remote_key = self.config.get('remote_key_path')
        restart_cmd = self.config.get('restart_cmd')

        if not all([remote_cert, remote_key, restart_cmd]):
            self.logger.error("Missing required config for Linux Service (remote_cert_path, remote_key_path, restart_cmd)")
            return False

        self.logger.info(f"Uploading certificates to {self.config.get('host')}...")
        
        # Upload Cert
        # Reference path for chown?
        # Ideally we want to match the folder's ownership.
        # We can extract the directory from the path.
        cert_dir = os.path.dirname(remote_cert)
        if not self._upload_to_remote(ssh, cert_path, remote_cert, owner_reference_path=cert_dir):
            return False
            
        # Upload Key
        key_dir = os.path.dirname(remote_key)
        if not self._upload_to_remote(ssh, key_path, remote_key, owner_reference_path=key_dir):
            return False

        # Restart
        return self._restart_service(ssh, restart_cmd)
