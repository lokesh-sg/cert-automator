from .base_handler import CertificateHandler
from .ssh_helper import SSHHelper

class SSHHandler(CertificateHandler):
    def renew(self, cert_path: str, key_path: str) -> bool:
        host = self.config.get('host')
        user = self.config.get('user')
        password = self.config.get('password') # Optional if key is used
        ssh_key = self.config.get('ssh_key_path') # Optional
        
        remote_cert_path = self.config.get('remote_cert_path')
        remote_key_path = self.config.get('remote_key_path')
        restart_cmd = self.config.get('restart_cmd')
        
        if not all([host, user, remote_cert_path, remote_key_path]):
            self.logger.error("Missing required config for SSH (host, user, remote_cert_path, remote_key_path)")
            return False
            
        helper = SSHHelper(host, user, key_path=ssh_key, password=password)
        
        # 1. Upload Cert
        if not helper.upload_file(cert_path, remote_cert_path):
            return False
            
        # 2. Upload Key
        if not helper.upload_file(key_path, remote_key_path):
            return False
            
        # 3. Restart Command
        if restart_cmd:
            success, output = helper.execute_command(restart_cmd)
            if not success:
                self.logger.error(f"Restart command failed: {output}")
                return False
                
        self.logger.info(f"Successfully updated certificate via SSH on {host}")
        return True
