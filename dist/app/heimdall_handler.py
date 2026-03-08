from .base_handler import CertificateHandler
from .ssh_helper import SSHHelper

class HeimdallHandler(CertificateHandler):
    def renew(self, cert_path: str, key_path: str) -> bool:
        host = self.config.get('host')
        user = self.config.get('ssh_user')
        key_path_ssh = self.config.get('ssh_key_path')
        
        target_cert_path = self.config.get('cert_path', '/data/heimdall/config/keys/fullchain1.pem')
        target_key_path = self.config.get('key_path', '/data/heimdall/config/keys/privkey1.pem')
        
        if not all([host, user]):
            self.logger.error("Missing required config for Heimdall (host, ssh_user)")
            return False

        ssh = SSHHelper(host, user, key_path=key_path_ssh)

        self.logger.info("Uploading certificates to Heimdall host...")
        if not ssh.upload_file(cert_path, target_cert_path):
            return False
        if not ssh.upload_file(key_path, target_key_path):
            return False

        # Check if we need to restart a container
        container_name = self.config.get('container_name')
        if container_name:
            restart_cmd = f"docker restart {container_name}"
            self.logger.info(f"Restarting Heimdall container: {restart_cmd}")
            success, output = ssh.execute_command(restart_cmd)
            return success
        else:
            self.logger.info("Certificates uploaded. No container_name provided to restart.")
            return True
