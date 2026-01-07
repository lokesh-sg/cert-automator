from .base_handler import CertificateHandler
from .ssh_helper import SSHHelper

class WazuhHandler(CertificateHandler):
    def renew(self, cert_path: str, key_path: str) -> bool:
        host = self.config.get('host')
        user = self.config.get('ssh_user')
        key_path_ssh = self.config.get('ssh_key_path')
        
        # Target paths from user request
        target_cert_path = self.config.get('cert_path', '/etc/wazuh-dashboard/certs/fullchain1.pem')
        target_key_path = self.config.get('key_path', '/etc/wazuh-dashboard/certs/privkey1.pem')
        
        if not all([host, user]):
            self.logger.error("Missing required config for Wazuh (host, ssh_user)")
            return False

        ssh = SSHHelper(host, user, key_path=key_path_ssh)

        self.logger.info("Uploading certificates to Wazuh dashboard...")
        # Note: Writing to /etc usually requires root. User should provide root user or user with permission.
        if not ssh.upload_file(cert_path, target_cert_path):
            return False
        if not ssh.upload_file(key_path, target_key_path):
            return False

        # Restart service
        restart_cmd = "systemctl restart wazuh-dashboard"
        self.logger.info(f"Restarting Wazuh Dashboard: {restart_cmd}")
        success, output = ssh.execute_command(restart_cmd)
        
        return success
