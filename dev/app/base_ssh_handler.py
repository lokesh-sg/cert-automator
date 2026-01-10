from .base_handler import CertificateHandler
from .ssh_helper import SSHHelper
import os

class BaseSSHHandler(CertificateHandler):
    """
    Base class for SSH-based handlers (Syncthing, Generic Linux).
    Provides robust upload (sudo fallback) and restart capabilities.
    """

    def _get_ssh_connection(self):
        """Initializes and returns an SSHHelper instance based on config."""
        host = self.config.get('host')
        user = self.config.get('user')
        password = self.config.get('password')
        key_path_ssh = self.config.get('ssh_key_path')

        if not all([host, user]):
            self.logger.error("Missing host or user in configuration.")
            return None

        # Validate Identity Key Path (if present)
        if key_path_ssh and not os.path.exists(key_path_ssh):
             self.logger.warning(f"SSH Identity Key configured at '{key_path_ssh}' does not exist! Ignoring it.")
             key_path_ssh = None

        return SSHHelper(host, user, password=password, key_path=key_path_ssh)

    def _upload_to_remote(self, ssh, local_path, remote_path, owner_reference_path=None):
        """
        Attempts to upload a file to a remote path.
        If direct upload fails (Permission Denied), attempts /tmp + sudo mv + sudo chown.
        
        Args:
            ssh: SSHHelper instance.
            local_path: Source file.
            remote_path: Destination path.
            owner_reference_path: Path to a file/dir to clone ownership from (for chown).
                                  If None, chown is skipped.
        """
        if ssh.upload_file(local_path, remote_path):
            return True
        
        self.logger.warning(f"Direct upload to {remote_path} failed. Attempting sudo workaround via /tmp...")
        
        filename = os.path.basename(remote_path)
        tmp_path = f"/tmp/upload_{filename}"
        password = self.config.get('password')
        
        # 1. Upload to /tmp
        if not ssh.upload_file(local_path, tmp_path):
            self.logger.error(f"Failed to upload to temporary path {tmp_path}")
            return False
            
        # Helper to run sudo cmd with fallback
        def run_sudo(cmd):
            # Try non-interactive first
            s, o = ssh.execute_command(f"sudo -n {cmd}")
            if not s and "password" in o.lower() and password:
                # Try with password
                s, o = ssh.execute_command(f"sudo -S -p '' {cmd}", stdin_input=password)
            return s, o

        # 2. Sudo Move
        move_cmd = f"mv {tmp_path} {remote_path}"
        s, o = run_sudo(move_cmd)
        
        if not s:
            self.logger.error(f"Failed to move file with sudo: {o}")
            # Try to clean up tmp
            ssh.execute_command(f"rm {tmp_path}")
            return False
            
        # 3. Fix Ownership
        if owner_reference_path:
            chown_cmd = f"chown --reference={owner_reference_path} {remote_path}"
            s2, o2 = run_sudo(chown_cmd)
            
            if not s2:
                self.logger.warning(f"Failed to fix ownership (chown) - Service might not be able to read file: {o2}")
            else:
                self.logger.info("Fixed file ownership successfully.")
        
        return True

    def _restart_service(self, ssh, restart_cmd):
        """
        Restarts a service using the provided command.
        Attempts direct execution, then sudo -n, then sudo -S (with password).
        """
        if not restart_cmd:
            return True

        self.logger.info(f"Executing Restart Command: {restart_cmd}")
        password = self.config.get('password')

        # Try direct
        success, output = ssh.execute_command(restart_cmd)
        
        # If failed, try sudo -n (non-interactive)
        if not success:
             self.logger.info("Command failed, trying sudo -n...")
             success, output = ssh.execute_command(f"sudo -n {restart_cmd}")
        
        # If failed and password required, try sudo -S (stdin password)
        # We try this regardless of the error message if sudo -n failed and we have a password,
        # because some systems might give empty or localized errors.
        if not success and password:
             self.logger.info("Command failed, trying sudo -S (with password)...")
             success, output = ssh.execute_command(f"sudo -S -p '' {restart_cmd}", stdin_input=password)

        if success:
             self.logger.info(f"Restart Output: {output.strip()}")
        else:
             self.logger.error(f"Restart Failed: {output.strip()}")
        
        return success

    def check_remote_expiry(self) -> dict:
        """
        Default SSH check: looks for 'remote_cert_path' and reads it.
        """
        remote_path = self.config.get('remote_cert_path')
        if not remote_path:
            return {"success": False, "message": "No remote_cert_path configured for SSH check"}
        
        return self._check_via_ssh(remote_path)

    def _check_via_ssh(self, remote_path: str) -> dict:
        """
        Connects via SSH, reads the file (trying sudo if needed), and parses it.
        """
        ssh = self._get_ssh_connection()
        if not ssh:
            return {"success": False, "message": "SSH Connection failed"}
            
        try:
            # 1. Read File
            cmd = f"cat {remote_path}"
            success, output = ssh.execute_command(cmd)
            
            # Sudo fallback
            if not success and ("denied" in output.lower() or "password" in output.lower()):
                password = self.config.get('password')
                # Try non-interactive sudo
                success, output = ssh.execute_command(f"sudo -n {cmd}")
                if not success and password:
                    # Try password sudo
                    success, output = ssh.execute_command(f"sudo -S -p '' {cmd}", stdin_input=password)
            
            if not success:
                return {"success": False, "message": f"Failed to read remote file: {output}"}
                
            # 2. Parse PEM
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            import datetime
            
            # The output is the PEM content string
            cert_bytes = output.encode('utf-8') 
            # Note: output might contain sudo warnings if we aren't careful, 
            # but execute_command usually separates stderr? SSHHelper implementation dependent.
            # Assuming output contains valid PEM.
            
            try:
                cert_obj = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            except Exception as e:
                # Fallback: find -----BEGIN CERTIFICATE-----
                if "-----BEGIN CERTIFICATE-----" in output:
                    start = output.find("-----BEGIN CERTIFICATE-----")
                    end = output.find("-----END CERTIFICATE-----") + 25
                    clean_pem = output[start:end]
                    cert_obj = x509.load_pem_x509_certificate(clean_pem.encode('utf-8'), default_backend())
                else:
                    raise e

            not_after = cert_obj.not_valid_after
            now = datetime.datetime.utcnow()
            days_remaining = (not_after - now).days
            
            return {
                "success": True,
                "expiry": not_after.strftime("%Y-%m-%d"),
                "days_remaining": days_remaining,
                "subject": cert_obj.subject.rfc4514_string(),
                "issuer": cert_obj.issuer.rfc4514_string()
            }
            
        except Exception as e:
            self.logger.error(f"SSH Check Error: {e}")
            return {"success": False, "message": str(e)}
