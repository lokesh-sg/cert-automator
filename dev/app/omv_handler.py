from .base_ssh_handler import BaseSSHHandler
import re
import os
import tempfile

# Embedded Helper Script
OMV_HELPER_SCRIPT = r"""#!/bin/bash
set -e

# omv_cert_helper.sh
# Helper script to update OpenMediaVault SSL Certificates via CLI.
# Usage: sudo ./omv_cert_helper.sh <UUID> <CERT_FILE> <KEY_FILE>

UUID=$1
CERT_FILE=$2
KEY_FILE=$3

if [ -z "$UUID" ] || [ -z "$CERT_FILE" ] || [ -z "$KEY_FILE" ]; then
    echo "Usage: $0 <UUID> <CERT_FILE> <KEY_FILE>"
    exit 1
fi

echo "--- OMV Certificate Import Helper ---"
echo "Target UUID: $UUID"

# We use embedded Python to safely handle JSON and piping to omv-confdbadm
# Capturing stderr to stdout for visibility
python3 -c "
import sys
import json
import subprocess

uuid = '$UUID'
cert_path = '$CERT_FILE'
key_path = '$KEY_FILE'

try:
    with open(cert_path, 'r') as f:
        cert_content = f.read()
    with open(key_path, 'r') as f:
        key_content = f.read()

    print(f'Read Certificate: {len(cert_content)} bytes')
    print(f'Read Private Key: {len(key_content)} bytes')

    import datetime
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    comment_str = f'CertAutomator Renewed: {timestamp}'

    # Construct the JSON payload for omv-confdbadm
    payload = {
        'uuid': uuid,
        'certificate': cert_content,
        'privatekey': key_content,
        'comment': comment_str
    }
    
    json_str = json.dumps(payload)
    
    print('Updating OMV Database...')
    # omv-confdbadm update conf.system.certificate.ssl <JSON_DATA>
    cmd = ['omv-confdbadm', 'update', 'conf.system.certificate.ssl', json_str]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    if process.returncode != 0:
        print(f'Database update failed: {stderr.decode()}')
        sys.exit(1)
        
    print('Database updated successfully.')

except Exception as e:
    print(f'Error: {e}')
    sys.exit(1)
" 2>&1

if [ $? -ne 0 ]; then
    echo "Python helper failed."
    exit 1
fi

# 2. Force Update Files on Disk
# It seems omv-salt deploy doesn't always rewrite the cert files from DB immediately.
# We manually overwrite them to ensure Nginx sees the new content.
TARGET_CERT="/etc/ssl/certs/openmediavault-${UUID}.crt"
TARGET_KEY="/etc/ssl/private/openmediavault-${UUID}.key"

echo "Manually updating certificate files..."
echo "Copying to $TARGET_CERT"
cp -f "$CERT_FILE" "$TARGET_CERT"
chmod 644 "$TARGET_CERT"

echo "Copying to $TARGET_KEY"
cp -f "$KEY_FILE" "$TARGET_KEY"
chmod 600 "$TARGET_KEY"
# Try to set group to ssl-cert if it exists, otherwise root
chown root:ssl-cert "$TARGET_KEY" 2>/dev/null || chown root:root "$TARGET_KEY"

# 3. Deploy Changes
echo "Deploying changes via omv-salt... (This may take a moment)"
omv-salt deploy run nginx 2>&1

# 4. Explicit Service Restart (Just in case salt didn't kick it)
echo "Restarting Nginx..."
systemctl restart nginx

echo "Verification - File Details:"
ls -l $TARGET_CERT

echo "Done."
"""

class OpenMediaVaultHandler(BaseSSHHandler):
    """
    Handler for OpenMediaVault (OMV) - Script Based - Zero Config.
    Strategy: "Auto-Deploy Helper Script"
    1. Auto-upload embedded helper script to remote /tmp.
    2. Upload certs to /tmp.
    3. Execute helper script via sudo to update OMV database.
    4. Cleanup.
    """

    def renew(self, cert_path, key_path):
        self.logger.info("Starting OpenMediaVault Renewal Process (Auto-Deploy Mode)...")
        
        ssh = self._get_ssh_connection()
        if not ssh:
            return False

        try:
            # 1. Discover UUID
            uuid = self.config.get('uuid')
            if not uuid:
                uuid = self._get_active_cert_uuid(ssh)
            
            if not uuid:
                self.logger.error("Could not discover active SSL UUID. Cannot proceed.")
                return False
            
            # Security: Validate UUID format to prevent shell injection
            if not re.match(r'^[0-9a-fA-F\-]{36}$', uuid):
                self.logger.error(f"Invalid UUID format detected: {uuid}")
                return False

            self.logger.info(f"Targeting Certificate UUID: {uuid}")

            # Define Temp Paths
            remote_cert_tmp = f"/tmp/cert_{uuid}.pem"
            remote_key_tmp = f"/tmp/key_{uuid}.pem"
            remote_script_path = "/tmp/omv_cert_helper.sh"

            # 2. Upload Helper Script
            self.logger.info("Deploying helper script...")
            if not self._deploy_helper_script(ssh, remote_script_path):
                return False

            # 3. Upload Certs to Temp
            self.logger.info(f"Uploading temporary files to {remote_cert_tmp}...")
            if not self._upload_to_remote(ssh, cert_path, remote_cert_tmp):
                return False
            
            if not self._upload_to_remote(ssh, key_path, remote_key_tmp):
                return False

            # Secure Temp Key
            ssh.execute_command(f"chmod 600 {remote_key_tmp}")

            # 4. Execute Script
            self.logger.info("Executing OMV Helper Script...")
            # Usage: sudo /tmp/omv_cert_helper.sh <UUID> <CERT> <KEY>
            cmd = f"sudo {remote_script_path} {uuid} {remote_cert_tmp} {remote_key_tmp}"
            
            # Use _restart_service logic for sudo handling (interactive password support)
            # Note: _restart_service logs output.
            if self._restart_service(ssh, cmd):
                self.logger.info("Script execution successful. Verifying remote file content...")
                
                # 5. POST-RENEWAL VERIFICATION
                # Read the remote file and compare serial/expiry with the local one we just sent
                remote_cert_path = f"/etc/ssl/certs/openmediavault-{uuid}.crt"
                
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                # Load Local
                with open(cert_path, 'rb') as f:
                    local_cert_obj = x509.load_pem_x509_certificate(f.read(), default_backend())
                
                # Load Remote via SSH
                check_res = self._check_via_ssh(remote_cert_path)
                if not check_res['success']:
                    self.logger.error(f"Verification Failed: Could not read remote file: {check_res['message']}")
                    return False
                
                # We can't get the object directly from _check_via_ssh easily provided existing method signature,
                # but we can parse the output if we refactor, or just trust 'expiry' is updated?
                # Better: Read raw again to be precise.
                
                cat_cmd = f"cat {remote_cert_path}"
                s, o = ssh.execute_command(cat_cmd)
                if not s:
                     # Try sudo
                    s, o = ssh.execute_command(f"sudo -n {cat_cmd}")
                    
                if s:
                    try:
                        remote_cert_obj = x509.load_pem_x509_certificate(o.encode(), default_backend())
                        if remote_cert_obj.serial_number == local_cert_obj.serial_number:
                            self.logger.info("Verification SUCCESS: Remote certificate serial matches local.")
                            self.logger.info("OpenMediaVault Renewal Complete.")
                            return True
                        else:
                            self.logger.error(f"Verification FAILED: Serial mismatch. Remote: {remote_cert_obj.serial_number}, Local: {local_cert_obj.serial_number}")
                            self.logger.error("The file on disk does not match the new certificate!")
                            return False
                    except Exception as e:
                        self.logger.error(f"Verification Check Error: {e}")
                        return False
                else:
                    self.logger.error("Verification Failed: Could not read remote certificate for comparison.")
                    return False

            else:
                self.logger.error("Helper script execution failed.")
                return False
        finally:
            # Cleanup
            try:
                ssh.execute_command(f"rm {remote_cert_tmp} {remote_key_tmp} {remote_script_path}")
            except:
                pass

    def _deploy_helper_script(self, ssh, remote_path):
        """
        Writes the embedded script to a local temp file, uploads it, and makes it executable.
        """
        local_tmp = None
        try:
            # Create local temp file
            fd, local_tmp = tempfile.mkstemp()
            with os.fdopen(fd, 'w') as f:
                f.write(OMV_HELPER_SCRIPT)
            
            # Upload
            if not self._upload_to_remote(ssh, local_tmp, remote_path):
                self.logger.error("Failed to upload helper script.")
                return False
            
            # Make executable
            ssh.execute_command(f"chmod +x {remote_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deploying helper script: {e}")
            return False
        finally:
            if local_tmp and os.path.exists(local_tmp):
                os.remove(local_tmp)

    def _get_active_cert_uuid(self, ssh):
        """
        Discovers the active certificate UUID by listing all SSL configs from the database
        and correlating with the most recently accessed/modified certificate file on disk.
        """
        self.logger.info("Discovering SSL UUID via omv-confdbadm list...")
        
        # 1. Get all SSL certificates from DB
        cmd = "omv-confdbadm read conf.system.certificate.ssl"
        success, output = ssh.execute_command(cmd)
        
        # Sudo handling
        if not success or "permission" in output.lower():
            self.logger.info("omv-confdbadm requires sudo...")
            password = self.config.get('password')
            success, output = ssh.execute_command(f"sudo -n {cmd}")
            if not success and password:
                 success, output = ssh.execute_command(f"sudo -S -p '' {cmd}", stdin_input=password)
        
        if not success:
            self.logger.error(f"Failed to list SSL certs from DB: {output}")
            return None

        try:
            import json
            # Output is a JSON list of objects
            certs = json.loads(output)
            
            if not certs:
                self.logger.error("No SSL certificates found in OMV database.")
                return None
                
            if isinstance(certs, dict):
                 # Single item return? Wrap it.
                 certs = [certs]
            
            # If only one cert exists, that's likely the one.
            if len(certs) == 1:
                uuid = certs[0].get('uuid')
                self.logger.info(f"Only one SSL cert found in DB. Using it: {uuid}")
                return uuid
            
            self.logger.info(f"Found {len(certs)} certificates in DB. correlating with filesystem...")
            
            # 2. Correlate with files to find the 'active' one (most recently used)
            # We list the file associated with each UUID and check timestamps
            
            best_uuid = None
            newest_ts = 0
            
            for cert in certs:
                uuid = cert.get('uuid')
                # OMV stores them as openmediavault-<uuid>.crt/key usually, 
                # OR we can assume the one referenced by nginx is actively read.
                
                # Check file modification time
                check_cmd = f"stat -c %Y /etc/ssl/certs/openmediavault-{uuid}.crt"
                s, o = ssh.execute_command(check_cmd)
                if not s:
                     # Try sudo
                    s, o = ssh.execute_command(f"sudo -n {check_cmd}")
                
                if s and o.strip().isdigit():
                    ts = int(o.strip())
                    if ts > newest_ts:
                        newest_ts = ts
                        best_uuid = uuid
            
            if best_uuid:
                self.logger.info(f"Identified active UUID based on file timestamp: {best_uuid}")
                return best_uuid
            
            # Fallback: Just return the first one
            self.logger.warning("Could not correlate timestamps. Defaulting to first certificate.")
            return certs[0].get('uuid')

        except Exception as e:
            self.logger.error(f"Failed to process OMV cert list: {e}")
            return None

    def check_remote_expiry(self):
        """
        Overrides BaseSSHHandler check to perform auto-discovery of the cert path
        before reading via SSH.
        """
        ssh = self._get_ssh_connection()
        if not ssh:
            return {"success": False, "message": "SSH Connection failed"}
            
        try:
            # 1. Discover UUID
            uuid = self.config.get('uuid')
            if not uuid:
                uuid = self._get_active_cert_uuid(ssh)
                
            if not uuid:
                 return {"success": False, "message": "Could not discover active OMV SSL UUID"}
            
            # 2. Construct Path
            remote_cert = f"/etc/ssl/certs/openmediavault-{uuid}.crt"
            self.logger.info(f"Checking remote OMV cert at: {remote_cert}")
            
            return self._check_via_ssh(remote_cert)
            
        except Exception as e:
            return {"success": False, "message": f"OMV Check Error: {e}"}
