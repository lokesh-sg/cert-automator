import os
import tempfile
import json
from .base_source import CertificateSource
from .ssh_helper import SSHHelper

class NginxProxyManagerSource(CertificateSource):
    """
    Pulls certificates from an Nginx Proxy Manager (NPM) instance via SSH.
    Assumes standard NPM directory structure: /etc/letsencrypt/live/npm-[id]/
    We need a way to map a domain to the correct npm-[id] folder.
    NPM stores this mapping in its SQLite or MySQL DB, but for a simpler generic pull:
    If the user knows the domain, we can grep the /etc/letsencrypt/live/npm-*/README 
    or just find the folder containing the cert for that domain.
    """
    
    def pull_certificate(self):
        host = self.config.get('host')
        user = self.config.get('user')
        password = self.config.get('password')
        domain = self.config.get('domain')
        
        is_docker = self.config.get('is_docker', False)
        container = self.config.get('container_name', 'nginx-proxy-manager')
        
        self.logger.info(f"Connecting via SSH to NPM at {host} to pull certificate for {domain}...")
        ssh = SSHHelper(host, user, password=password)
        
        try:
            def run_npm_cmd(raw_cmd):
                if is_docker:
                    # Try docker exec directly, fallback to sudo docker exec
                    cmd = f"docker exec {container} {raw_cmd}"
                    ok, out = ssh.execute_command(cmd, log_errors=False)
                    if not ok:
                        ok, out = ssh.execute_sudo_command(cmd)
                    return ok, out
                else:
                    return ssh.execute_sudo_command(raw_cmd)

            find_script = f"bash -c 'for d in $(ls -td /etc/letsencrypt/live/npm-*/ 2>/dev/null); do if openssl x509 -in \"${{d}}fullchain.pem\" -noout -ext subjectAltName 2>/dev/null | grep -q \"{domain}\"; then echo $d; exit 0; fi; done'"
            
            success, stdout = run_npm_cmd(find_script)
            
            if not success or not stdout.strip():
                return {
                    "success": False, 
                    "message": f"Could not locate a certificate for domain '{domain}' on NPM server.",
                    "changed": False
                }
                
            cert_dir = stdout.strip()
            self.logger.info(f"Found certificate directory: {cert_dir}")
            
            # Read the files
            c_success, c_out = run_npm_cmd(f"cat {cert_dir}fullchain.pem")
            k_success, k_out = run_npm_cmd(f"cat {cert_dir}privkey.pem")
            
            if not c_success or not k_success:
                 return {
                    "success": False, 
                    "message": f"Failed to read certificate files from {cert_dir}. Permission denied?",
                    "changed": False
                }
                
            cert_data = c_out.encode('utf-8')
            key_data = k_out.encode('utf-8')

            return {
                "success": True,
                "message": f"Successfully pulled certificate for {domain}",
                "cert_data": cert_data,
                "key_data": key_data,
                "changed": True # The manager will hash and diff this later to see if it actually changed
            }
                
        except Exception as e:
            self.logger.error(f"Failed to pull from NPM: {e}")
            return {"success": False, "message": f"SSH Error: {e}", "changed": False}
