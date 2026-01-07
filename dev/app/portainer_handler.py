from .base_ssh_handler import BaseSSHHandler
import os

class PortainerHandler(BaseSSHHandler):
    def renew(self, cert_path: str, key_path: str) -> bool:
        ssh = self._get_ssh_connection()
        if not ssh:
            return False

        remote_cert = self.config.get('remote_cert_path')
        remote_key = self.config.get('remote_key_path')
        restart_cmd = self.config.get('restart_cmd')

        self.logger.info(f"Uploading Portainer certificates to {self.config.get('host')}...")
        
        # Determine base directory for ownership fix
        target_dir = os.path.dirname(remote_cert)

        # Upload Cert
        if not self._upload_to_remote(ssh, cert_path, remote_cert, owner_reference_path=target_dir):
            return False
            
        # Upload Key
        if not self._upload_to_remote(ssh, key_path, remote_key, owner_reference_path=target_dir):
            return False

        # Restart
        return self._restart_service(ssh, restart_cmd)

    def check_remote_expiry(self) -> dict:
        from .network_utils import check_ssl_expiry
        host = self.config.get('host')
        # Portainer usually 9443 for HTTPS API
        return check_ssl_expiry(host, port=9443)

    @staticmethod
    def provision_token(host, user, password):
        """
        Authenticates via /api/auth to get JWT.
        Returns: jwt_token (str)
        """
        import requests
        try:
            # Portainer API: POST /api/auth
            # Body: { Username, Password }
            # Resp: { jwt: ... }
            if "://" not in host:
                host = f"https://{host}:9443" # Default port if not specified? Or assume user puts port. Portainer is usually 9000 (http) or 9443 (https)
            
            # Simple heuristic: if no port in string, try 9443
            if ':' not in host.split('//')[-1]:
                 host = f"{host}:9443"

            resp = requests.post(
                f"{host}/api/auth",
                json={"Username": user, "Password": password},
                verify=False
            )
            
            if resp.status_code != 200:
                raise Exception(f"Authentication failed: {resp.text}")
            
            return resp.json()['jwt']
        except Exception as e:
            raise Exception(f"Portainer Provisioning Error: {e}")

    @staticmethod
    def detect_paths(host, user, password):
        """
        Uses SSH to inspect the running Portainer container.
        """
        from .ssh_helper import SSHHelper
        import json
        
        try:
            # Fix: pass password as kwarg
            ssh = SSHHelper(host, user, password=password)
            
            def run_docker_cmd(cmd):
                # Try normal
                s, o = ssh.execute_command(cmd)
                if s and o:
                    return o
                # Try sudo if failed (or empty output might mean permissions too?)
                # Usually permission denied is stderr.
                # Let's just try sudo immediately if first failed or empty.
                s_sudo, o_sudo = ssh.execute_command(f"sudo -n {cmd}") # -n for non-interactive
                if s_sudo and o_sudo:
                    return o_sudo
                return None

            # 1. Find the container ID
            # Simplest, most robust: docker ps and grep for portainer
            # Format: ID Image Names
            ps_output = run_docker_cmd("docker ps --format '{{.ID}} {{.Image}} {{.Names}}'")
            
            if not ps_output:
                raise Exception("Failed to list containers (checked 'docker ps' and 'sudo docker ps'). Check SSH user permissions.")

            container_id = None
            # Parse line by line
            for line in ps_output.splitlines():
                if 'portainer' in line.lower():
                    # return the first ID (first column)
                    container_id = line.split()[0]
                    break
            
            if not container_id:
                raise Exception("Could not find a running container with 'portainer' in name or image.")
                
            # 2. Inspect
            inspect_json = run_docker_cmd(f"docker inspect {container_id}")
            if not inspect_json:
                 raise Exception(f"Failed to inspect container {container_id} (tried sudo).")
            
            data = json.loads(inspect_json)[0]
            
            # 3. Parse Args for internal paths
            args = data.get('Args', []) or data.get('Config', {}).get('Cmd', []) or []
            env = data.get('Config', {}).get('Env', [])
            
            internal_cert = None
            internal_key = None
            
            # Flag parsing
            for i, arg in enumerate(args):
                if arg == '--sslcert' and i+1 < len(args):
                    internal_cert = args[i+1]
                if (arg == '--tlskey' or arg == '--sslkey') and i+1 < len(args):
                    internal_key = args[i+1]
            
            # Env parsing (some setups use environment variables?) -> Not standard Portainer CE but possible.
            
            # Env parsing (some setups use environment variables?) -> Not standard Portainer CE but possible.
            
            if not internal_cert:
                 # Logic for default/self-signed installations or missing flags
                 # Try to find exactly what Portainer is using by checking the filesystem inside the container
                 
                 # try to find /data mount
                 data_mount = next((m for m in data.get('Mounts', []) if m['Destination'] == '/data'), None)
                 
                 if data_mount:
                     # Check if we can find certificates inside the container
                     # Try both standard Portainer defaults and our previous 'portainer.crt' naming
                     possible_locations = [
                         '/data/tls/cert.pem', 
                         '/data/certs/cert.pem', 
                         '/data/cert.pem',
                         '/data/certs/portainer.crt',
                         '/data/portainer.crt'
                     ]
                     
                     found_loc = None
                     for loc in possible_locations:
                         # Use docker exec to check if file exists inside the container
                         s_chk, o_chk = ssh.execute_command(f"docker exec {container_id} ls {loc}")
                         if s_chk and loc in o_chk:
                             found_loc = loc
                             break
                     
                     if found_loc:
                         internal_cert = found_loc
                         # Usually key is next to it with .key instead of .pem/.crt or similar naming
                         if 'cert.pem' in found_loc:
                             internal_key = found_loc.replace('cert.pem', 'key.pem')
                         elif 'portainer.crt' in found_loc:
                             internal_key = found_loc.replace('portainer.crt', 'portainer.key')
                         else:
                             # Generic fallback if we found something but naming is weird
                             internal_key = found_loc.replace('.crt', '.key').replace('.pem', '.key')
                     else:
                         # No certificates found on disk inside container.
                         # Fallback to the most common Portainer default
                         internal_cert = "/data/certs/cert.pem"
                         internal_key = "/data/certs/key.pem"
                 else:
                     raise Exception("Container found, but no SSL flags AND no /data mount found. Cannot determine where to put certificates.")

            # 4. Map to Host Paths

            # 4. Map to Host Paths
            mounts = data.get('Mounts', [])
            host_cert = None
            host_key = None
            
            def resolve_mount(internal_path):
                for m in mounts:
                    dest = m['Destination']
                    if internal_path.startswith(dest):
                        rel_path = internal_path[len(dest):].lstrip('/')
                        # Handle case where dest IS the file
                        if not rel_path and internal_path == dest:
                            return m['Source']
                        return f"{m['Source']}/{rel_path}".replace('//', '/')
                return None

            host_cert = resolve_mount(internal_cert)
            if internal_key:
                host_key = resolve_mount(internal_key)

            if not host_cert:
                raise Exception(f"Could not map internal path {internal_cert} to a host bind mount.")
                
            return {
                "remote_cert_path": host_cert,
                "remote_key_path": host_key or host_cert.replace('.crt', '.key').replace('.pem', '.key'),
                "restart_cmd": f"docker restart {container_id}"
            }

        except Exception as e:
            raise Exception(f"Detection failed: {e}")
