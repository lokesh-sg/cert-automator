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

        # Restart (with auto-recovery if container ID was recreated)
        if self._restart_service(ssh, restart_cmd):
            return True

        # Self-healing fallback: if restart_cmd had an old container ID ("No such container"),
        # resolve the active Portainer container name/ID and restart it.
        if restart_cmd and "docker restart" in restart_cmd:
            self.logger.warning("Restart command failed (container ID may have changed). Attempting to locate active Portainer container...")
            s, ps_out = ssh.execute_command("docker ps --format '{{.Names}} {{.Image}}'", log_errors=False)
            if not s or not ps_out:
                s, ps_out = ssh.execute_sudo_command("docker ps --format '{{.Names}} {{.Image}}'", log_errors=False)
            if s and ps_out:
                for line in ps_out.splitlines():
                    if 'portainer' in line.lower():
                        active_name = line.split()[0]
                        fallback_cmd = f"docker restart {active_name}"
                        self.logger.info(f"Found active Portainer container '{active_name}'. Retrying restart with: {fallback_cmd}")
                        if self._restart_service(ssh, fallback_cmd):
                            self.config['restart_cmd'] = fallback_cmd
                            return True
                        break
        return False

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
                verify=False,
                timeout=10
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
            ssh = SSHHelper(host, user, password=password)
            
            def run_docker_cmd(cmd):
                # Try normal without logging expected failure if user needs sudo
                s, o = ssh.execute_command(cmd, log_errors=False)
                if s and o:
                    return o
                # Fallback to sudo (handles both NOPASSWD and password via sudo -S)
                s_sudo, o_sudo = ssh.execute_sudo_command(cmd, log_errors=False)
                if s_sudo and o_sudo:
                    return o_sudo
                return None

            # 1. Find the container ID and Name
            ps_output = run_docker_cmd("docker ps --format '{{.ID}} {{.Image}} {{.Names}}'")
            
            if not ps_output:
                raise Exception("Failed to list containers (checked 'docker ps' and 'sudo docker ps'). Check SSH user permissions.")

            container_id = None
            container_name = None
            for line in ps_output.splitlines():
                if 'portainer' in line.lower():
                    parts = line.split()
                    container_id = parts[0]
                    container_name = parts[-1] if len(parts) >= 3 else container_id
                    break
            
            if not container_id:
                raise Exception("Could not find a running container with 'portainer' in name or image.")
                
            # 2. Inspect
            inspect_json = run_docker_cmd(f"docker inspect {container_id}")
            if not inspect_json:
                 raise Exception(f"Failed to inspect container {container_id} (tried sudo).")
            
            data = json.loads(inspect_json)[0]
            # Prefer stable container name over ephemeral container ID for restart_cmd
            inspected_name = (data.get('Name') or '').lstrip('/')
            target_container = inspected_name or container_name or container_id
            
            # 3. Parse Args for internal paths
            args = data.get('Args', []) or data.get('Config', {}).get('Cmd', []) or []
            
            internal_cert = None
            internal_key = None
            
            # Flag parsing
            for i, arg in enumerate(args):
                if arg == '--sslcert' and i+1 < len(args):
                    internal_cert = args[i+1]
                if (arg == '--tlskey' or arg == '--sslkey') and i+1 < len(args):
                    internal_key = args[i+1]
            
            mounts = data.get('Mounts', [])

            def resolve_mount(internal_path):
                for m in mounts:
                    dest = m['Destination']
                    if internal_path.startswith(dest):
                        rel_path = internal_path[len(dest):].lstrip('/')
                        if not rel_path and internal_path == dest:
                            return m['Source']
                        return f"{m['Source']}/{rel_path}".replace('//', '/')
                return None

            if not internal_cert:
                 # Portainer CE is a scratch/distroless image without /bin/ls or /bin/sh inside the container.
                 # Instead of 'docker exec ls', check the mapped host directory directly via the host OS!
                 data_mount = next((m for m in mounts if m['Destination'] == '/data'), None)
                 
                 if data_mount:
                     possible_locations = [
                         '/data/certs/cert.pem',
                         '/data/tls/cert.pem', 
                         '/data/cert.pem',
                         '/data/certs/portainer.crt',
                         '/data/portainer.crt'
                     ]
                     
                     found_loc = None
                     for loc in possible_locations:
                         host_candidate = resolve_mount(loc)
                         if not host_candidate:
                             continue
                         # Check on the host (normal or sudo test -f)
                         s_chk, _ = ssh.execute_command(f"test -f \"{host_candidate}\"", log_errors=False)
                         if not s_chk:
                             s_chk, _ = ssh.execute_sudo_command(f"test -f \"{host_candidate}\"", log_errors=False)
                         if s_chk:
                             found_loc = loc
                             break
                     
                     if found_loc:
                         internal_cert = found_loc
                         if 'cert.pem' in found_loc:
                             internal_key = found_loc.replace('cert.pem', 'key.pem')
                         elif 'portainer.crt' in found_loc:
                             internal_key = found_loc.replace('portainer.crt', 'portainer.key')
                         else:
                             internal_key = found_loc.replace('.crt', '.key').replace('.pem', '.key')
                     else:
                         # Default Portainer CE path
                         internal_cert = "/data/certs/cert.pem"
                         internal_key = "/data/certs/key.pem"
                 else:
                     raise Exception("Container found, but no SSL flags AND no /data mount found. Cannot determine where to put certificates.")

            # 4. Map to Host Paths
            host_cert = resolve_mount(internal_cert)
            host_key = resolve_mount(internal_key) if internal_key else None

            if not host_cert:
                raise Exception(f"Could not map internal path {internal_cert} to a host bind mount.")
                
            return {
                "remote_cert_path": host_cert,
                "remote_key_path": host_key or host_cert.replace('.crt', '.key').replace('.pem', '.key'),
                "restart_cmd": f"docker restart {target_container}"
            }

        except Exception as e:
            raise Exception(f"Detection failed: {e}")
