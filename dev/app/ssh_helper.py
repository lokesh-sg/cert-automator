import paramiko
import logging
import os

class SSHHelper:
    def __init__(self, host, user, key_path=None, password=None, port=22):
        self.host = host
        self.user = user
        self.key_path = key_path
        self.password = password
        self.port = port
        self.logger = logging.getLogger("CertAutomator.SSHHelper")

    def upload_file(self, local_path, remote_path, log_errors=True):
        """Uploads a file via SCP/SFTP."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self._connect(client)
            sftp = client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            self.logger.info(f"Uploaded {local_path} to {self.host}:{remote_path}")
            return True
        except Exception as e:
            if log_errors:
                self.logger.error(f"Failed to upload file to {self.host}: {e}")
            return False
        finally:
            client.close()

    def execute_command(self, command, stdin_input=None, log_errors=True):
        """Executes a command via SSH. Optional stdin_input for sudo/interactive prompts."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self._connect(client)
            stdin, stdout, stderr = client.exec_command(command)
            
            if stdin_input:
                stdin.write(stdin_input + "\n")
                stdin.flush()
                
            exit_status = stdout.channel.recv_exit_status()
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            
            if exit_status == 0:
                self.logger.info(f"Command executed successfully: {command}")
                return True, out
            else:
                # Combine out/err for visibility since some commands (or 2>&1) put errors in stdout
                full_error = f"{out}\n{err}".strip()
                if log_errors:
                    self.logger.error(f"Command failed (Exit {exit_status}): {full_error}")
                return False, full_error
        except Exception as e:
            if log_errors:
                self.logger.error(f"Failed to execute command on {self.host}: {e}")
            return False, str(e)
        finally:
            client.close()

    def execute_sudo_command(self, command, log_errors=True):
        """
        Executes a command with sudo privileges.
        If a password is provided, uses 'sudo -S -p ""' directly (silently handling both NOPASSWD and password prompts)
        to avoid noisy 'sudo: a password is required' errors from 'sudo -n'.
        """
        clean_cmd = command.strip()
        if clean_cmd.startswith("sudo "):
            clean_cmd = clean_cmd[5:].strip()

        if self.password:
            return self.execute_command(f"sudo -S -p '' {clean_cmd}", stdin_input=self.password, log_errors=log_errors)
        else:
            return self.execute_command(f"sudo -n {clean_cmd}", log_errors=log_errors)

    def _connect(self, client):
        connect_kwargs = {
            "hostname": self.host,
            "username": self.user,
            "port": self.port
        }
        if self.key_path:
            connect_kwargs["key_filename"] = self.key_path
        if self.password:
            connect_kwargs["password"] = self.password
            
        client.connect(**connect_kwargs)
