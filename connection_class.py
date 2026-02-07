import paramiko
import socket
from typing import Tuple, Optional


class SSHClient:
    """
    SOAR SSH Client
    Used for remote response actions (kill process, block IP, collect logs, etc.)
    """
    def __init__(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        port: int = 22,
        key_path: Optional[str] = None,
        timeout: int = 10
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.key_path = key_path
        self.timeout = timeout
        self.client = None

    # -------------------------------
    # Connect
    # -------------------------------
    def connect(self) -> None:
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if self.key_path:
                key = paramiko.RSAKey.from_private_key_file(self.key_path)
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    pkey=key,
                    timeout=self.timeout
                )
            else:
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout
                )

        except (paramiko.SSHException, socket.error) as e:
            raise RuntimeError(f"SSH connection failed: {e}")

    # -------------------------------
    # Execute Command
    # -------------------------------
    def execute(self, command: str) -> Tuple[str, str, int]:
        if not self.client:
            raise RuntimeError("SSH client is not connected")

        stdin, stdout, stderr = self.client.exec_command(command)

        out = stdout.read().decode(errors="ignore").strip()
        err = stderr.read().decode(errors="ignore").strip()
        exit_code = stdout.channel.recv_exit_status()

        return out, err, exit_code



    # -------------------------------
    # Close
    # -------------------------------
    def close(self) -> None:
        if self.client:
            self.client.close()
            self.client = None


