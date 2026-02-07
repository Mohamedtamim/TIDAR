import threading
import queue
import time
from utils.connection_class import SSHClient


TARGET_IP = "0.0.0.0"
USERNAME = "DeviceName"
PASSWORD = "123"


class PersistentSSHExecutor:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.ssh = None
        self.command_queue = queue.Queue()
        self.running = False
        
    def connect(self) -> bool:
        """Connect to SSH. Returns True on success, False on failure (no exception)."""
        try:
            self.ssh = SSHClient(
                host=self.host,
                username=self.username,
                password=self.password
            )
            print("[*] Connecting to SSH...")
            self.ssh.connect()
            print("[+] SSH connected")
            return True
        except Exception as e:
            print(f"[!] SSH connection failed: {e} (will retry when needed)")
            self.ssh = None
            return False

    def start(self):
        self.running = True
        self.connect()  # Try once; if it fails, worker will retry
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        while self.running:
            try:
                command, response_queue = self.command_queue.get(timeout=1)

                if not self.ssh and not self.connect():
                    response_queue.put({
                        "stdout": "",
                        "stderr": "SSH not connected (target unreachable)",
                        "exit_code": -1
                    })
                    continue

                out, err, code = self.ssh.execute(command)
                response_queue.put({
                    "stdout": out,
                    "stderr": err,
                    "exit_code": code
                })

            except queue.Empty:
                if self.ssh:
                    try:
                        self.ssh.execute("echo alive")
                    except Exception:
                        self._reconnect()
                # else: not connected, skip keepalive

            except Exception as e:
                try:
                    response_queue.put({
                        "stdout": "",
                        "stderr": str(e),
                        "exit_code": -1
                    })
                except Exception:
                    pass
                self._reconnect()

    def _reconnect(self):
        try:
            if self.ssh:
                self.ssh.close()
        except Exception:
            pass
        self.ssh = None
        time.sleep(5)
        self.connect()

    def send_command(self, command):
        response_queue = queue.Queue()
        self.command_queue.put((command, response_queue))
        return response_queue.get()

    def stop(self):
        self.running = False
        try:
            if self.ssh:
                self.ssh.close()
        except Exception:
            pass
        self.ssh = None
        print("[+] SSH executor stopped")


# ---------------- INTERACTIVE MODE ----------------

def main():
    executor = PersistentSSHExecutor(
        TARGET_IP,
        USERNAME,
        PASSWORD
    )

    executor.start()

    ps_mode = False

    print("\n=== SOAR Interactive Shell ===")
    print("Type 'powershell' to enter PS mode")
    print("Type 'exit' to quit or leave PS mode\n")

    try:
        while True:
            prompt = "PS> " if ps_mode else "SOAR> "
            cmd = input(prompt).strip()

            if not cmd:
                continue

            # Exit logic
            if cmd.lower() == "exit":
                if ps_mode:
                    ps_mode = False
                    print("[+] Exited PowerShell mode")
                    continue
                else:
                    break

            # Enter PowerShell mode
            if cmd.lower() == "powershell" and not ps_mode:
                ps_mode = True
                print("[+] PowerShell mode enabled")
                continue

            # Command execution
            if ps_mode:
                full_cmd = f'powershell.exe -Command "{cmd}"'
            else:
                full_cmd = cmd

            result = executor.send_command(full_cmd)

            if result["stdout"]:
                print(result["stdout"])
            if result["stderr"]:
                print(result["stderr"])

    except KeyboardInterrupt:
        pass

    executor.stop()


if __name__ == "__main__":
    main()
