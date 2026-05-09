"""Free a TCP port by killing whatever process holds it. Cross-platform."""
from __future__ import annotations

import socket
import subprocess
import sys


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def free_port(port: int) -> None:
    if not port_in_use(port):
        return
    if sys.platform == "win32":
        # netstat + taskkill
        try:
            out = subprocess.check_output(
                f"netstat -ano | findstr :{port}", shell=True, text=True,
            )
            for line in out.strip().splitlines():
                parts = line.split()
                if f":{port}" in parts[1] and "LISTENING" in line:
                    pid = int(parts[-1])
                    if pid > 0:
                        subprocess.call(f"taskkill /PID {pid} /F", shell=True,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        print(f"  Killed PID {pid} on port {port}")
                        return
        except (subprocess.CalledProcessError, ValueError, IndexError):
            pass
    else:
        # fuser
        try:
            subprocess.call(f"fuser -k {port}/tcp", shell=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <port>")
        sys.exit(1)
    free_port(int(sys.argv[1]))
