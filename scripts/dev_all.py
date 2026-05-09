"""Start all AILA services in one command. Cross-platform.

Spawns backend, frontend, and 3 workers as child processes.
Ctrl+C kills everything cleanly. Logs are interleaved with color prefixes.

Usage:
    python scripts/dev_all.py
    make dev-all
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
SRC = ROOT / "src"

# ANSI colors for log prefixes
COLORS = {
    "backend":  "\033[96m",   # cyan
    "frontend": "\033[95m",   # magenta
    "worker":   "\033[93m",   # yellow
    "vuln":     "\033[91m",   # red
    "forensic": "\033[92m",   # green
}
RESET = "\033[0m"


def free_port(port: int) -> None:
    """Kill whatever holds a port. Cross-platform."""
    try:
        subprocess.call(
            [sys.executable, str(ROOT / "scripts" / "portfree.py"), str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        pass


def start_process(name: str, cmd: list[str], cwd: Path, env: dict | None = None) -> subprocess.Popen:
    """Start a subprocess with a colored prefix label."""
    merged_env = {**os.environ, **(env or {})}
    merged_env["PYTHONPATH"] = str(SRC) + os.pathsep + merged_env.get("PYTHONPATH", "")
    merged_env["PYTHONUNBUFFERED"] = "1"
    color = COLORS.get(name, "")
    print(f"{color}[{name}]{RESET} starting: {' '.join(cmd)}")
    return subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=merged_env,
        stdin=subprocess.DEVNULL,
    )


def main() -> int:
    procs: dict[str, subprocess.Popen] = {}

    # 1. DB init (blocking — must finish before workers start)
    print(f"\033[97m[init]\033[0m Initializing database...")
    subprocess.call(
        [sys.executable, str(ROOT / "scripts" / "db_init.py")],
        cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )

    # 2. Free ports
    free_port(8000)
    free_port(3000)

    # 3. Start backend
    procs["backend"] = start_process(
        "backend",
        [sys.executable, "-m", "uvicorn", "aila.api.app:app",
         "--host", "0.0.0.0", "--port", "8000", "--reload"],
        cwd=ROOT,
    )

    # 4. Start frontend (need to find vite)
    vite_cmd = _find_vite()
    procs["frontend"] = start_process(
        "frontend",
        vite_cmd + ["--host", "0.0.0.0", "--port", "3000"],
        cwd=FRONTEND,
    )

    # 5. Start workers
    for name, queue in [("worker", "default"), ("vuln", "vulnerability"), ("forensic", "forensics")]:
        cmd = [sys.executable, "-m", "aila", "worker"]
        if queue != "default":
            cmd += ["-q", queue]
        procs[name] = start_process(name, cmd, cwd=ROOT)

    # 6. Wait — Ctrl+C kills all
    print(f"\n\033[97m{'='*60}")
    print(f"  AILA running — 5 services")
    print(f"  Backend:  http://localhost:8000")
    print(f"  Frontend: http://localhost:3000")
    print(f"  Workers:  default, vulnerability, forensics")
    print(f"  Press Ctrl+C to stop everything")
    print(f"{'='*60}{RESET}\n")

    try:
        while True:
            # Check for dead processes and report
            for name, proc in list(procs.items()):
                ret = proc.poll()
                if ret is not None:
                    color = COLORS.get(name, "")
                    print(f"{color}[{name}]{RESET} exited with code {ret}")
                    del procs[name]
            if not procs:
                print("All processes exited.")
                return 1
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n\033[97m[shutdown]\033[0m Stopping all services...")
        for name, proc in procs.items():
            try:
                if sys.platform == "win32":
                    proc.terminate()
                else:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
        # Wait briefly then force kill
        time.sleep(2)
        for name, proc in procs.items():
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
        print("All services stopped.")
        return 0


def _find_vite() -> list[str]:
    """Find vite executable — npx, pnpm, or direct."""
    # Try direct node_modules/.bin/vite first
    vite_bin = FRONTEND / "node_modules" / ".bin" / ("vite.cmd" if sys.platform == "win32" else "vite")
    if vite_bin.exists():
        return [str(vite_bin)]
    # Fall back to npx
    return ["npx", "vite"]


if __name__ == "__main__":
    sys.exit(main())
