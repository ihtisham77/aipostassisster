#!/usr/bin/env python3
"""
Framework Auto-Starter
Automatically starts the C2 operator server when needed
"""

import os
import sys
import time
import subprocess
import requests
import signal
import psutil
from typing import Optional, Tuple

# Add operator directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'operator'))
from config import get_config

# Configuration
config = get_config()
DEFAULT_HOST = config.get("server", "host") or "0.0.0.0"
DEFAULT_PORT = config.get("server", "port") or 8542
LOCAL_IP = config.get_local_ip()
SERVER_URL = f"http://{LOCAL_IP}:{DEFAULT_PORT}"


def is_port_in_use(port: int) -> bool:
    """Check if a port is already in use"""
    for conn in psutil.net_connections():
        if conn.laddr.port == port and conn.status == 'LISTEN':
            return True
    return False


def is_server_healthy(url: str = SERVER_URL, timeout: int = 5) -> bool:
    """
    Check if the operator server is running and healthy

    Args:
        url: Server URL to check
        timeout: Request timeout in seconds

    Returns:
        True if server is healthy, False otherwise
    """
    try:
        response = requests.get(f"{url}/api/health", timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            return data.get("status") == "online"
    except:
        pass
    return False


def find_server_process() -> Optional[psutil.Process]:
    """
    Find the operator server process if running

    Returns:
        Process object if found, None otherwise
    """
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline', [])
            if cmdline and 'python' in cmdline[0].lower():
                if any('server.py' in arg for arg in cmdline):
                    return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def start_server(
    detached: bool = True,
    wait_timeout: int = 15
) -> Tuple[bool, str, Optional[int]]:
    """
    Start the operator server

    Args:
        detached: If True, start in background. If False, run in foreground
        wait_timeout: Seconds to wait for server to become healthy

    Returns:
        Tuple of (success: bool, message: str, pid: Optional[int])
    """
    # Check if already running
    if is_server_healthy():
        existing_proc = find_server_process()
        pid = existing_proc.pid if existing_proc else None
        return True, f"Server already running at {SERVER_URL}", pid

    # Check if port is in use by another process
    if is_port_in_use(DEFAULT_PORT):
        return False, f"Port {DEFAULT_PORT} is already in use by another process", None

    # Get server script path
    server_script = os.path.join(os.path.dirname(__file__), 'operator', 'server.py')

    if not os.path.exists(server_script):
        return False, f"Server script not found: {server_script}", None

    try:
        # Start server
        if detached:
            # Background process
            process = subprocess.Popen(
                [sys.executable, server_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                cwd=os.path.dirname(server_script)
            )
            pid = process.pid

            # Wait for server to become healthy
            print(f"[*] Starting operator server (PID: {pid})...")
            for i in range(wait_timeout):
                time.sleep(1)
                if is_server_healthy():
                    return True, f"Server started successfully at {SERVER_URL}", pid
                print(f"[*] Waiting for server to start... ({i+1}/{wait_timeout})")

            # Server didn't become healthy in time
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                pass
            return False, f"Server started but didn't become healthy within {wait_timeout} seconds", None
        else:
            # Foreground process (blocks)
            print(f"[*] Starting operator server at {SERVER_URL}...")
            print("[*] Press Ctrl+C to stop")
            subprocess.run([sys.executable, server_script], cwd=os.path.dirname(server_script))
            return True, "Server stopped", None

    except KeyboardInterrupt:
        return True, "Server stopped by user", None
    except Exception as e:
        return False, f"Failed to start server: {str(e)}", None


def stop_server() -> Tuple[bool, str]:
    """
    Stop the operator server if running

    Returns:
        Tuple of (success: bool, message: str)
    """
    proc = find_server_process()

    if not proc:
        return True, "Server is not running"

    try:
        pid = proc.pid
        print(f"[*] Stopping server (PID: {pid})...")

        # Try graceful shutdown first
        proc.terminate()

        # Wait up to 10 seconds for graceful shutdown
        try:
            proc.wait(timeout=10)
            return True, f"Server stopped successfully (PID: {pid})"
        except psutil.TimeoutExpired:
            # Force kill if graceful shutdown failed
            print("[*] Graceful shutdown failed, forcing kill...")
            proc.kill()
            proc.wait(timeout=5)
            return True, f"Server forcefully stopped (PID: {pid})"

    except psutil.NoSuchProcess:
        return True, "Server process no longer exists"
    except psutil.AccessDenied:
        return False, "Access denied - cannot stop server (try running as administrator/root)"
    except Exception as e:
        return False, f"Failed to stop server: {str(e)}"


def restart_server(wait_timeout: int = 15) -> Tuple[bool, str, Optional[int]]:
    """
    Restart the operator server

    Args:
        wait_timeout: Seconds to wait for server to become healthy

    Returns:
        Tuple of (success: bool, message: str, pid: Optional[int])
    """
    # Stop if running
    print("[*] Stopping server...")
    success, message = stop_server()
    if not success:
        return False, f"Failed to stop server: {message}", None

    # Wait a bit before restarting
    time.sleep(2)

    # Start server
    print("[*] Starting server...")
    return start_server(detached=True, wait_timeout=wait_timeout)


def get_server_status() -> dict:
    """
    Get comprehensive server status

    Returns:
        Dictionary with server status information
    """
    status = {
        "url": SERVER_URL,
        "port": DEFAULT_PORT,
        "host": DEFAULT_HOST
    }

    # Check if healthy
    if is_server_healthy():
        status["status"] = "online"
        status["healthy"] = True

        # Get health info
        try:
            response = requests.get(f"{SERVER_URL}/api/health", timeout=5)
            health_data = response.json()
            status["active_agents"] = health_data.get("active_agents", 0)
            status["total_agents"] = health_data.get("total_agents", 0)
        except:
            pass

        # Get process info
        proc = find_server_process()
        if proc:
            status["pid"] = proc.pid
            status["cpu_percent"] = proc.cpu_percent(interval=0.1)
            status["memory_mb"] = proc.memory_info().rss / 1024 / 1024

    else:
        status["status"] = "offline"
        status["healthy"] = False

        # Check if port is in use
        if is_port_in_use(DEFAULT_PORT):
            status["error"] = f"Port {DEFAULT_PORT} is in use but server is not responding"
        else:
            status["error"] = "Server is not running"

    return status


def main():
    """Main CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(
        description="C2 Framework Auto-Starter - Manage the operator server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start server in background
  python framework_starter.py start

  # Start server in foreground (blocks until Ctrl+C)
  python framework_starter.py start --foreground

  # Check server status
  python framework_starter.py status

  # Stop running server
  python framework_starter.py stop

  # Restart server
  python framework_starter.py restart
        """
    )

    parser.add_argument(
        'action',
        choices=['start', 'stop', 'restart', 'status'],
        help='Action to perform'
    )

    parser.add_argument(
        '--foreground',
        action='store_true',
        help='Start server in foreground (only with start action)'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=15,
        help='Seconds to wait for server startup (default: 15)'
    )

    args = parser.parse_args()

    print("""
╔═══════════════════════════════════════════════════════════╗
║       C2 Framework Auto-Starter                           ║
║       Operator Server Management                          ║
╚═══════════════════════════════════════════════════════════╝
    """)

    if args.action == 'start':
        success, message, pid = start_server(
            detached=not args.foreground,
            wait_timeout=args.timeout
        )
        print(f"\n{'[+]' if success else '[!]'} {message}")
        if pid:
            print(f"[*] Process ID: {pid}")
            print(f"[*] Server URL: {SERVER_URL}")
        sys.exit(0 if success else 1)

    elif args.action == 'stop':
        success, message = stop_server()
        print(f"\n{'[+]' if success else '[!]'} {message}")
        sys.exit(0 if success else 1)

    elif args.action == 'restart':
        success, message, pid = restart_server(wait_timeout=args.timeout)
        print(f"\n{'[+]' if success else '[!]'} {message}")
        if pid:
            print(f"[*] Process ID: {pid}")
            print(f"[*] Server URL: {SERVER_URL}")
        sys.exit(0 if success else 1)

    elif args.action == 'status':
        status = get_server_status()
        print(f"\n[*] Server Status: {status['status'].upper()}")
        print(f"[*] Server URL: {status['url']}")
        print(f"[*] Listening Port: {status['port']}")

        if status['healthy']:
            print(f"[+] Server is healthy")
            if 'pid' in status:
                print(f"[*] Process ID: {status['pid']}")
                print(f"[*] CPU Usage: {status['cpu_percent']:.1f}%")
                print(f"[*] Memory Usage: {status['memory_mb']:.1f} MB")
            if 'active_agents' in status:
                print(f"[*] Active Agents: {status['active_agents']}")
                print(f"[*] Total Agents: {status['total_agents']}")
        else:
            print(f"[!] Server is not healthy")
            if 'error' in status:
                print(f"[!] Error: {status['error']}")

        sys.exit(0 if status['healthy'] else 1)


if __name__ == '__main__':
    main()
