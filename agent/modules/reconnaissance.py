"""
Internal Reconnaissance Assessment Module
Gathers system and network information for security assessment
"""

import os
import platform
import socket
import subprocess
import psutil
import pwd
import grp

def check():
    """
    Perform internal reconnaissance
    """
    results = {
        "module": "reconnaissance",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # System information
        system_info = get_system_info()
        if system_info:
            results["findings"].append(system_info)

        # Network information
        network_info = get_network_info()
        if network_info:
            results["findings"].append(network_info)

        # User information
        user_info = get_user_info()
        if user_info:
            results["findings"].append(user_info)

        # Process information
        process_info = get_process_info()
        if process_info:
            results["findings"].append(process_info)

        # Installed software
        software_info = get_installed_software()
        if software_info:
            results["findings"].append(software_info)

        # Network connections
        connection_info = get_network_connections()
        if connection_info:
            results["findings"].append(connection_info)

        # Security software
        security_info = check_security_software()
        if security_info:
            results["findings"].append(security_info)

    except Exception as e:
        results["error"] = str(e)

    return results

def get_system_info():
    """Gather system information"""
    try:
        info = {
            "severity": "info",
            "finding": "System Information",
            "description": {
                "hostname": socket.gethostname(),
                "platform": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "architecture": platform.architecture()[0],
                "python_version": platform.python_version()
            }
        }

        # Get uptime
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                uptime_days = int(uptime_seconds / 86400)
                info["description"]["uptime_days"] = uptime_days
        except Exception:
            pass

        # Get kernel version
        try:
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=5)
            info["description"]["kernel"] = result.stdout.strip()
        except Exception:
            pass

        return info

    except Exception:
        return None

def get_network_info():
    """Gather network configuration"""
    try:
        info = {
            "severity": "info",
            "finding": "Network Information",
            "description": {
                "interfaces": []
            }
        }

        # Get network interfaces
        for interface, addrs in psutil.net_if_addrs().items():
            iface_info = {"name": interface, "addresses": []}

            for addr in addrs:
                if addr.family == socket.AF_INET:
                    iface_info["addresses"].append({
                        "type": "IPv4",
                        "address": addr.address,
                        "netmask": addr.netmask
                    })
                elif addr.family == socket.AF_INET6:
                    iface_info["addresses"].append({
                        "type": "IPv6",
                        "address": addr.address
                    })

            if iface_info["addresses"]:
                info["description"]["interfaces"].append(iface_info)

        # Get routing information
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
            info["description"]["routes"] = result.stdout.strip().split('\n')[:5]
        except Exception:
            pass

        # Get DNS servers
        try:
            with open('/etc/resolv.conf', 'r') as f:
                dns_servers = [line.split()[1] for line in f if line.startswith('nameserver')]
                info["description"]["dns_servers"] = dns_servers
        except Exception:
            pass

        return info

    except Exception:
        return None

def get_user_info():
    """Gather user and group information"""
    try:
        info = {
            "severity": "info",
            "finding": "User Information",
            "description": {
                "current_user": os.getlogin() if hasattr(os, 'getlogin') else pwd.getpwuid(os.getuid()).pw_name,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "groups": [grp.getgrgid(g).gr_name for g in os.getgroups()],
                "home_directory": os.path.expanduser('~'),
                "shell": os.environ.get('SHELL', 'unknown')
            }
        }

        # Check sudo privileges
        try:
            result = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=2)
            info["description"]["sudo_nopasswd"] = (result.returncode == 0)
        except Exception:
            info["description"]["sudo_nopasswd"] = False

        # List all users
        try:
            users = []
            for user in pwd.getpwall():
                if user.pw_uid >= 1000 or user.pw_uid == 0:
                    users.append({
                        "username": user.pw_name,
                        "uid": user.pw_uid,
                        "home": user.pw_dir,
                        "shell": user.pw_shell
                    })
            info["description"]["system_users"] = users[:10]  # Limit to first 10
        except Exception:
            pass

        return info

    except Exception:
        return None

def get_process_info():
    """Gather running process information"""
    try:
        info = {
            "severity": "info",
            "finding": "Process Information",
            "description": {
                "total_processes": len(psutil.pids()),
                "interesting_processes": []
            }
        }

        # Look for interesting processes
        interesting = [
            'apache', 'nginx', 'mysql', 'postgres', 'redis', 'mongodb',
            'docker', 'ssh', 'sshd', 'sudo', 'cron', 'systemd'
        ]

        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                proc_name = proc.info['name'].lower()

                if any(interesting_proc in proc_name for interesting_proc in interesting):
                    info["description"]["interesting_processes"].append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "user": proc.info['username']
                    })

                    # Limit results
                    if len(info["description"]["interesting_processes"]) >= 20:
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return info

    except Exception:
        return None

def get_installed_software():
    """Gather installed software information"""
    try:
        info = {
            "severity": "info",
            "finding": "Installed Software",
            "description": {
                "packages": []
            }
        }

        # Try different package managers
        package_managers = [
            (['dpkg', '-l'], 'dpkg'),
            (['rpm', '-qa'], 'rpm'),
            (['pacman', '-Q'], 'pacman')
        ]

        for cmd, pm_name in package_managers:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    package_count = len(result.stdout.strip().split('\n'))
                    info["description"]["package_manager"] = pm_name
                    info["description"]["package_count"] = package_count

                    # Get first few packages
                    packages = result.stdout.strip().split('\n')[:10]
                    info["description"]["sample_packages"] = packages
                    break
            except Exception:
                continue

        return info

    except Exception:
        return None

def get_network_connections():
    """Gather active network connections"""
    try:
        info = {
            "severity": "info",
            "finding": "Network Connections",
            "description": {
                "listening_ports": [],
                "established_connections": []
            }
        }

        # Get listening ports
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                info["description"]["listening_ports"].append({
                    "address": conn.laddr.ip,
                    "port": conn.laddr.port,
                    "pid": conn.pid
                })

            elif conn.status == 'ESTABLISHED':
                if conn.raddr:
                    info["description"]["established_connections"].append({
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "pid": conn.pid
                    })

            # Limit results
            if len(info["description"]["listening_ports"]) >= 20:
                break

        return info

    except Exception:
        return None

def check_security_software():
    """Check for security software"""
    try:
        info = {
            "severity": "info",
            "finding": "Security Software",
            "description": {
                "detected": []
            }
        }

        # Check for common security tools
        security_tools = [
            'iptables', 'firewalld', 'ufw', 'apparmor', 'selinux',
            'fail2ban', 'aide', 'ossec', 'tripwire', 'clamav'
        ]

        for tool in security_tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, timeout=2)
                if result.returncode == 0:
                    info["description"]["detected"].append(tool)
            except Exception:
                continue

        # Check firewall status
        try:
            result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                rule_count = len(result.stdout.strip().split('\n'))
                info["description"]["iptables_rules"] = rule_count
        except Exception:
            pass

        # Check SELinux status
        try:
            result = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                info["description"]["selinux"] = result.stdout.strip()
        except Exception:
            pass

        return info

    except Exception:
        return None

if __name__ == '__main__':
    # Test module
    import json
    results = check()
    print(json.dumps(results, indent=2))
