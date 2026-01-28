"""
Internal Reconnaissance Assessment Module - PRODUCTION ENHANCED
Gathers system and network information for security assessment with confidence scoring
"""

import os
import platform
import socket
import subprocess
import json
import re
try:
    import psutil
except ImportError:
    psutil = None

# Import common utilities for OS detection and confidence scoring
from . import common_utils

# Platform-specific imports
try:
    import pwd
    import grp
except ImportError:
    pwd = None
    grp = None


def create_finding(severity, finding, description, remediation="No action required - informational", confidence=100, verified=True):
    """Create a standardized finding with confidence scoring"""
    confidence_level = common_utils.get_confidence_level(confidence)

    return {
        "severity": severity,
        "finding": finding,
        "description": description,
        "remediation": remediation,
        "confidence_score": confidence,
        "confidence_level": confidence_level,
        "verified": verified,
        "os_specific": common_utils.get_os_type()
    }


def check():
    """
    Perform internal reconnaissance with OS-specific enhanced checks
    """
    results = {
        "module": "reconnaissance",
        "platform": platform.system(),
        "os_type": common_utils.get_os_type(),
        "findings": []
    }

    try:
        # System information (OS-specific)
        system_info = get_system_info_enhanced()
        results["findings"].extend(system_info)

        # Network information (OS-specific)
        network_info = get_network_info_enhanced()
        results["findings"].extend(network_info)

        # User information (OS-specific)
        user_info = get_user_info_enhanced()
        results["findings"].extend(user_info)

        # Process information (OS-specific)
        process_info = get_process_info_enhanced()
        results["findings"].extend(process_info)

        # Installed software (OS-specific)
        software_info = get_installed_software_enhanced()
        results["findings"].extend(software_info)

        # Network connections
        connection_info = get_network_connections_enhanced()
        results["findings"].extend(connection_info)

        # Security software (OS-specific)
        security_info = check_security_software_enhanced()
        results["findings"].extend(security_info)

        # Cloud environment detection (NEW)
        cloud_info = detect_cloud_environment()
        results["findings"].extend(cloud_info)

        # Container detection (NEW)
        container_info = detect_container_environment()
        results["findings"].extend(container_info)

    except Exception as e:
        results["error"] = str(e)

    return results

def get_system_info_enhanced():
    """Gather system information with OS-specific multi-method verification"""
    findings = []

    try:
        # Multi-method system information gathering
        methods_used = []
        system_data = {}

        # Method 1: Python platform module
        try:
            system_data['hostname'] = socket.gethostname()
            system_data['platform'] = platform.system()
            system_data['release'] = platform.release()
            system_data['version'] = platform.version()
            system_data['machine'] = platform.machine()
            system_data['processor'] = platform.processor()
            system_data['architecture'] = platform.architecture()[0]
            methods_used.append('platform_module')
        except Exception:
            pass

        # OS-specific enhancements
        if common_utils.is_linux():
            # Linux-specific system information
            try:
                # Method 2: uname command
                result = subprocess.run(['uname', '-a'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    system_data['uname'] = result.stdout.strip()
                    methods_used.append('uname')
            except Exception:
                pass

            try:
                # Method 3: /etc/os-release
                if os.path.exists('/etc/os-release'):
                    with open('/etc/os-release', 'r') as f:
                        os_release = {}
                        for line in f:
                            if '=' in line:
                                key, value = line.strip().split('=', 1)
                                os_release[key] = value.strip('"')
                        system_data['os_release'] = os_release
                        system_data['distro'] = os_release.get('NAME', 'Unknown')
                        system_data['distro_version'] = os_release.get('VERSION_ID', 'Unknown')
                        methods_used.append('os-release')
            except Exception:
                pass

            try:
                # Get uptime
                if os.path.exists('/proc/uptime'):
                    with open('/proc/uptime', 'r') as f:
                        uptime_seconds = float(f.readline().split()[0])
                        uptime_days = int(uptime_seconds / 86400)
                        system_data['uptime_days'] = uptime_days
                        methods_used.append('proc_uptime')
            except Exception:
                pass

            try:
                # Kernel version
                result = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    system_data['kernel'] = result.stdout.strip()
                    methods_used.append('kernel_version')
            except Exception:
                pass

        elif common_utils.is_windows():
            # Windows-specific system information
            try:
                # Method 2: systeminfo command
                result = subprocess.run(['systeminfo'], capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    # Parse systeminfo output
                    for line in result.stdout.split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            value = value.strip()
                            if key in ['OS Name', 'OS Version', 'System Type', 'Domain', 'Logon Server']:
                                system_data[key.lower().replace(' ', '_')] = value
                    methods_used.append('systeminfo')
            except Exception:
                pass

            try:
                # Method 3: PowerShell Get-ComputerInfo (if available)
                result = subprocess.run(
                    ['powershell', '-Command', 'Get-ComputerInfo | Select-Object CsName,WindowsVersion,OsArchitecture | ConvertTo-Json'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    ps_data = json.loads(result.stdout)
                    system_data['ps_computerinfo'] = ps_data
                    methods_used.append('powershell_computerinfo')
            except Exception:
                pass

            try:
                # Get Windows uptime
                result = subprocess.run(
                    ['powershell', '-Command', '(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object -ExpandProperty Days'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    system_data['uptime_days'] = int(result.stdout.strip())
                    methods_used.append('windows_uptime')
            except Exception:
                pass

        elif common_utils.is_macos():
            # macOS-specific system information
            try:
                # Method 2: sw_vers command
                result = subprocess.run(['sw_vers'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    macos_info = {}
                    for line in result.stdout.split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            macos_info[key.strip()] = value.strip()
                    system_data['macos_version'] = macos_info
                    methods_used.append('sw_vers')
            except Exception:
                pass

            try:
                # Get uptime
                result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    system_data['uptime'] = result.stdout.strip()
                    methods_used.append('uptime_command')
            except Exception:
                pass

        # Calculate confidence based on number of verification methods
        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))
        confidence = min(confidence, 100)  # Cap at 100%

        # Create finding
        description = f"System information gathered using {len(methods_used)} methods: {', '.join(methods_used)}. "
        description += f"Hostname: {system_data.get('hostname', 'Unknown')}. "
        description += f"Platform: {system_data.get('platform', 'Unknown')} {system_data.get('release', '')}. "

        if 'distro' in system_data:
            description += f"Distribution: {system_data['distro']} {system_data.get('distro_version', '')}. "
        if 'uptime_days' in system_data:
            description += f"Uptime: {system_data['uptime_days']} days. "

        findings.append(create_finding(
            "info",
            "System Information Gathered",
            description,
            "Review system configuration for security hardening opportunities",
            confidence,
            confidence >= 75
        ))

        # Additional finding: Detailed system data
        findings.append({
            "severity": "info",
            "finding": "Detailed System Information",
            "description": system_data,
            "confidence_score": confidence,
            "confidence_level": common_utils.get_confidence_level(confidence),
            "verified": confidence >= 75,
            "verification_methods": methods_used,
            "os_specific": common_utils.get_os_type()
        })

    except Exception:
        pass

    return findings

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

def get_network_info_enhanced():
    """Enhanced network information gathering with multi-method verification"""
    findings = []

    if not psutil:
        return findings

    try:
        methods_used = []
        network_data = {'interfaces': []}

        # Method 1: psutil network interfaces
        for interface, addrs in psutil.net_if_addrs().items():
            iface_info = {"name": interface, "addresses": []}
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    iface_info["addresses"].append({"type": "IPv4", "address": addr.address, "netmask": addr.netmask})
            if iface_info["addresses"]:
                network_data["interfaces"].append(iface_info)
        methods_used.append('psutil')

        # Method 2: OS-specific commands
        if common_utils.is_linux():
            try:
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    methods_used.append('ip_addr')
            except:
                pass
        elif common_utils.is_windows():
            try:
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    methods_used.append('ipconfig')
            except:
                pass

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

        findings.append(create_finding(
            "info",
            f"Network Configuration Enumerated ({len(network_data['interfaces'])} interfaces)",
            f"Gathered network information using {len(methods_used)} methods. Found {len(network_data['interfaces'])} active network interfaces.",
            "Review network configuration",
            confidence,
            confidence >= 75
        ))

    except Exception:
        pass

    return findings


def get_user_info_enhanced():
    """Enhanced user information gathering"""
    findings = []

    try:
        methods_used = []
        user_data = {}

        # Method 1: OS module
        try:
            user_data['uid'] = os.getuid()
            user_data['gid'] = os.getgid()
            methods_used.append('os_module')
        except:
            pass

        # Method 2: pwd/grp modules (Unix)
        if pwd and grp:
            try:
                user_data['username'] = pwd.getpwuid(os.getuid()).pw_name
                user_data['groups'] = [grp.getgrgid(g).gr_name for g in os.getgroups()]
                methods_used.append('pwd_grp')
            except:
                pass

        # Method 3: whoami command
        try:
            result = subprocess.run(['whoami'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                user_data['whoami'] = result.stdout.strip()
                methods_used.append('whoami')
        except:
            pass

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

        findings.append(create_finding(
            "info",
            f"Current User: {user_data.get('username', user_data.get('whoami', 'Unknown'))}",
            f"User enumerated using {len(methods_used)} methods. UID: {user_data.get('uid', 'N/A')}, Groups: {len(user_data.get('groups', []))}",
            "Review user privileges",
            confidence,
            confidence >= 75
        ))

    except Exception:
        pass

    return findings


def get_process_info_enhanced():
    """Enhanced process information gathering"""
    findings = []

    if not psutil:
        return findings

    try:
        interesting = ['apache', 'nginx', 'mysql', 'postgres', 'redis', 'mongodb', 'docker', 'ssh', 'sshd']
        found_processes = []

        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                if any(interesting_proc in proc.info['name'].lower() for interesting_proc in interesting):
                    found_processes.append(proc.info['name'])
                    if len(found_processes) >= 15:
                        break
            except:
                continue

        if found_processes:
            findings.append(create_finding(
                "info",
                f"Interesting Processes Detected: {len(found_processes)}",
                f"Found {len(found_processes)} interesting processes: {', '.join(found_processes[:10])}",
                "Review running services",
                95,
                True
            ))
    except Exception:
        pass

    return findings


def get_installed_software_enhanced():
    """Enhanced software enumeration"""
    findings = []

    try:
        methods_used = []

        if common_utils.is_linux():
            for cmd, pm_name in [(['dpkg', '-l'], 'dpkg'), (['rpm', '-qa'], 'rpm')]:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        package_count = len(result.stdout.strip().split('\n'))
                        methods_used.append(pm_name)

                        findings.append(create_finding(
                            "info",
                            f"Installed Packages: {package_count} ({pm_name})",
                            f"System has {package_count} packages managed by {pm_name}",
                            "Review installed software for vulnerabilities",
                            100,
                            True
                        ))
                        break
                except:
                    continue

        elif common_utils.is_windows():
            try:
                result = subprocess.run(
                    ['powershell', '-Command', 'Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName | Measure-Object | Select-Object -ExpandProperty Count'],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                if result.returncode == 0 and result.stdout.strip():
                    software_count = int(result.stdout.strip())
                    findings.append(create_finding(
                        "info",
                        f"Installed Software: {software_count} applications",
                        f"Windows system has {software_count} installed applications",
                        "Review installed software",
                        95,
                        True
                    ))
            except:
                pass
    except Exception:
        pass

    return findings


def get_network_connections_enhanced():
    """Enhanced network connections enumeration"""
    findings = []

    if not psutil:
        return findings

    try:
        listening = []
        established = []

        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                listening.append(conn.laddr.port)
            elif conn.status == 'ESTABLISHED' and conn.raddr:
                established.append(f"{conn.raddr.ip}:{conn.raddr.port}")

            if len(listening) >= 20:
                break

        findings.append(create_finding(
            "info",
            f"Network Connections: {len(listening)} listening, {len(established)} established",
            f"System has {len(listening)} listening ports and {len(established)} established connections",
            "Review network exposure",
            95,
            True
        ))
    except Exception:
        pass

    return findings


def check_security_software_enhanced():
    """Enhanced security software detection"""
    findings = []

    try:
        detected = []
        methods_used = []

        if common_utils.is_linux():
            security_tools = ['iptables', 'firewalld', 'ufw', 'apparmor', 'selinux', 'fail2ban']
            for tool in security_tools:
                try:
                    result = subprocess.run(['which', tool], capture_output=True, timeout=2)
                    if result.returncode == 0:
                        detected.append(tool)
                except:
                    continue
            methods_used.append('which')

            # Check SELinux
            try:
                result = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    selinux_status = result.stdout.strip()
                    if selinux_status in ['Enforcing', 'Permissive']:
                        detected.append(f'SELinux ({selinux_status})')
                        methods_used.append('getenforce')
            except:
                pass

        elif common_utils.is_windows():
            try:
                # Check Windows Defender
                result = subprocess.run(
                    ['powershell', '-Command', 'Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and 'True' in result.stdout:
                    detected.append('Windows Defender')
                    methods_used.append('powershell')
            except:
                pass

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

        if detected:
            findings.append(create_finding(
                "info",
                f"Security Software Detected: {len(detected)} tools",
                f"Found {len(detected)} security tools: {', '.join(detected)}",
                "Security software present - may detect malicious activity",
                confidence,
                confidence >= 75
            ))
        else:
            findings.append(create_finding(
                "low",
                "No security software detected",
                "No common security tools detected on system",
                "Consider installing security software",
                confidence,
                confidence >= 75
            ))
    except Exception:
        pass

    return findings


def detect_cloud_environment():
    """Detect if running in cloud environment (AWS, Azure, GCP)"""
    findings = []

    try:
        cloud_detected = []

        # Check for AWS
        try:
            result = subprocess.run(['curl', '-s', '-m', '2', 'http://169.254.169.254/latest/meta-data/'], capture_output=True, timeout=3)
            if result.returncode == 0 and result.stdout:
                cloud_detected.append('AWS')
        except:
            pass

        # Check for Azure
        try:
            result = subprocess.run(['curl', '-s', '-m', '2', '-H', 'Metadata:true', 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'], capture_output=True, timeout=3)
            if result.returncode == 0 and result.stdout:
                cloud_detected.append('Azure')
        except:
            pass

        # Check for GCP
        try:
            result = subprocess.run(['curl', '-s', '-m', '2', '-H', 'Metadata-Flavor: Google', 'http://metadata.google.internal/computeMetadata/v1/'], capture_output=True, timeout=3)
            if result.returncode == 0 and result.stdout:
                cloud_detected.append('GCP')
        except:
            pass

        if cloud_detected:
            findings.append(create_finding(
                "medium",
                f"Cloud Environment Detected: {', '.join(cloud_detected)}",
                f"System is running in cloud environment: {', '.join(cloud_detected)}. Metadata service accessible.",
                "Restrict access to cloud metadata service",
                95,
                True
            ))
    except Exception:
        pass

    return findings


def detect_container_environment():
    """Detect if running in container (Docker, LXC, etc.)"""
    findings = []

    try:
        container_indicators = []

        # Check for Docker
        if os.path.exists('/.dockerenv'):
            container_indicators.append('Docker (.dockerenv file)')

        # Check cgroup
        if os.path.exists('/proc/1/cgroup'):
            try:
                with open('/proc/1/cgroup', 'r') as f:
                    content = f.read()
                    if 'docker' in content:
                        container_indicators.append('Docker (cgroup)')
                    elif 'lxc' in content:
                        container_indicators.append('LXC (cgroup)')
            except:
                pass

        # Check for kubernetes
        if os.path.exists('/var/run/secrets/kubernetes.io'):
            container_indicators.append('Kubernetes')

        if container_indicators:
            confidence = common_utils.calculate_confidence_score(*[True] * len(container_indicators))
            findings.append(create_finding(
                "medium",
                f"Container Environment Detected",
                f"System is running in a container: {', '.join(container_indicators)}. Container escape may be possible.",
                "Review container security and host access",
                confidence,
                confidence >= 75
            ))
    except Exception:
        pass

    return findings


# Keep old functions for backward compatibility (deprecated)
def get_system_info():
    """Deprecated: Use get_system_info_enhanced()"""
    return {"severity": "info", "finding": "Use enhanced version", "description": "Deprecated"}

def get_network_info():
    """Deprecated: Use get_network_info_enhanced()"""
    return {"severity": "info", "finding": "Use enhanced version", "description": "Deprecated"}

def get_user_info():
    """Deprecated: Use get_user_info_enhanced()"""
    return {"severity": "info", "finding": "Use enhanced version", "description": "Deprecated"}

def get_process_info():
    """Deprecated: Use get_process_info_enhanced()"""
    return {"severity": "info", "finding": "Use enhanced version", "description": "Deprecated"}

def get_installed_software():
    """Deprecated: Use get_installed_software_enhanced()"""
    return {"severity": "info", "finding": "Use enhanced version", "description": "Deprecated"}

def get_network_connections():
    """Deprecated: Use get_network_connections_enhanced()"""
    return {"severity": "info", "finding": "Use enhanced version", "description": "Deprecated"}

def check_security_software():
    """Deprecated: Use check_security_software_enhanced()"""
    return {"severity": "info", "finding": "Use enhanced version", "description": "Deprecated"}


if __name__ == '__main__':
    # Test module
    import json
    results = check()
    print(json.dumps(results, indent=2))
