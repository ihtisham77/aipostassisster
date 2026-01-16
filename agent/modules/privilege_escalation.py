"""
Privilege Escalation Assessment Module
Checks for common privilege escalation vectors and misconfigurations
Enhanced with OS-specific checks and confidence scoring
"""

import os
import platform
import subprocess
import sys

# Import common utilities for verification and confidence scoring
try:
    from common_utils import (
        is_linux, is_windows, is_macos,
        verify_suid_binary, verify_writable, verify_executable,
        create_finding, calculate_confidence_score, get_confidence_level,
        safe_run_command, get_dangerous_binaries
    )
except ImportError:
    # Fallback if common_utils not available
    def is_linux(): return platform.system().lower() == 'linux'
    def is_windows(): return platform.system().lower() == 'windows'
    def is_macos(): return platform.system().lower() == 'darwin'
    def create_finding(sev, find, desc, rem, conf=None, ver=False):
        f = {"severity": sev, "finding": find, "description": desc, "remediation": rem}
        if conf: f["confidence_score"] = conf
        return f

def check():
    """
    Check for privilege escalation vulnerabilities
    OS-specific with confidence scoring
    """
    results = {
        "module": "privilege_escalation",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # OS-specific privilege checks
        if is_linux() or is_macos():
            results["findings"].extend(check_linux_privileges())
        elif is_windows():
            results["findings"].extend(check_windows_privileges())
        else:
            results["findings"].append(create_finding(
                "info",
                "Unsupported OS",
                f"Privilege escalation checks not implemented for {platform.system()}",
                "Run module on Linux or Windows system",
                0
            ))

    except Exception as e:
        results["error"] = str(e)

    return results

def check_linux_privileges():
    """Linux-specific privilege escalation checks"""
    findings = []

    # Check if running as root
    try:
        if os.geteuid() == 0:
            findings.append(create_finding(
                "info",
                "Running as root",
                "Agent has root privileges",
                "No action needed - informational",
                100,
                True
            ))
    except:
        pass

    # Enhanced SUID binary checks
    findings.extend(check_suid_binaries_enhanced())

    # Enhanced sudo configuration checks
    findings.extend(check_sudo_config_enhanced())

    # Enhanced writable service files
    findings.extend(check_writable_services_enhanced())

    # Kernel version information
    findings.extend(check_kernel_version())

    # Enhanced writable PATH directories
    findings.extend(check_writable_path_enhanced())

    # Enhanced capabilities check
    findings.extend(check_capabilities_enhanced())

    # Additional Linux checks
    findings.extend(check_cron_permissions())
    findings.extend(check_docker_socket())

    return findings

def check_windows_privileges():
    """Windows-specific privilege escalation checks"""
    findings = []

    # Check if running as Administrator
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        findings.append(create_finding(
            "info",
            "Running as Administrator" if is_admin else "Running as standard user",
            f"Agent has {'administrator' if is_admin else 'standard user'} privileges",
            "No action needed - informational",
            100,
            True
        ))
    except:
        pass

    # Check for AlwaysInstallElevated
    findings.extend(check_always_install_elevated())

    # Check for unquoted service paths
    findings.extend(check_unquoted_service_paths())

    # Check for writable service binaries
    findings.extend(check_writable_service_binaries())

    # Check scheduled tasks
    findings.extend(check_scheduled_tasks())

    # Check registry autoruns
    findings.extend(check_registry_autoruns())

    # Check token privileges (NEW - Critical!)
    findings.extend(check_token_privileges())

    # Check DLL hijacking opportunities (NEW - High impact!)
    findings.extend(check_dll_hijacking())

    # Check writable system paths
    findings.extend(check_writable_system_paths())

    return findings

def check_suid_binaries_enhanced():
    """Enhanced SUID binary checks with multi-method verification"""
    findings = []

    try:
        # Common directories to check
        search_paths = ['/usr/bin', '/usr/local/bin', '/bin', '/sbin', '/usr/sbin', '/usr/local/sbin']

        # Get OS-specific dangerous binaries
        dangerous_binaries = get_dangerous_binaries()

        suid_binaries_found = {}

        # Method 1: Use find command
        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue

            try:
                result = subprocess.run(
                    ['find', search_path, '-perm', '-4000', '-type', 'f'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    suid_files = [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]

                    for suid_file in suid_files:
                        # Use multi-method verification
                        has_suid, confidence = verify_suid_binary(suid_file)

                        if has_suid:
                            basename = os.path.basename(suid_file)
                            suid_binaries_found[suid_file] = {
                                'basename': basename,
                                'confidence': confidence,
                                'dangerous': basename in dangerous_binaries
                            }

            except (subprocess.TimeoutExpired, Exception):
                continue

        # Create findings with confidence scores
        for suid_file, info in suid_binaries_found.items():
            basename = info['basename']
            confidence = info['confidence']
            is_dangerous = info['dangerous']

            if is_dangerous:
                # High severity for dangerous binaries
                findings.append(create_finding(
                    "high",
                    f"Dangerous SUID binary: {suid_file}",
                    f"{basename} with SUID bit can be exploited for privilege escalation. "
                    f"This binary is known to have privilege escalation techniques. "
                    f"Verification confidence: {confidence}%",
                    f"Remove SUID bit: chmod u-s {suid_file}",
                    confidence,
                    confidence >= 95
                ))
            else:
                # Medium severity for other SUID binaries
                findings.append(create_finding(
                    "medium",
                    f"SUID binary found: {suid_file}",
                    f"Binary {basename} has SUID bit set. Review if necessary. "
                    f"Verification confidence: {confidence}%",
                    f"Verify if SUID permission is required, or remove: chmod u-s {suid_file}",
                    confidence,
                    confidence >= 95
                ))

    except Exception as e:
        findings.append(create_finding(
            "info",
            "SUID check encountered error",
            str(e),
            "Review system permissions manually",
            0
        ))

    return findings

def check_sudo_config_enhanced():
    """Enhanced sudo configuration checks with verification"""
    findings = []

    try:
        # Multi-method verification of sudo access
        checks = []

        # Method 1: Try sudo -l
        result = subprocess.run(
            ['sudo', '-n', '-l'],
            capture_output=True,
            text=True,
            timeout=5
        )
        sudo_accessible = result.returncode == 0
        checks.append(sudo_accessible)

        if not sudo_accessible:
            # Can't check sudo config
            return findings

        # Method 2: Read sudo output
        result = subprocess.run(
            ['sudo', '-l'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return findings

        output = result.stdout.lower()
        checks.append(len(output) > 0)

        base_confidence = calculate_confidence_score(*checks)

        # Check for NOPASSWD
        if 'nopasswd' in output:
            # Count occurrences for confidence
            nopasswd_count = output.count('nopasswd')
            confidence = min(100, base_confidence + (nopasswd_count * 10))

            findings.append(create_finding(
                "high",
                "Sudo NOPASSWD configured",
                f"User can run sudo commands without password authentication. "
                f"Found {nopasswd_count} NOPASSWD entries. This significantly weakens security. "
                f"Verification confidence: {confidence}%",
                "Review /etc/sudoers and remove NOPASSWD entries: sudo visudo",
                confidence,
                confidence >= 95
            ))

        # Check for ALL=(ALL) or ALL=(ALL:ALL)
        if ('all' in output and '(all)' in output) or 'all=(all:all)' in output:
            all_count = output.count('(all)')
            confidence = min(100, base_confidence + (all_count * 10))

            findings.append(create_finding(
                "critical",
                "Sudo ALL privileges granted",
                f"User can run all commands as any user with sudo. This is equivalent to root access. "
                f"Verification confidence: {confidence}%",
                "Restrict sudo privileges to specific commands only: sudo visudo",
                confidence,
                confidence >= 95
            ))

        # Check for specific dangerous commands
        dangerous_cmds = {
            'vim': 'Can escape to shell with :!/bin/bash',
            'vi': 'Can escape to shell with :!/bin/bash',
            'nano': 'Can execute commands with Ctrl+R Ctrl+X',
            'python': 'Can spawn shell with os.system()',
            'perl': 'Can execute system commands',
            'bash': 'Direct shell access',
            'sh': 'Direct shell access',
            'less': 'Can escape to shell with !bash',
            'more': 'Can escape to shell with !bash',
            'find': 'Can execute commands with -exec',
            'awk': 'Can execute system commands',
            'man': 'Can escape to shell with !bash'
        }

        for cmd, exploit in dangerous_cmds.items():
            if cmd in output:
                # Check if it's in a command context
                cmd_confidence = base_confidence
                if f'/{cmd}' in output:
                    cmd_confidence = min(100, base_confidence + 20)

                findings.append(create_finding(
                    "high",
                    f"Sudo privilege for dangerous command: {cmd}",
                    f"User can run {cmd} with sudo, which allows privilege escalation. "
                    f"Exploit method: {exploit}. "
                    f"Verification confidence: {cmd_confidence}%",
                    f"Remove sudo privilege for {cmd} or use sudoedit for file editing",
                    cmd_confidence,
                    cmd_confidence >= 95
                ))

    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        pass

    return findings

def check_writable_services_enhanced():
    """Enhanced check for writable systemd service files with verification"""
    findings = []

    try:
        service_dirs = [
            '/etc/systemd/system',
            '/lib/systemd/system',
            '/usr/lib/systemd/system',
            '/run/systemd/system'
        ]

        for service_dir in service_dirs:
            if not os.path.exists(service_dir):
                continue

            for root, dirs, files in os.walk(service_dir):
                for file in files:
                    if file.endswith('.service'):
                        filepath = os.path.join(root, file)

                        # Use multi-method verification
                        is_writable, confidence = verify_writable(filepath)

                        if is_writable:
                            # Check if service is enabled/active for severity
                            severity = "high"
                            service_name = file

                            # Try to check if service is active
                            try:
                                result = subprocess.run(
                                    ['systemctl', 'is-active', service_name],
                                    capture_output=True,
                                    text=True,
                                    timeout=2
                                )
                                is_active = result.returncode == 0
                                if is_active:
                                    severity = "critical"
                                    confidence = min(100, confidence + 10)
                            except:
                                pass

                            findings.append(create_finding(
                                severity,
                                f"Writable service file: {filepath}",
                                f"Service file is writable by current user. "
                                f"Can be modified to execute arbitrary code as root when service starts. "
                                f"Service is {'active' if severity == 'critical' else 'potentially inactive'}. "
                                f"Verification confidence: {confidence}%",
                                f"Fix permissions: sudo chmod 644 {filepath} && sudo chown root:root {filepath}",
                                confidence,
                                confidence >= 95
                            ))

    except Exception as e:
        pass

    return findings

def check_kernel_version():
    """Check kernel version for known vulnerabilities"""
    findings = []

    try:
        kernel_version = platform.release()

        findings.append({
            "severity": "info",
            "finding": f"Kernel version: {kernel_version}",
            "description": "Check for known kernel exploits for this version",
            "remediation": "Keep kernel updated to latest version"
        })

    except Exception:
        pass

    return findings

def check_writable_path_enhanced():
    """Enhanced check for writable directories in PATH with verification"""
    findings = []

    try:
        path_dirs = os.environ.get('PATH', '').split(':')

        for path_dir in path_dirs:
            if not path_dir or not os.path.exists(path_dir):
                continue

            # Use multi-method verification
            is_writable, confidence = verify_writable(path_dir)

            if is_writable:
                # Check position in PATH for severity
                path_position = path_dirs.index(path_dir)
                severity = "high" if path_position < 3 else "medium"

                # Higher confidence if earlier in PATH
                if path_position == 0:
                    confidence = min(100, confidence + 15)
                elif path_position < 3:
                    confidence = min(100, confidence + 10)

                findings.append(create_finding(
                    severity,
                    f"Writable PATH directory: {path_dir}",
                    f"PATH directory is writable by current user (position {path_position + 1} in PATH). "
                    f"Attacker can place malicious binaries that will be executed with elevated privileges. "
                    f"{'Early position in PATH increases exploit likelihood.' if path_position < 3 else ''} "
                    f"Verification confidence: {confidence}%",
                    f"Fix permissions: sudo chmod 755 {path_dir} && sudo chown root:root {path_dir}",
                    confidence,
                    confidence >= 95
                ))

    except Exception as e:
        pass

    return findings

def check_capabilities_enhanced():
    """Enhanced check for binaries with dangerous Linux capabilities"""
    findings = []

    try:
        # Check if getcap is available
        result = subprocess.run(
            ['which', 'getcap'],
            capture_output=True,
            timeout=2
        )

        if result.returncode != 0:
            return findings  # getcap not available

        # Search common directories for capabilities
        search_paths = ['/usr/bin', '/usr/local/bin', '/bin', '/sbin', '/usr/sbin']

        dangerous_caps = {
            'cap_setuid': 'Can change UID - allows privilege escalation',
            'cap_setgid': 'Can change GID - allows group privilege escalation',
            'cap_dac_override': 'Can bypass file read/write/execute permission checks',
            'cap_dac_read_search': 'Can bypass file and directory read permission checks',
            'cap_sys_admin': 'Can perform system administration operations',
            'cap_sys_ptrace': 'Can trace arbitrary processes',
            'cap_sys_module': 'Can load/unload kernel modules',
            'cap_net_admin': 'Can perform network administration',
            'cap_net_raw': 'Can use RAW and PACKET sockets'
        }

        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue

            try:
                result = subprocess.run(
                    ['getcap', '-r', search_path],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    stderr=subprocess.DEVNULL
                )

                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().split('\n'):
                        if '=' in line:
                            parts = line.split('=')
                            if len(parts) >= 2:
                                binary_path = parts[0].strip()
                                caps_str = parts[1].strip()

                                # Verify the file has capabilities
                                checks = []
                                checks.append('cap_' in caps_str.lower())

                                # Verify file exists and is executable
                                if os.path.exists(binary_path):
                                    checks.append(True)
                                    is_exec, exec_conf = verify_executable(binary_path)
                                    checks.append(is_exec)

                                confidence = calculate_confidence_score(*checks)

                                # Check if any dangerous capability is present
                                is_dangerous = False
                                dangerous_cap_found = []
                                for cap, description in dangerous_caps.items():
                                    if cap in caps_str.lower():
                                        is_dangerous = True
                                        dangerous_cap_found.append((cap, description))

                                severity = "high" if is_dangerous else "medium"

                                if is_dangerous:
                                    for cap, desc in dangerous_cap_found:
                                        findings.append(create_finding(
                                            severity,
                                            f"Dangerous capability on {binary_path}: {cap}",
                                            f"Binary has {cap} capability. {desc}. "
                                            f"Full capabilities: {caps_str}. "
                                            f"Verification confidence: {confidence}%",
                                            f"Remove capability if not needed: sudo setcap -r {binary_path}",
                                            confidence,
                                            confidence >= 95
                                        ))
                                else:
                                    findings.append(create_finding(
                                        severity,
                                        f"Capability found on {binary_path}",
                                        f"Binary has capabilities: {caps_str}. Review if necessary. "
                                        f"Verification confidence: {confidence}%",
                                        f"Review and remove if not needed: sudo setcap -r {binary_path}",
                                        confidence,
                                        confidence >= 95
                                    ))

            except (subprocess.TimeoutExpired, Exception):
                continue

    except Exception as e:
        pass

    return findings

def check_cron_permissions():
    """Check for writable cron files and directories"""
    findings = []

    try:
        cron_locations = [
            '/etc/crontab',
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.monthly',
            '/etc/cron.weekly',
            '/var/spool/cron',
            '/var/spool/cron/crontabs'
        ]

        for location in cron_locations:
            if not os.path.exists(location):
                continue

            # Check if writable
            is_writable, confidence = verify_writable(location)

            if is_writable:
                is_file = os.path.isfile(location)
                item_type = "file" if is_file else "directory"

                findings.append(create_finding(
                    "critical",
                    f"Writable cron {item_type}: {location}",
                    f"Cron {item_type} is writable by current user. "
                    f"Can be modified to execute arbitrary commands as root. "
                    f"This is a direct privilege escalation vector. "
                    f"Verification confidence: {confidence}%",
                    f"Fix permissions: sudo chmod {'644' if is_file else '755'} {location} && sudo chown root:root {location}",
                    confidence,
                    confidence >= 95
                ))

    except Exception:
        pass

    return findings

def check_docker_socket():
    """Check for accessible Docker socket (common privilege escalation)"""
    findings = []

    try:
        docker_socket = '/var/run/docker.sock'

        if not os.path.exists(docker_socket):
            return findings

        # Check if current user can access docker socket
        checks = []
        checks.append(os.path.exists(docker_socket))

        # Check if writable
        is_writable, write_confidence = verify_writable(docker_socket)
        checks.append(is_writable)

        # Check if can connect
        can_read = os.access(docker_socket, os.R_OK)
        checks.append(can_read)

        confidence = calculate_confidence_score(*checks)

        if is_writable or can_read:
            findings.append(create_finding(
                "critical",
                "Accessible Docker socket",
                f"Docker socket is accessible by current user. "
                f"User can spawn privileged containers and break out to host root. "
                f"This provides direct root access on the host system. "
                f"Socket permissions: {'writable' if is_writable else 'readable'}. "
                f"Verification confidence: {confidence}%",
                "Remove user from docker group or restrict socket permissions: sudo chmod 660 /var/run/docker.sock",
                confidence,
                confidence >= 95
            ))

    except Exception:
        pass

    return findings

# Windows-specific privilege escalation checks

def check_always_install_elevated():
    """Check for AlwaysInstallElevated registry keys (Windows)"""
    findings = []

    if not is_windows():
        return findings

    try:
        import winreg

        checks = []
        keys_to_check = [
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\Installer'),
            (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Policies\Microsoft\Windows\Installer')
        ]

        hklm_enabled = False
        hkcu_enabled = False

        # Check HKLM
        try:
            key = winreg.OpenKey(keys_to_check[0][0], keys_to_check[0][1])
            value, _ = winreg.QueryValueEx(key, 'AlwaysInstallElevated')
            hklm_enabled = (value == 1)
            checks.append(hklm_enabled)
            winreg.CloseKey(key)
        except:
            checks.append(False)

        # Check HKCU
        try:
            key = winreg.OpenKey(keys_to_check[1][0], keys_to_check[1][1])
            value, _ = winreg.QueryValueEx(key, 'AlwaysInstallElevated')
            hkcu_enabled = (value == 1)
            checks.append(hkcu_enabled)
            winreg.CloseKey(key)
        except:
            checks.append(False)

        confidence = calculate_confidence_score(*checks)

        # Both must be set for vulnerability
        if hklm_enabled and hkcu_enabled:
            findings.append(create_finding(
                "critical",
                "AlwaysInstallElevated enabled",
                f"Both HKLM and HKCU AlwaysInstallElevated registry keys are set. "
                f"Any user can install MSI packages with SYSTEM privileges. "
                f"This allows immediate privilege escalation. "
                f"Verification confidence: {confidence}%",
                "Disable AlwaysInstallElevated in Group Policy or remove registry keys",
                confidence,
                confidence >= 95
            ))
        elif hklm_enabled or hkcu_enabled:
            findings.append(create_finding(
                "medium",
                f"AlwaysInstallElevated partially configured",
                f"Only {'HKLM' if hklm_enabled else 'HKCU'} AlwaysInstallElevated key is set. "
                f"Not exploitable unless both are set. "
                f"Verification confidence: {confidence}%",
                "Review registry configuration",
                confidence,
                confidence >= 95
            ))

    except Exception:
        pass

    return findings

def check_unquoted_service_paths():
    """Check for unquoted service paths (Windows)"""
    findings = []

    if not is_windows():
        return findings

    try:
        # Query services using sc query
        result = subprocess.run(
            ['sc', 'query', 'state=', 'all'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return findings

        # Get service names
        services = []
        for line in result.stdout.split('\n'):
            if 'SERVICE_NAME:' in line:
                service_name = line.split(':', 1)[1].strip()
                services.append(service_name)

        # Check each service for unquoted path
        for service in services[:50]:  # Limit to first 50 to avoid timeout
            try:
                result = subprocess.run(
                    ['sc', 'qc', service],
                    capture_output=True,
                    text=True,
                    timeout=2
                )

                if result.returncode == 0:
                    output = result.stdout
                    for line in output.split('\n'):
                        if 'BINARY_PATH_NAME' in line:
                            path = line.split(':', 1)[1].strip()

                            # Check if path contains spaces and is not quoted
                            if ' ' in path and not path.startswith('"'):
                                # Remove common prefixes
                                clean_path = path
                                for prefix in ['\\??\\', '\\SystemRoot\\']:
                                    if clean_path.startswith(prefix):
                                        clean_path = clean_path[len(prefix):]

                                # Extract directory path
                                parts = clean_path.split()
                                if len(parts) > 1:
                                    # Verify the path exists
                                    checks = []
                                    checks.append(' ' in path)
                                    checks.append(not path.startswith('"'))

                                    confidence = calculate_confidence_score(*checks)

                                    findings.append(create_finding(
                                        "high",
                                        f"Unquoted service path: {service}",
                                        f"Service has unquoted path with spaces: {path}. "
                                        f"If any directory in path is writable, attacker can place malicious executable. "
                                        f"Verification confidence: {confidence}%",
                                        f"Quote the service path or check directory permissions",
                                        confidence,
                                        confidence >= 95
                                    ))
            except:
                continue

    except Exception:
        pass

    return findings

def check_writable_service_binaries():
    """Check for writable service binaries (Windows)"""
    findings = []

    if not is_windows():
        return findings

    try:
        # Query services
        result = subprocess.run(
            ['sc', 'query', 'state=', 'all'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return findings

        services = []
        for line in result.stdout.split('\n'):
            if 'SERVICE_NAME:' in line:
                service_name = line.split(':', 1)[1].strip()
                services.append(service_name)

        # Check service binaries
        for service in services[:30]:  # Limit check
            try:
                result = subprocess.run(
                    ['sc', 'qc', service],
                    capture_output=True,
                    text=True,
                    timeout=2
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'BINARY_PATH_NAME' in line:
                            path = line.split(':', 1)[1].strip().strip('"')

                            # Extract executable path
                            exe_path = path.split()[0] if ' ' in path else path

                            if os.path.exists(exe_path):
                                # Check if writable
                                is_writable, confidence = verify_writable(exe_path)

                                if is_writable:
                                    findings.append(create_finding(
                                        "critical",
                                        f"Writable service binary: {service}",
                                        f"Service binary is writable: {exe_path}. "
                                        f"Can be replaced with malicious executable that runs as SYSTEM. "
                                        f"Verification confidence: {confidence}%",
                                        f"Fix permissions on service binary: {exe_path}",
                                        confidence,
                                        confidence >= 95
                                    ))
            except:
                continue

    except Exception:
        pass

    return findings

def check_scheduled_tasks():
    """Check for misconfigured scheduled tasks (Windows)"""
    findings = []

    if not is_windows():
        return findings

    try:
        # Query scheduled tasks
        result = subprocess.run(
            ['schtasks', '/query', '/fo', 'LIST', '/v'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return findings

        # Parse output for tasks running as SYSTEM with writable binaries
        current_task = {}
        for line in result.stdout.split('\n'):
            line = line.strip()

            if line.startswith('TaskName:'):
                if current_task:
                    # Check previous task
                    if current_task.get('user') == 'SYSTEM' and current_task.get('task_to_run'):
                        task_path = current_task['task_to_run']
                        if os.path.exists(task_path):
                            is_writable, confidence = verify_writable(task_path)
                            if is_writable:
                                findings.append(create_finding(
                                    "critical",
                                    f"Writable scheduled task binary: {current_task['name']}",
                                    f"Scheduled task runs as SYSTEM with writable binary: {task_path}. "
                                    f"Verification confidence: {confidence}%",
                                    f"Fix permissions on task binary: {task_path}",
                                    confidence,
                                    confidence >= 95
                                ))

                # Start new task
                current_task = {'name': line.split(':', 1)[1].strip()}

            elif line.startswith('Run As User:'):
                current_task['user'] = line.split(':', 1)[1].strip()

            elif line.startswith('Task To Run:'):
                current_task['task_to_run'] = line.split(':', 1)[1].strip()

    except Exception:
        pass

    return findings

def check_registry_autoruns():
    """Check for writable registry autorun locations (Windows)"""
    findings = []

    if not is_windows():
        return findings

    try:
        import winreg

        autorun_keys = [
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
            (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
        ]

        for hive, key_path in autorun_keys:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE)

                hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"

                # If we can open with write access, it's writable
                findings.append(create_finding(
                    "high" if hive_name == "HKLM" else "medium",
                    f"Writable autorun registry key: {hive_name}\\{key_path}",
                    f"Registry autorun key is writable. "
                    f"Can add malicious programs to auto-start. "
                    f"{'Affects all users.' if hive_name == 'HKLM' else 'Affects current user.'}",
                    f"Review and restrict permissions on registry key",
                    100,
                    True
                ))

                winreg.CloseKey(key)
            except PermissionError:
                # Expected - key is not writable
                pass
            except:
                pass

    except Exception:
        pass

    return findings

def check_token_privileges():
    """Check for dangerous Windows token privileges (CRITICAL!)"""
    findings = []

    if not is_windows():
        return findings

    try:
        import ctypes
        from ctypes import wintypes

        # Define privilege constants
        SE_PRIVILEGE_ENABLED = 0x00000002
        TOKEN_QUERY = 0x0008

        # Dangerous privileges that allow privilege escalation
        dangerous_privileges = {
            'SeImpersonatePrivilege': {
                'description': 'Can impersonate other users/tokens',
                'exploits': 'PrintSpoofer, RoguePotato, JuicyPotato',
                'severity': 'critical'
            },
            'SeAssignPrimaryTokenPrivilege': {
                'description': 'Can assign primary token to process',
                'exploits': 'Token manipulation attacks',
                'severity': 'critical'
            },
            'SeDebugPrivilege': {
                'description': 'Can debug any process (including SYSTEM)',
                'exploits': 'Process injection, memory manipulation',
                'severity': 'critical'
            },
            'SeLoadDriverPrivilege': {
                'description': 'Can load kernel drivers',
                'exploits': 'Capcom.sys, other vulnerable drivers',
                'severity': 'critical'
            },
            'SeTakeOwnershipPrivilege': {
                'description': 'Can take ownership of any object',
                'exploits': 'File/registry ownership hijacking',
                'severity': 'high'
            },
            'SeRestorePrivilege': {
                'description': 'Can write to any file/registry',
                'exploits': 'File/registry replacement',
                'severity': 'high'
            },
            'SeBackupPrivilege': {
                'description': 'Can read any file (bypass ACLs)',
                'exploits': 'SAM/SYSTEM hive extraction',
                'severity': 'high'
            },
            'SeTcbPrivilege': {
                'description': 'Act as part of operating system',
                'exploits': 'Full system compromise',
                'severity': 'critical'
            }
        }

        # Get current process token
        handle = ctypes.c_void_p()
        if not ctypes.windll.advapi32.OpenProcessToken(
            ctypes.windll.kernel32.GetCurrentProcess(),
            TOKEN_QUERY,
            ctypes.byref(handle)
        ):
            return findings

        # Check each dangerous privilege
        found_privileges = []

        for priv_name, priv_info in dangerous_privileges.items():
            # Look up privilege LUID
            luid = wintypes.LUID()
            if ctypes.windll.advapi32.LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):

                # Check if privilege is enabled
                class PRIVILEGE_SET(ctypes.Structure):
                    _fields_ = [
                        ("PrivilegeCount", wintypes.DWORD),
                        ("Control", wintypes.DWORD),
                        ("Privilege", wintypes.LUID * 1),
                    ]

                priv_set = PRIVILEGE_SET()
                priv_set.PrivilegeCount = 1
                priv_set.Privilege[0] = luid

                result = wintypes.BOOL()
                if ctypes.windll.advapi32.PrivilegeCheck(
                    handle,
                    ctypes.byref(priv_set),
                    ctypes.byref(result)
                ):
                    if result.value:
                        found_privileges.append((priv_name, priv_info))

        ctypes.windll.kernel32.CloseHandle(handle)

        # Create findings for dangerous privileges
        if found_privileges:
            for priv_name, priv_info in found_privileges:
                findings.append(create_finding(
                    priv_info['severity'],
                    f"Dangerous token privilege: {priv_name}",
                    f"{priv_info['description']}. "
                    f"This privilege allows privilege escalation to SYSTEM. "
                    f"Known exploits: {priv_info['exploits']}. "
                    f"Verification confidence: 100%",
                    f"This is expected for service accounts. If running as regular user, investigate how privilege was obtained.",
                    100,
                    True
                ))

    except Exception as e:
        # Privilege checking failed - try alternate method
        try:
            # Fallback: Use whoami /priv command
            result = subprocess.run(
                ['whoami', '/priv'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                output = result.stdout

                # Check for dangerous privileges in output
                for priv_name, priv_info in dangerous_privileges.items():
                    if priv_name in output and 'Enabled' in output:
                        findings.append(create_finding(
                            priv_info['severity'],
                            f"Dangerous token privilege: {priv_name}",
                            f"{priv_info['description']}. "
                            f"Known exploits: {priv_info['exploits']}. "
                            f"Detected via whoami command. "
                            f"Verification confidence: 95%",
                            f"Investigate how privilege was obtained",
                            95,
                            True
                        ))

        except Exception:
            pass

    return findings

def check_dll_hijacking():
    """Check for DLL hijacking opportunities (Windows)"""
    findings = []

    if not is_windows():
        return findings

    try:
        # Check PATH for writable directories (DLL search order exploitation)
        path_env = os.environ.get('PATH', '')
        if not path_env:
            return findings

        path_dirs = path_env.split(';')

        writable_dirs = []
        early_writable = []

        for idx, path_dir in enumerate(path_dirs):
            if not path_dir or not os.path.exists(path_dir):
                continue

            try:
                # Check if writable
                is_writable, confidence = verify_writable(path_dir)

                if is_writable:
                    writable_dirs.append((path_dir, idx, confidence))

                    # Early PATH positions are more dangerous
                    if idx < 3:
                        early_writable.append((path_dir, idx))

            except Exception:
                continue

        # Report writable PATH directories (DLL hijacking opportunity)
        if writable_dirs:
            for path_dir, position, confidence in writable_dirs:
                severity = "critical" if position < 3 else "high"

                # System directories in writable PATH are especially bad
                is_system_path = any(sys_dir in path_dir.lower() for sys_dir in [
                    'windows', 'system32', 'syswow64', 'program files'
                ])

                if is_system_path:
                    severity = "critical"
                    confidence = min(100, confidence + 10)

                findings.append(create_finding(
                    severity,
                    f"DLL hijacking opportunity: Writable PATH directory at position {position + 1}",
                    f"Directory '{path_dir}' is writable and in PATH. "
                    f"Attacker can place malicious DLLs that will be loaded before system DLLs. "
                    f"Position {position + 1} in DLL search order. "
                    f"{'CRITICAL: System directory is writable!' if is_system_path else 'Can hijack DLL loading.'} "
                    f"Verification confidence: {confidence}%",
                    f"Remove '{path_dir}' from PATH or fix permissions",
                    confidence,
                    confidence >= 95
                ))

        # Check current directory in PATH (. or empty entry)
        if '.' in path_dirs or '' in path_dirs:
            findings.append(create_finding(
                "high",
                "Current directory in PATH (DLL hijacking risk)",
                "PATH contains current directory (. or empty entry). "
                "DLLs in current directory will be loaded before system DLLs. "
                "Attacker can place malicious DLL in any directory user navigates to. "
                "Verification confidence: 100%",
                "Remove current directory from PATH",
                100,
                True
            ))

        # Check for writable system directories (extreme risk)
        system_dirs = [
            os.environ.get('SYSTEMROOT', 'C:\\Windows'),
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32'),
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64'),
        ]

        for sys_dir in system_dirs:
            if os.path.exists(sys_dir):
                is_writable, confidence = verify_writable(sys_dir)

                if is_writable:
                    findings.append(create_finding(
                        "critical",
                        f"System directory is writable: {sys_dir}",
                        f"Critical Windows system directory is writable by current user. "
                        f"Can replace system DLLs with malicious versions. "
                        f"This indicates severe privilege escalation or system misconfiguration. "
                        f"Verification confidence: {confidence}%",
                        f"This should never happen. Investigate immediately: Check system integrity",
                        confidence,
                        confidence >= 95
                    ))

    except Exception as e:
        pass

    return findings

def check_writable_system_paths():
    """Check for writable critical Windows system paths"""
    findings = []

    if not is_windows():
        return findings

    try:
        # Critical system locations that should NEVER be writable
        critical_paths = {
            os.environ.get('SYSTEMROOT', 'C:\\Windows'): 'Windows directory',
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32'): 'System32 directory',
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64'): 'SysWOW64 directory',
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\config'): 'Registry hive location',
            'C:\\Program Files': 'Program Files directory',
            'C:\\Program Files (x86)': 'Program Files (x86) directory',
        }

        for path, description in critical_paths.items():
            if not os.path.exists(path):
                continue

            is_writable, confidence = verify_writable(path)

            if is_writable:
                findings.append(create_finding(
                    "critical",
                    f"Critical system path is writable: {path}",
                    f"{description} is writable by current user. "
                    f"This allows replacement of system files, DLLs, or executables. "
                    f"Indicates privilege escalation or severe misconfiguration. "
                    f"Verification confidence: {confidence}%",
                    f"Investigate immediately: {path} should not be writable. Check system integrity and permissions.",
                    confidence,
                    confidence >= 95
                ))

        # Check Program Files subdirectories (common target)
        program_files_dirs = [
            'C:\\Program Files',
            'C:\\Program Files (x86)'
        ]

        for pf_dir in program_files_dirs:
            if not os.path.exists(pf_dir):
                continue

            try:
                # Check top-level subdirectories
                for subdir in os.listdir(pf_dir)[:20]:  # Limit to first 20
                    subdir_path = os.path.join(pf_dir, subdir)

                    if not os.path.isdir(subdir_path):
                        continue

                    is_writable, confidence = verify_writable(subdir_path)

                    if is_writable:
                        findings.append(create_finding(
                            "high",
                            f"Writable Program Files subdirectory: {subdir_path}",
                            f"Application directory in Program Files is writable. "
                            f"Can replace application binaries or inject DLLs. "
                            f"Verification confidence: {confidence}%",
                            f"Fix permissions: Remove write access for standard users",
                            confidence,
                            confidence >= 95
                        ))

            except Exception:
                pass

    except Exception:
        pass

    return findings

if __name__ == '__main__':
    # Test module
    import json
    results = check()
    print(json.dumps(results, indent=2))
