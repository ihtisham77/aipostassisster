"""
Privilege Escalation Assessment Module
Checks for common privilege escalation vectors and misconfigurations
"""

import os
import platform
import subprocess
import pwd
import grp

def check():
    """
    Check for privilege escalation vulnerabilities
    """
    results = {
        "module": "privilege_escalation",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # Check if running as root
        if os.geteuid() == 0:
            results["findings"].append({
                "severity": "info",
                "finding": "Running as root",
                "description": "Agent has root privileges"
            })

        # Check for SUID binaries
        suid_findings = check_suid_binaries()
        if suid_findings:
            results["findings"].extend(suid_findings)

        # Check sudo configuration
        sudo_findings = check_sudo_config()
        if sudo_findings:
            results["findings"].extend(sudo_findings)

        # Check for writable service files
        service_findings = check_writable_services()
        if service_findings:
            results["findings"].extend(service_findings)

        # Check kernel version
        kernel_findings = check_kernel_version()
        if kernel_findings:
            results["findings"].extend(kernel_findings)

        # Check for writable PATH directories
        path_findings = check_writable_path()
        if path_findings:
            results["findings"].extend(path_findings)

        # Check capabilities
        cap_findings = check_capabilities()
        if cap_findings:
            results["findings"].extend(cap_findings)

    except Exception as e:
        results["error"] = str(e)

    return results

def check_suid_binaries():
    """Check for SUID binaries that could be exploited"""
    findings = []

    try:
        # Common directories to check
        search_paths = ['/usr/bin', '/usr/local/bin', '/bin', '/sbin', '/usr/sbin']

        dangerous_binaries = [
            'nmap', 'vim', 'find', 'bash', 'more', 'less', 'nano',
            'cp', 'mv', 'python', 'perl', 'ruby', 'lua', 'php',
            'awk', 'sed', 'tar', 'zip', 'unzip'
        ]

        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue

            try:
                result = subprocess.run(
                    ['find', search_path, '-perm', '-4000', '-type', 'f', '2>/dev/null'],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=False
                )

                suid_files = result.stdout.strip().split('\n')

                for suid_file in suid_files:
                    if suid_file:
                        basename = os.path.basename(suid_file)
                        if basename in dangerous_binaries:
                            findings.append({
                                "severity": "high",
                                "finding": f"Dangerous SUID binary: {suid_file}",
                                "description": f"{basename} with SUID bit can be exploited for privilege escalation",
                                "remediation": f"Remove SUID bit: chmod u-s {suid_file}"
                            })
                        else:
                            findings.append({
                                "severity": "medium",
                                "finding": f"SUID binary found: {suid_file}",
                                "description": "Review if SUID bit is necessary",
                                "remediation": "Verify if SUID permission is required"
                            })
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue

    except Exception as e:
        findings.append({
            "severity": "info",
            "finding": "SUID check failed",
            "description": str(e)
        })

    return findings

def check_sudo_config():
    """Check sudo configuration for misconfigurations"""
    findings = []

    try:
        # Check if user can run sudo
        result = subprocess.run(
            ['sudo', '-l'],
            capture_output=True,
            text=True,
            timeout=5
        )

        output = result.stdout.lower()

        # Check for NOPASSWD
        if 'nopasswd' in output:
            findings.append({
                "severity": "high",
                "finding": "Sudo NOPASSWD configured",
                "description": "User can run sudo commands without password",
                "remediation": "Review /etc/sudoers and remove NOPASSWD if not necessary"
            })

        # Check for ALL=(ALL)
        if 'all' in output and '(all)' in output:
            findings.append({
                "severity": "high",
                "finding": "Sudo ALL privileges",
                "description": "User can run all commands as any user",
                "remediation": "Restrict sudo privileges to specific commands"
            })

        # Check for specific dangerous commands
        dangerous_cmds = ['vim', 'vi', 'nano', 'python', 'perl', 'bash', 'sh']
        for cmd in dangerous_cmds:
            if cmd in output:
                findings.append({
                    "severity": "high",
                    "finding": f"Sudo privilege for {cmd}",
                    "description": f"User can run {cmd} with sudo, which can spawn root shell",
                    "remediation": f"Remove sudo privilege for {cmd}"
                })

    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return findings

def check_writable_services():
    """Check for writable systemd service files"""
    findings = []

    try:
        service_dirs = ['/etc/systemd/system', '/lib/systemd/system']

        for service_dir in service_dirs:
            if not os.path.exists(service_dir):
                continue

            for root, dirs, files in os.walk(service_dir):
                for file in files:
                    if file.endswith('.service'):
                        filepath = os.path.join(root, file)

                        # Check if writable by current user
                        if os.access(filepath, os.W_OK):
                            findings.append({
                                "severity": "high",
                                "finding": f"Writable service file: {filepath}",
                                "description": "Service file is writable, could be modified for privilege escalation",
                                "remediation": f"Fix permissions: chmod 644 {filepath}"
                            })

    except Exception:
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

def check_writable_path():
    """Check for writable directories in PATH"""
    findings = []

    try:
        path_dirs = os.environ.get('PATH', '').split(':')

        for path_dir in path_dirs:
            if os.path.exists(path_dir) and os.access(path_dir, os.W_OK):
                findings.append({
                    "severity": "medium",
                    "finding": f"Writable PATH directory: {path_dir}",
                    "description": "Writable PATH directory could be used for privilege escalation",
                    "remediation": f"Fix permissions: chmod 755 {path_dir}"
                })

    except Exception:
        pass

    return findings

def check_capabilities():
    """Check for binaries with dangerous capabilities"""
    findings = []

    try:
        result = subprocess.run(
            ['getcap', '-r', '/', '2>/dev/null'],
            capture_output=True,
            text=True,
            timeout=30,
            shell=True
        )

        output = result.stdout.strip()

        if output:
            for line in output.split('\n'):
                if 'cap_' in line:
                    findings.append({
                        "severity": "medium",
                        "finding": f"Capability found: {line}",
                        "description": "Binary has special capabilities that may be exploitable",
                        "remediation": "Review if capabilities are necessary"
                    })

    except Exception:
        pass

    return findings

if __name__ == '__main__':
    # Test module
    import json
    results = check()
    print(json.dumps(results, indent=2))
