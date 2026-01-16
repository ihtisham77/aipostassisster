"""
Persistence Assessment Module
Checks for persistence mechanisms and misconfigurations
"""

import os
import platform
import subprocess
import glob

def check():
    """
    Check for persistence mechanisms and vulnerabilities
    """
    results = {
        "module": "persistence",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # Check cron jobs
        cron_findings = check_cron_jobs()
        if cron_findings:
            results["findings"].extend(cron_findings)

        # Check systemd timers and services
        systemd_findings = check_systemd_persistence()
        if systemd_findings:
            results["findings"].extend(systemd_findings)

        # Check startup scripts
        startup_findings = check_startup_scripts()
        if startup_findings:
            results["findings"].extend(startup_findings)

        # Check user profile scripts
        profile_findings = check_profile_scripts()
        if profile_findings:
            results["findings"].extend(profile_findings)

        # Check SSH authorized_keys
        ssh_findings = check_ssh_keys()
        if ssh_findings:
            results["findings"].extend(ssh_findings)

        # Check writable init scripts
        init_findings = check_init_scripts()
        if init_findings:
            results["findings"].extend(init_findings)

    except Exception as e:
        results["error"] = str(e)

    return results

def check_cron_jobs():
    """Check for suspicious or writable cron jobs"""
    findings = []

    try:
        # Check user crontab
        result = subprocess.run(
            ['crontab', '-l'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0 and result.stdout.strip():
            findings.append({
                "severity": "info",
                "finding": "User crontab exists",
                "description": f"Crontab entries:\n{result.stdout}",
                "remediation": "Review crontab entries for unauthorized jobs"
            })

        # Check system cron directories
        cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly',
                     '/etc/cron.monthly', '/etc/cron.weekly']

        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir):
                for file in os.listdir(cron_dir):
                    filepath = os.path.join(cron_dir, file)

                    # Check if writable
                    if os.path.isfile(filepath) and os.access(filepath, os.W_OK):
                        findings.append({
                            "severity": "high",
                            "finding": f"Writable cron file: {filepath}",
                            "description": "Cron file is writable and could be modified for persistence",
                            "remediation": f"Fix permissions: chmod 644 {filepath}"
                        })

        # Check /etc/crontab
        if os.path.exists('/etc/crontab'):
            if os.access('/etc/crontab', os.W_OK):
                findings.append({
                    "severity": "high",
                    "finding": "Writable /etc/crontab",
                    "description": "System crontab is writable",
                    "remediation": "Fix permissions: chmod 644 /etc/crontab"
                })

    except Exception:
        pass

    return findings

def check_systemd_persistence():
    """Check systemd services and timers for persistence"""
    findings = []

    try:
        # Check for writable service files
        service_dirs = [
            '/etc/systemd/system',
            '/lib/systemd/system',
            os.path.expanduser('~/.config/systemd/user')
        ]

        for service_dir in service_dirs:
            if not os.path.exists(service_dir):
                continue

            for root, dirs, files in os.walk(service_dir):
                for file in files:
                    filepath = os.path.join(root, file)

                    if os.access(filepath, os.W_OK):
                        findings.append({
                            "severity": "high",
                            "finding": f"Writable systemd file: {filepath}",
                            "description": "Systemd unit file is writable",
                            "remediation": f"Fix permissions: chmod 644 {filepath}"
                        })

        # List all enabled services
        result = subprocess.run(
            ['systemctl', 'list-unit-files', '--state=enabled'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            findings.append({
                "severity": "info",
                "finding": "Enabled systemd services",
                "description": f"Services:\n{result.stdout[:500]}",
                "remediation": "Review enabled services for unauthorized units"
            })

    except Exception:
        pass

    return findings

def check_startup_scripts():
    """Check startup scripts for persistence mechanisms"""
    findings = []

    try:
        # Check /etc/rc.local
        if os.path.exists('/etc/rc.local'):
            if os.access('/etc/rc.local', os.W_OK):
                findings.append({
                    "severity": "high",
                    "finding": "Writable /etc/rc.local",
                    "description": "Startup script is writable",
                    "remediation": "Fix permissions: chmod 755 /etc/rc.local"
                })

            # Read content
            try:
                with open('/etc/rc.local', 'r') as f:
                    content = f.read()
                    if content.strip() and 'exit 0' not in content:
                        findings.append({
                            "severity": "medium",
                            "finding": "/etc/rc.local has content",
                            "description": f"Content:\n{content[:500]}",
                            "remediation": "Review /etc/rc.local for unauthorized commands"
                        })
            except Exception:
                pass

        # Check /etc/init.d scripts
        if os.path.exists('/etc/init.d'):
            for file in os.listdir('/etc/init.d'):
                filepath = os.path.join('/etc/init.d', file)

                if os.path.isfile(filepath) and os.access(filepath, os.W_OK):
                    findings.append({
                        "severity": "high",
                        "finding": f"Writable init script: {filepath}",
                        "description": "Init script is writable",
                        "remediation": f"Fix permissions: chmod 755 {filepath}"
                    })

    except Exception:
        pass

    return findings

def check_profile_scripts():
    """Check user profile scripts for persistence"""
    findings = []

    try:
        profile_files = [
            '~/.bashrc',
            '~/.bash_profile',
            '~/.profile',
            '~/.zshrc',
            '~/.config/fish/config.fish',
            '/etc/profile',
            '/etc/bash.bashrc'
        ]

        for profile_file in profile_files:
            expanded_path = os.path.expanduser(profile_file)

            if os.path.exists(expanded_path):
                # Check if writable by others
                stat_info = os.stat(expanded_path)
                if stat_info.st_mode & 0o002:  # World writable
                    findings.append({
                        "severity": "high",
                        "finding": f"World-writable profile: {expanded_path}",
                        "description": "Profile script is world-writable",
                        "remediation": f"Fix permissions: chmod 644 {expanded_path}"
                    })

                # Check for suspicious content
                try:
                    with open(expanded_path, 'r') as f:
                        content = f.read()

                        # Look for suspicious patterns
                        suspicious_patterns = [
                            'curl', 'wget', 'nc ', 'netcat', '/dev/tcp',
                            'base64', 'python -c', 'perl -e', 'bash -i'
                        ]

                        for pattern in suspicious_patterns:
                            if pattern in content:
                                findings.append({
                                    "severity": "medium",
                                    "finding": f"Suspicious pattern in {expanded_path}",
                                    "description": f"Found pattern: {pattern}",
                                    "remediation": "Review profile script for unauthorized commands"
                                })
                                break

                except Exception:
                    pass

    except Exception:
        pass

    return findings

def check_ssh_keys():
    """Check SSH authorized_keys for persistence"""
    findings = []

    try:
        ssh_dir = os.path.expanduser('~/.ssh')

        if os.path.exists(ssh_dir):
            # Check authorized_keys
            auth_keys = os.path.join(ssh_dir, 'authorized_keys')

            if os.path.exists(auth_keys):
                try:
                    with open(auth_keys, 'r') as f:
                        keys = f.readlines()

                    if keys:
                        findings.append({
                            "severity": "info",
                            "finding": "SSH authorized_keys exists",
                            "description": f"Number of keys: {len(keys)}",
                            "remediation": "Review authorized_keys for unauthorized keys"
                        })

                except Exception:
                    pass

            # Check if .ssh directory is writable
            if os.access(ssh_dir, os.W_OK):
                stat_info = os.stat(ssh_dir)
                if stat_info.st_mode & 0o022:  # Group or world writable
                    findings.append({
                        "severity": "high",
                        "finding": "Insecure .ssh directory permissions",
                        "description": ".ssh directory has incorrect permissions",
                        "remediation": f"Fix permissions: chmod 700 {ssh_dir}"
                    })

    except Exception:
        pass

    return findings

def check_init_scripts():
    """Check init scripts and startup directories"""
    findings = []

    try:
        # Check various startup directories
        startup_dirs = [
            '/etc/init.d',
            '/etc/rc*.d',
            '/etc/systemd/system',
            os.path.expanduser('~/.config/autostart')
        ]

        for pattern in startup_dirs:
            for dir_path in glob.glob(pattern):
                if os.path.exists(dir_path) and os.path.isdir(dir_path):
                    if os.access(dir_path, os.W_OK):
                        findings.append({
                            "severity": "high",
                            "finding": f"Writable startup directory: {dir_path}",
                            "description": "Startup directory is writable",
                            "remediation": f"Fix permissions: chmod 755 {dir_path}"
                        })

    except Exception:
        pass

    return findings

if __name__ == '__main__':
    # Test module
    import json
    results = check()
    print(json.dumps(results, indent=2))
