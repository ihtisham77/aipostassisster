"""
Covering Tracks Assessment Module
Checks for log files and forensic artifacts
"""

import os
import platform
import subprocess
import glob
import pwd

def check():
    """
    Check for logging and forensic capabilities
    """
    results = {
        "module": "covering_tracks",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # Check system logs
        log_findings = check_system_logs()
        if log_findings:
            results["findings"].extend(log_findings)

        # Check shell history
        history_findings = check_shell_history()
        if history_findings:
            results["findings"].extend(history_findings)

        # Check authentication logs
        auth_findings = check_auth_logs()
        if auth_findings:
            results["findings"].extend(auth_findings)

        # Check log permissions
        permission_findings = check_log_permissions()
        if permission_findings:
            results["findings"].extend(permission_findings)

        # Check logging daemons
        daemon_findings = check_logging_daemons()
        if daemon_findings:
            results["findings"].extend(daemon_findings)

        # Check audit system
        audit_findings = check_audit_system()
        if audit_findings:
            results["findings"].extend(audit_findings)

    except Exception as e:
        results["error"] = str(e)

    return results

def check_system_logs():
    """Check system log files"""
    findings = []

    try:
        log_locations = [
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/system.log',
            '/var/log/kern.log'
        ]

        accessible_logs = []

        for log_file in log_locations:
            if os.path.exists(log_file):
                if os.access(log_file, os.R_OK):
                    accessible_logs.append(log_file)

                    findings.append({
                        "severity": "info",
                        "finding": f"System log accessible: {log_file}",
                        "description": "Log file is readable",
                        "remediation": "This log may contain evidence of activity"
                    })

                if os.access(log_file, os.W_OK):
                    findings.append({
                        "severity": "high",
                        "finding": f"System log writable: {log_file}",
                        "description": "Log file can be modified",
                        "remediation": "Writable logs can be tampered with to cover tracks"
                    })

        if not accessible_logs:
            findings.append({
                "severity": "medium",
                "finding": "No system logs accessible",
                "description": "Cannot read or modify system logs",
                "remediation": "Limited ability to cover tracks in system logs"
            })

    except Exception:
        pass

    return findings

def check_shell_history():
    """Check shell history files"""
    findings = []

    try:
        history_files = [
            '~/.bash_history',
            '~/.zsh_history',
            '~/.sh_history',
            '~/.python_history',
            '~/.mysql_history'
        ]

        for history_file in history_files:
            expanded = os.path.expanduser(history_file)

            if os.path.exists(expanded):
                if os.access(expanded, os.R_OK):
                    try:
                        with open(expanded, 'r') as f:
                            lines = f.readlines()

                        findings.append({
                            "severity": "info",
                            "finding": f"History file accessible: {expanded}",
                            "description": f"Contains {len(lines)} entries",
                            "remediation": "History file records commands executed"
                        })
                    except Exception:
                        pass

                if os.access(expanded, os.W_OK):
                    findings.append({
                        "severity": "medium",
                        "finding": f"History file writable: {expanded}",
                        "description": "Can modify command history",
                        "remediation": "Writable history allows covering tracks"
                    })

        # Check if HISTFILE is set
        histfile = os.environ.get('HISTFILE')
        if histfile:
            findings.append({
                "severity": "info",
                "finding": f"HISTFILE environment variable set: {histfile}",
                "description": "Commands are being logged to this file",
                "remediation": "Can unset HISTFILE to prevent logging"
            })

        # Check HISTFILESIZE
        histsize = os.environ.get('HISTFILESIZE')
        if histsize == '0':
            findings.append({
                "severity": "medium",
                "finding": "HISTFILESIZE is 0",
                "description": "Command history is disabled",
                "remediation": "No commands are being logged to history"
            })

    except Exception:
        pass

    return findings

def check_auth_logs():
    """Check authentication logs"""
    findings = []

    try:
        auth_logs = [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/wtmp',
            '/var/log/lastlog',
            '/var/log/btmp'
        ]

        for log_file in auth_logs:
            if os.path.exists(log_file):
                if os.access(log_file, os.R_OK):
                    findings.append({
                        "severity": "high",
                        "finding": f"Authentication log accessible: {log_file}",
                        "description": "Log contains authentication events",
                        "remediation": "This log records login attempts and authentication"
                    })

                if os.access(log_file, os.W_OK):
                    findings.append({
                        "severity": "critical",
                        "finding": f"Authentication log writable: {log_file}",
                        "description": "Can modify authentication logs",
                        "remediation": "Critical security issue - logs can be tampered"
                    })

        # Check last command
        try:
            result = subprocess.run(
                ['last', '-n', '5'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                findings.append({
                    "severity": "info",
                    "finding": "Login history available",
                    "description": "System tracks user logins",
                    "remediation": "Login history shows user activity"
                })
        except Exception:
            pass

    except Exception:
        pass

    return findings

def check_log_permissions():
    """Check log directory permissions"""
    findings = []

    try:
        log_dir = '/var/log'

        if os.path.exists(log_dir):
            # Check if log directory is writable
            if os.access(log_dir, os.W_OK):
                findings.append({
                    "severity": "critical",
                    "finding": "Log directory is writable",
                    "description": f"{log_dir} can be modified",
                    "remediation": "Can delete or modify log files"
                })

            # Check individual log files
            writable_logs = []

            for root, dirs, files in os.walk(log_dir):
                for file in files:
                    filepath = os.path.join(root, file)

                    try:
                        if os.access(filepath, os.W_OK):
                            writable_logs.append(filepath)

                            if len(writable_logs) >= 5:
                                break
                    except Exception:
                        continue

                if len(writable_logs) >= 5:
                    break

            if writable_logs:
                findings.append({
                    "severity": "high",
                    "finding": f"Writable log files found: {len(writable_logs)}",
                    "description": f"Files: {', '.join(writable_logs[:5])}",
                    "remediation": "These logs can be modified to cover tracks"
                })

    except Exception:
        pass

    return findings

def check_logging_daemons():
    """Check logging daemon status"""
    findings = []

    try:
        logging_services = [
            'rsyslog',
            'syslog-ng',
            'systemd-journald',
            'auditd'
        ]

        running_loggers = []

        for service in logging_services:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True,
                    text=True,
                    timeout=3
                )

                if result.returncode == 0 and 'active' in result.stdout:
                    running_loggers.append(service)
            except Exception:
                continue

        if running_loggers:
            findings.append({
                "severity": "info",
                "finding": f"Logging daemons active: {len(running_loggers)}",
                "description": f"Services: {', '.join(running_loggers)}",
                "remediation": "Active logging makes covering tracks more difficult"
            })
        else:
            findings.append({
                "severity": "medium",
                "finding": "No logging daemons detected",
                "description": "Logging may not be active",
                "remediation": "Lack of logging makes covering tracks easier"
            })

        # Check journalctl
        try:
            result = subprocess.run(
                ['journalctl', '--no-pager', '-n', '1'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                findings.append({
                    "severity": "info",
                    "finding": "systemd journal is active",
                    "description": "System logs are being collected by journald",
                    "remediation": "Journal logs contain detailed system activity"
                })
        except Exception:
            pass

    except Exception:
        pass

    return findings

def check_audit_system():
    """Check audit system configuration"""
    findings = []

    try:
        # Check if auditd is installed
        try:
            result = subprocess.run(['which', 'auditctl'], capture_output=True, timeout=2)
            if result.returncode == 0:
                findings.append({
                    "severity": "high",
                    "finding": "Linux audit system installed",
                    "description": "auditd is present on the system",
                    "remediation": "Audit system provides detailed forensic logging"
                })

                # Check audit rules
                try:
                    result = subprocess.run(
                        ['auditctl', '-l'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )

                    if result.returncode == 0:
                        rule_count = len(result.stdout.strip().split('\n'))

                        findings.append({
                            "severity": "high",
                            "finding": f"Audit rules configured: {rule_count}",
                            "description": "System has active audit rules",
                            "remediation": "Audit logs will capture system calls and file access"
                        })
                except Exception:
                    pass

        except Exception:
            pass

        # Check for AIDE/Tripwire
        integrity_tools = ['aide', 'tripwire']

        for tool in integrity_tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, timeout=2)
                if result.returncode == 0:
                    findings.append({
                        "severity": "high",
                        "finding": f"File integrity monitoring installed: {tool}",
                        "description": "System has file integrity checking",
                        "remediation": "File modifications will be detected"
                    })
            except Exception:
                continue

    except Exception:
        pass

    return findings

if __name__ == '__main__':
    # Test module
    import json
    results = check()
    print(json.dumps(results, indent=2))
