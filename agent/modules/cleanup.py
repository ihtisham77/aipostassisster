"""
Cleanup Assessment Module - PRODUCTION ENHANCED
Checks for logging capabilities and forensic artifacts with OS-specific detection
Assesses anti-forensic opportunities and track covering capabilities
"""

import os
import platform
import subprocess
import glob
import pwd
from . import common_utils


def create_finding(severity, finding, description, remediation, confidence=100, verified=True):
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
    Check for logging and forensic capabilities with comprehensive multi-method verification
    """
    results = {
        "module": "cleanup",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # Check system logs with OS-specific detection
        log_findings = check_system_logs_enhanced()
        if log_findings:
            results["findings"].extend(log_findings)

        # Check shell history with comprehensive enumeration
        history_findings = check_shell_history_enhanced()
        if history_findings:
            results["findings"].extend(history_findings)

        # Check authentication logs
        auth_findings = check_auth_logs_enhanced()
        if auth_findings:
            results["findings"].extend(auth_findings)

        # Check log permissions for modification opportunities
        permission_findings = check_log_permissions_enhanced()
        if permission_findings:
            results["findings"].extend(permission_findings)

        # Check logging daemons and services
        daemon_findings = check_logging_daemons_enhanced()
        if daemon_findings:
            results["findings"].extend(daemon_findings)

        # Check audit and forensic systems
        audit_findings = check_audit_system_enhanced()
        if audit_findings:
            results["findings"].extend(audit_findings)

        # Check Windows Event Logs
        if common_utils.is_windows():
            event_findings = check_windows_event_logs()
            if event_findings:
                results["findings"].extend(event_findings)

    except Exception as e:
        results["error"] = str(e)

    return results


def check_system_logs_enhanced():
    """Enhanced system log detection with multi-method verification"""
    findings = []

    try:
        if common_utils.is_linux() or common_utils.is_macos():
            # Linux/macOS system logs
            log_locations = [
                ('/var/log/syslog', 'System log (Debian/Ubuntu)'),
                ('/var/log/messages', 'System log (RHEL/CentOS)'),
                ('/var/log/system.log', 'System log (macOS)'),
                ('/var/log/kern.log', 'Kernel log'),
                ('/var/log/dmesg', 'Kernel ring buffer'),
                ('/var/log/cron', 'Cron job log'),
                ('/var/log/mail.log', 'Mail system log')
            ]

            accessible_logs = []
            writable_logs = []
            methods_verified = []

            for log_file, description in log_locations:
                if os.path.exists(log_file):
                    # Method 1: Check readability
                    is_readable = os.access(log_file, os.R_OK)
                    # Method 2: Check writability
                    is_writable = os.access(log_file, os.W_OK)
                    # Method 3: Verify file stat
                    try:
                        file_stat = os.stat(log_file)
                        file_exists = True
                    except:
                        file_exists = False

                    methods_verified.append(file_exists)

                    if is_readable:
                        accessible_logs.append(f"{description} ({log_file})")

                        try:
                            # Try to get log size
                            size_mb = os.path.getsize(log_file) / (1024 * 1024)

                            findings.append(create_finding(
                                "info",
                                f"System log accessible: {description}",
                                f"Log file {log_file} is readable ({size_mb:.2f} MB). "
                                f"This log contains system events and may record attacker activity. "
                                f"Can be analyzed for forensic evidence.",
                                "Attacker activity may be logged in this file",
                                100,
                                True
                            ))
                        except:
                            pass

                    if is_writable:
                        writable_logs.append(f"{description} ({log_file})")

                        findings.append(create_finding(
                            "high",
                            f"System log is WRITABLE: {description}",
                            f"Log file {log_file} can be modified! "
                            f"Attacker can tamper with logs to cover tracks by: "
                            f"1) Deleting incriminating entries "
                            f"2) Modifying timestamps "
                            f"3) Inserting false entries. "
                            f"This is a critical capability for covering tracks.",
                            "Protect log file permissions; implement remote logging",
                            100,
                            True
                        ))

            if not accessible_logs and not writable_logs:
                findings.append(create_finding(
                    "medium",
                    "No system logs accessible",
                    "Cannot read or modify system logs. Limited visibility into logged activity. "
                    "Covering tracks is easier when logs cannot be examined.",
                    "Limited forensic evidence available in system logs",
                    90,
                    True
                ))

        elif common_utils.is_windows():
            # Windows Event Logs - check access
            try:
                result = subprocess.run(
                    ['wevtutil', 'el'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    log_count = len(result.stdout.strip().split('\n'))

                    findings.append(create_finding(
                        "info",
                        f"Windows Event Logs detected: {log_count} log channels",
                        f"System has {log_count} event log channels. Key logs: Security, System, Application. "
                        f"These logs record all system activity including logons, privilege use, and process creation.",
                        "Event logs contain forensic evidence of attacker activity",
                        95,
                        True
                    ))

                    # Check if we can clear logs (indicates admin privileges)
                    try:
                        result = subprocess.run(
                            ['wevtutil', 'cl', 'Application', '/bu:test.evtx'],
                            capture_output=True,
                            text=True,
                            timeout=3
                        )

                        # If command doesn't fail with access denied, we might have clearing capability
                        if 'Access is denied' not in result.stderr:
                            findings.append(create_finding(
                                "critical",
                                "Windows Event Log clearing capability detected",
                                "May have privileges to clear Windows Event Logs. "
                                "Command 'wevtutil cl <logname>' can erase forensic evidence. "
                                "Clearing Security log generates Event ID 1102 (audit log cleared).",
                                "Event log clearing is critical IOC; monitor Event ID 1102",
                                90,
                                True
                            ))
                    except:
                        pass
            except:
                pass

    except Exception:
        pass

    return findings


def check_shell_history_enhanced():
    """Enhanced shell history detection with comprehensive coverage"""
    findings = []

    try:
        # Comprehensive list of history files
        history_files = [
            ('~/.bash_history', 'Bash history'),
            ('~/.zsh_history', 'Zsh history'),
            ('~/.sh_history', 'Shell history'),
            ('~/.python_history', 'Python REPL history'),
            ('~/.mysql_history', 'MySQL client history'),
            ('~/.psql_history', 'PostgreSQL client history'),
            ('~/.sqlite_history', 'SQLite history'),
            ('~/.irb_history', 'Ruby IRB history'),
            ('~/.node_repl_history', 'Node.js REPL history'),
            ('~/.lesshst', 'Less pager history'),
            ('~/.viminfo', 'Vim history')
        ]

        if common_utils.is_windows():
            # PowerShell history
            history_files.extend([
                ('~\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt', 'PowerShell history'),
                ('~\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\Visual Studio Code Host_history.txt', 'VS Code PowerShell history')
            ])

        accessible_history = []
        writable_history = []
        history_stats = []

        for history_file, description in history_files:
            expanded = os.path.expanduser(history_file)

            if os.path.exists(expanded):
                is_readable = os.access(expanded, os.R_OK)
                is_writable = os.access(expanded, os.W_OK)

                if is_readable:
                    try:
                        with open(expanded, 'r', errors='ignore') as f:
                            lines = f.readlines()
                            entry_count = len(lines)

                        accessible_history.append(description)
                        history_stats.append(f"{description}: {entry_count} entries")

                        # Look for sensitive commands in history
                        sensitive_keywords = ['password', 'passwd', 'secret', 'token', 'api_key', 'ssh', 'sudo', 'su ']
                        sensitive_found = []

                        for line in lines[-100:]:  # Check last 100 entries
                            for keyword in sensitive_keywords:
                                if keyword in line.lower():
                                    sensitive_found.append(keyword)
                                    break

                        if sensitive_found:
                            findings.append(create_finding(
                                "medium",
                                f"Sensitive commands in {description}",
                                f"History file {expanded} contains {entry_count} commands, including "
                                f"potentially sensitive keywords: {', '.join(set(sensitive_found)[:5])}. "
                                f"Command history reveals attacker actions and credentials.",
                                "Review history for indicators of compromise; consider clearing sensitive entries",
                                95,
                                True
                            ))
                        else:
                            findings.append(create_finding(
                                "info",
                                f"Command history accessible: {description}",
                                f"File {expanded} contains {entry_count} command entries. "
                                f"Provides forensic record of commands executed.",
                                "Command history records attacker activity",
                                100,
                                True
                            ))

                    except Exception:
                        accessible_history.append(description)

                if is_writable:
                    writable_history.append(description)

                    findings.append(create_finding(
                        "medium",
                        f"History file is WRITABLE: {description}",
                        f"File {expanded} can be modified. Attacker can cover tracks by: "
                        f"1) Deleting the entire history file "
                        f"2) Removing specific incriminating commands "
                        f"3) Disabling history logging (unset HISTFILE). "
                        f"History tampering is common anti-forensic technique.",
                        "Monitor history file modifications; implement file integrity monitoring",
                        100,
                        True
                    ))

        # Check environment variables related to history
        env_checks = []

        histfile = os.environ.get('HISTFILE')
        if histfile:
            env_checks.append(f"HISTFILE={histfile}")
            findings.append(create_finding(
                "info",
                f"HISTFILE environment variable set: {histfile}",
                "Commands are being logged to this history file.",
                "Can disable history by unsetting HISTFILE or setting to /dev/null",
                100,
                True
            ))

        histsize = os.environ.get('HISTSIZE')
        histfilesize = os.environ.get('HISTFILESIZE')

        if histfilesize == '0' or histsize == '0':
            findings.append(create_finding(
                "high",
                "Command history is DISABLED",
                f"HISTSIZE or HISTFILESIZE is set to 0. Command history is not being recorded! "
                f"This prevents forensic analysis of commands executed. "
                f"Common anti-forensic technique used by attackers.",
                "History tampering detected; investigate who disabled history",
                100,
                True
            ))

        # Check for common history evasion techniques
        if common_utils.is_linux() or common_utils.is_macos():
            # Check if history is symlinked to /dev/null
            bash_history = os.path.expanduser('~/.bash_history')
            if os.path.islink(bash_history):
                link_target = os.readlink(bash_history)
                if link_target == '/dev/null':
                    findings.append(create_finding(
                        "critical",
                        "History file symlinked to /dev/null",
                        f"{bash_history} is symlinked to /dev/null. All commands are discarded! "
                        f"This is a deliberate anti-forensic technique to prevent command logging.",
                        "Critical IOC - history evasion detected",
                        100,
                        True
                    ))

    except Exception:
        pass

    return findings


def check_auth_logs_enhanced():
    """Enhanced authentication log detection"""
    findings = []

    try:
        if common_utils.is_linux() or common_utils.is_macos():
            auth_logs = [
                ('/var/log/auth.log', 'Authentication log (Debian/Ubuntu)'),
                ('/var/log/secure', 'Secure log (RHEL/CentOS)'),
                ('/var/log/wtmp', 'Login records (binary)'),
                ('/var/log/lastlog', 'Last login per user (binary)'),
                ('/var/log/btmp', 'Failed login attempts (binary)'),
                ('/var/log/faillog', 'Failed login log')
            ]

            accessible_auth = []
            writable_auth = []

            for log_file, description in auth_logs:
                if os.path.exists(log_file):
                    is_readable = os.access(log_file, os.R_OK)
                    is_writable = os.access(log_file, os.W_OK)

                    if is_readable:
                        accessible_auth.append(description)

                        findings.append(create_finding(
                            "high",
                            f"Authentication log accessible: {description}",
                            f"Log {log_file} records authentication events: "
                            f"successful logins, failed attempts, sudo usage, SSH connections. "
                            f"Critical forensic evidence for tracking attacker access.",
                            "Authentication logs reveal attacker access patterns",
                            100,
                            True
                        ))

                    if is_writable:
                        writable_auth.append(description)

                        findings.append(create_finding(
                            "critical",
                            f"Authentication log is WRITABLE: {description}",
                            f"CRITICAL: Log file {log_file} can be modified! "
                            f"Attacker can erase evidence of unauthorized access. "
                            f"Can delete entries showing: SSH logins, sudo commands, "
                            f"privilege escalation, lateral movement.",
                            "CRITICAL SECURITY ISSUE - protect authentication log permissions immediately",
                            100,
                            True
                        ))

            # Check 'last' command output
            try:
                result = subprocess.run(
                    ['last', '-n', '10'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0 and result.stdout.strip():
                    login_count = len([l for l in result.stdout.split('\n') if l.strip()])

                    findings.append(create_finding(
                        "info",
                        f"Login history available: {login_count} recent entries",
                        f"The 'last' command shows recent user logins. "
                        f"Forensic investigators can use this to track unauthorized access. "
                        f"Data source: /var/log/wtmp",
                        "Login history provides forensic timeline",
                        95,
                        True
                    ))
            except Exception:
                pass

            # Check 'lastb' command (failed logins)
            try:
                result = subprocess.run(
                    ['lastb', '-n', '5'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0 and result.stdout.strip() and 'btmp begins' not in result.stdout:
                    findings.append(create_finding(
                        "info",
                        "Failed login attempts logged",
                        "System records failed login attempts. Useful for detecting brute force attacks. "
                        "Data source: /var/log/btmp",
                        "Failed login logs can reveal attack attempts",
                        95,
                        True
                    ))
            except Exception:
                pass

        elif common_utils.is_windows():
            # Windows authentication is in Event Logs (Security log)
            findings.append(create_finding(
                "info",
                "Windows authentication logging via Event Logs",
                "Windows logs authentication events to Security Event Log. "
                "Key Event IDs: 4624 (logon success), 4625 (logon failure), "
                "4672 (special privileges assigned), 4634 (logoff). "
                "Requires administrator privileges to access Security log.",
                "Security Event Log contains authentication forensics",
                90,
                True
            ))

    except Exception:
        pass

    return findings


def check_log_permissions_enhanced():
    """Enhanced log directory permission analysis"""
    findings = []

    try:
        log_dir = '/var/log'

        if common_utils.is_linux() or common_utils.is_macos():
            if os.path.exists(log_dir):
                # Check if log directory is writable
                is_dir_writable = os.access(log_dir, os.W_OK)

                if is_dir_writable:
                    findings.append(create_finding(
                        "critical",
                        "Log directory is WRITABLE",
                        f"CRITICAL: Directory {log_dir} can be modified! "
                        f"Attacker can: delete entire log files, create fake logs, "
                        f"modify log rotation configuration. "
                        f"Complete control over system logging.",
                        "CRITICAL - Restrict /var/log permissions immediately",
                        100,
                        True
                    ))

                # Enumerate writable log files
                writable_logs = []
                total_logs = 0

                try:
                    for root, dirs, files in os.walk(log_dir):
                        for file in files:
                            total_logs += 1
                            filepath = os.path.join(root, file)

                            try:
                                if os.access(filepath, os.W_OK):
                                    writable_logs.append(filepath)

                                    if len(writable_logs) >= 10:
                                        break
                            except Exception:
                                continue

                        if len(writable_logs) >= 10:
                            break
                except Exception:
                    pass

                if writable_logs:
                    findings.append(create_finding(
                        "high",
                        f"Multiple writable log files found: {len(writable_logs)}+ files",
                        f"Writable log files detected (showing first 10):\n" +
                        "\n".join(f"- {log}" for log in writable_logs[:10]) +
                        f"\n\nThese logs can be tampered with to cover tracks.",
                        "Audit and restrict log file permissions",
                        95,
                        True
                    ))
                elif total_logs > 0:
                    findings.append(create_finding(
                        "info",
                        f"Log files protected: {total_logs} files checked",
                        f"No writable log files found in {log_dir}. "
                        f"Proper permissions are enforced. Tampering is difficult.",
                        "Good security posture - logs are protected",
                        90,
                        True
                    ))

    except Exception:
        pass

    return findings


def check_logging_daemons_enhanced():
    """Enhanced logging daemon detection with service verification"""
    findings = []

    try:
        if common_utils.is_linux():
            logging_services = [
                ('rsyslog', 'rsyslog (standard syslog daemon)'),
                ('syslog-ng', 'syslog-ng (alternative syslog)'),
                ('systemd-journald', 'systemd journal (binary logging)'),
                ('auditd', 'Linux audit daemon')
            ]

            running_loggers = []
            stopped_loggers = []

            for service, description in logging_services:
                try:
                    result = subprocess.run(
                        ['systemctl', 'is-active', service],
                        capture_output=True,
                        text=True,
                        timeout=3
                    )

                    if result.returncode == 0 and 'active' in result.stdout:
                        running_loggers.append(description)
                    else:
                        stopped_loggers.append(service)
                except Exception:
                    continue

            if running_loggers:
                findings.append(create_finding(
                    "info",
                    f"Active logging daemons: {len(running_loggers)}",
                    f"Logging services running:\n" + "\n".join(f"- {logger}" for logger in running_loggers) +
                    f"\n\nActive logging makes covering tracks more difficult. "
                    f"Logs are continuously written and may be forwarded to remote syslog servers.",
                    "Active logging provides real-time forensic capability",
                    100,
                    True
                ))
            else:
                findings.append(create_finding(
                    "medium",
                    "No active logging daemons detected",
                    "No standard logging daemons are running. System events may not be logged. "
                    "Covering tracks is easier without active logging.",
                    "Lack of logging reduces forensic evidence",
                    95,
                    True
                ))

            # Check journalctl (systemd journal)
            try:
                result = subprocess.run(
                    ['journalctl', '--no-pager', '-n', '1'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    # Check journal size
                    try:
                        result = subprocess.run(
                            ['journalctl', '--disk-usage'],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )

                        if result.returncode == 0:
                            findings.append(create_finding(
                                "info",
                                "systemd journal active",
                                f"System uses systemd journal for logging. "
                                f"Disk usage: {result.stdout.strip()}. "
                                f"Journal stores structured logs with metadata (timestamps, PIDs, etc.). "
                                f"Harder to tamper with than text logs.",
                                "Journal provides robust forensic logging",
                                95,
                                True
                            ))
                    except:
                        pass
            except Exception:
                pass

        elif common_utils.is_windows():
            # Check Windows Event Log service
            try:
                result = subprocess.run(
                    ['sc', 'query', 'EventLog'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    if 'RUNNING' in result.stdout:
                        findings.append(create_finding(
                            "info",
                            "Windows Event Log service is running",
                            "Event Log service (EventLog) is active. All system events are being logged. "
                            "Critical for forensics and security monitoring.",
                            "Event logging is functioning properly",
                            100,
                            True
                        ))
                    else:
                        findings.append(create_finding(
                            "critical",
                            "Windows Event Log service is STOPPED",
                            "Event Log service is not running! No events are being logged. "
                            "This is highly suspicious and may indicate attacker anti-forensic activity.",
                            "CRITICAL - Event Log service disabled - investigate immediately",
                            100,
                            True
                        ))
            except Exception:
                pass

    except Exception:
        pass

    return findings


def check_audit_system_enhanced():
    """Enhanced audit system detection with rule analysis"""
    findings = []

    try:
        if common_utils.is_linux():
            # Check for auditd
            auditctl_exists, confidence, path = common_utils.verify_command_exists('auditctl')

            if auditctl_exists:
                findings.append(create_finding(
                    "high",
                    f"Linux audit system installed: {path}",
                    "auditd (Linux Audit) is installed. Provides kernel-level auditing of: "
                    "system calls, file access, process execution, network connections. "
                    "Audit logs are tamper-resistant and provide detailed forensic data.",
                    "Audit system provides comprehensive forensic logging",
                    confidence,
                    True
                ))

                # Check audit rules
                try:
                    result = subprocess.run(
                        ['auditctl', '-l'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )

                    if result.returncode == 0:
                        rules_output = result.stdout.strip()

                        if 'No rules' in rules_output:
                            findings.append(create_finding(
                                "medium",
                                "Audit system installed but no rules configured",
                                "auditd is present but has no active audit rules. "
                                "Limited forensic capability without rules.",
                                "Configure audit rules for critical files and system calls",
                                100,
                                True
                            ))
                        else:
                            rule_lines = rules_output.split('\n')
                            rule_count = len([l for l in rule_lines if l.strip() and not l.startswith('#')])

                            # Analyze rules for critical paths
                            critical_paths = ['/etc/passwd', '/etc/shadow', '/var/log', '/root/.ssh']
                            monitored_paths = [p for p in critical_paths if any(p in line for line in rule_lines)]

                            findings.append(create_finding(
                                "high",
                                f"Audit rules active: {rule_count} rules configured",
                                f"auditd has {rule_count} active rules. "
                                f"Monitored critical paths: {', '.join(monitored_paths) if monitored_paths else 'None'}. "
                                f"Audit logs will capture file access, system calls, and process execution. "
                                f"Tampering with audit logs generates alerts.",
                                "Comprehensive audit logging active - high forensic capability",
                                100,
                                True
                            ))
                except Exception:
                    pass

            # Check for file integrity monitoring (AIDE/Tripwire)
            integrity_tools = [
                ('aide', 'AIDE (Advanced Intrusion Detection Environment)'),
                ('tripwire', 'Tripwire')
            ]

            detected_fim = []
            for tool, description in integrity_tools:
                exists, confidence, path = common_utils.verify_command_exists(tool)
                if exists:
                    detected_fim.append(description)

                    findings.append(create_finding(
                        "high",
                        f"File integrity monitoring installed: {description}",
                        f"FIM tool detected at {path}. "
                        f"File integrity monitoring detects unauthorized modifications to: "
                        f"system files, binaries, logs, configuration files. "
                        f"Covering tracks by modifying files will trigger alerts.",
                        "File integrity monitoring active - file tampering will be detected",
                        confidence,
                        True
                    ))

            # Check osquery (endpoint visibility)
            osquery_exists, confidence, path = common_utils.verify_command_exists('osqueryi')
            if osquery_exists:
                findings.append(create_finding(
                    "high",
                    f"osquery installed: {path}",
                    "osquery provides SQL-based endpoint visibility. "
                    "Can query: running processes, file hashes, network connections, users, etc. "
                    "Real-time monitoring and forensic analysis capability.",
                    "osquery provides advanced endpoint monitoring",
                    confidence,
                    True
                ))

        elif common_utils.is_windows():
            # Check Windows Audit Policy
            try:
                result = subprocess.run(
                    ['auditpol', '/get', '/category:*'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    audit_output = result.stdout

                    # Count enabled audit policies
                    success_count = audit_output.lower().count('success')
                    failure_count = audit_output.lower().count('failure')

                    if success_count > 0 or failure_count > 0:
                        findings.append(create_finding(
                            "high",
                            f"Windows audit policy configured: {success_count} success + {failure_count} failure policies",
                            f"Windows auditing is configured with {success_count + failure_count} active policies. "
                            f"Audit events are logged to Security Event Log. "
                            f"Key events: logons, object access, privilege use, process tracking.",
                            "Windows audit policy provides forensic logging",
                            95,
                            True
                        ))
                    else:
                        findings.append(create_finding(
                            "medium",
                            "Windows audit policy not configured",
                            "No audit policies are enabled. Limited forensic logging capability.",
                            "Enable audit policies for security monitoring",
                            100,
                            True
                        ))
            except Exception:
                pass

            # Check Sysmon
            sysmon_exists, confidence, path = common_utils.verify_command_exists('sysmon')
            if sysmon_exists:
                findings.append(create_finding(
                    "critical",
                    f"Sysmon detected: {path}",
                    "Sysmon (System Monitor) is installed! "
                    "Sysmon provides detailed logging of: process creation, network connections, "
                    "file creation, registry changes, driver loads. "
                    "Extremely powerful forensic tool. Covering tracks is very difficult.",
                    "Sysmon provides enterprise-grade endpoint logging",
                    confidence,
                    True
                ))

    except Exception:
        pass

    return findings


def check_windows_event_logs():
    """Windows-specific Event Log analysis"""
    findings = []

    try:
        # Check critical Event Logs
        critical_logs = [
            ('Security', 'Security events (authentication, authorization)'),
            ('System', 'System events (service starts, driver loads)'),
            ('Application', 'Application events'),
            ('Microsoft-Windows-Sysmon/Operational', 'Sysmon events'),
            ('Microsoft-Windows-PowerShell/Operational', 'PowerShell events'),
            ('Windows PowerShell', 'PowerShell legacy events')
        ]

        for log_name, description in critical_logs:
            try:
                result = subprocess.run(
                    ['wevtutil', 'gli', log_name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    # Parse log information
                    log_info = result.stdout

                    # Extract log size and record count
                    size_match = [line for line in log_info.split('\n') if 'fileSize' in line.lower()]
                    count_match = [line for line in log_info.split('\n') if 'numberOfLogRecords' in line.lower()]

                    log_details = f"{description}"
                    if size_match:
                        log_details += f". {size_match[0].strip()}"
                    if count_match:
                        log_details += f". {count_match[0].strip()}"

                    findings.append(create_finding(
                        "info",
                        f"Windows Event Log active: {log_name}",
                        f"Event log '{log_name}' is active. {log_details}. "
                        f"Contains forensic evidence of system activity.",
                        "Event log contains forensic data",
                        95,
                        True
                    ))
            except Exception:
                continue

        # Check Event Log retention settings
        try:
            result = subprocess.run(
                ['wevtutil', 'gli', 'Security'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                if 'retention: true' in result.stdout.lower():
                    findings.append(create_finding(
                        "info",
                        "Event Log retention enabled",
                        "Security Event Log has retention enabled. Logs are preserved and not automatically overwritten. "
                        "Extended forensic timeline available.",
                        "Log retention preserves forensic evidence",
                        100,
                        True
                    ))
        except:
            pass

    except Exception:
        pass

    return findings


if __name__ == '__main__':
    # Test module
    import json
    results = check()
    print(json.dumps(results, indent=2))
