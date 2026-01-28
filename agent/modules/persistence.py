"""
Persistence Assessment Module
Checks for persistence mechanisms and misconfigurations
Enhanced with OS-specific checks and confidence scoring
"""

import os
import platform
import subprocess
import glob
import re
import sys

# Import common utilities for verification and confidence scoring
try:
    from common_utils import (
        is_linux, is_windows, is_macos,
        verify_world_readable, verify_writable, verify_file_exists,
        create_finding, calculate_confidence_score, get_confidence_level,
        safe_run_command
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
    def verify_file_exists(path):
        return (os.path.exists(path), 100 if os.path.exists(path) else 0)
    def verify_writable(path):
        try:
            return (os.access(path, os.W_OK), 100 if os.access(path, os.W_OK) else 0)
        except:
            return (False, 0)
    def calculate_confidence_score(*checks):
        if not checks: return 0
        return int((sum(1 for c in checks if c) / len(checks)) * 100)

def check():
    """
    Check for persistence mechanisms and vulnerabilities
    OS-specific with confidence scoring
    """
    results = {
        "module": "persistence",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # OS-specific persistence checks
        if is_linux() or is_macos():
            results["findings"].extend(check_unix_persistence())
        elif is_windows():
            results["findings"].extend(check_windows_persistence())
        else:
            results["findings"].append(create_finding(
                "info",
                "Unsupported OS",
                f"Persistence checks not implemented for {platform.system()}",
                "Run module on Linux or Windows system",
                0
            ))

    except Exception as e:
        results["error"] = str(e)

    return results

def check_unix_persistence():
    """Unix/Linux-specific persistence checks"""
    findings = []

    # Enhanced cron job checks
    findings.extend(check_cron_jobs_enhanced())

    # Enhanced systemd checks
    findings.extend(check_systemd_persistence_enhanced())

    # Enhanced startup scripts
    findings.extend(check_startup_scripts_enhanced())

    # Enhanced profile scripts
    findings.extend(check_profile_scripts_enhanced())

    # Enhanced SSH authorized_keys
    findings.extend(check_ssh_keys_enhanced())

    # Additional Unix persistence vectors
    findings.extend(check_ld_preload())
    findings.extend(check_pam_modules())
    findings.extend(check_bashrc_persistence())
    findings.extend(check_cron_at_jobs())

    return findings

def check_windows_persistence():
    """Windows-specific persistence checks"""
    findings = []

    # Windows registry autoruns
    findings.extend(check_windows_registry_autoruns())

    # Windows scheduled tasks
    findings.extend(check_windows_scheduled_tasks())

    # Windows startup folders
    findings.extend(check_windows_startup_folders())

    # Windows services
    findings.extend(check_windows_services())

    # Windows WMI persistence
    findings.extend(check_windows_wmi_persistence())

    # Windows DLL hijacking opportunities
    findings.extend(check_windows_dll_hijacking())

    return findings

def check_cron_jobs_enhanced():
    """Enhanced cron job checks with confidence scoring"""
    findings = []

    try:
        # Check user crontab with verification
        checks = []
        result = subprocess.run(
            ['crontab', '-l'],
            capture_output=True,
            text=True,
            timeout=5
        )

        has_crontab = result.returncode == 0 and result.stdout.strip()
        checks.append(has_crontab)

        if has_crontab:
            crontab_content = result.stdout

            # Check for suspicious patterns in crontab
            suspicious_patterns = {
                r'curl\s+.*\|\s*bash': 'Remote code execution via curl',
                r'wget\s+.*\|\s*bash': 'Remote code execution via wget',
                r'/dev/tcp/': 'Reverse shell connection',
                r'nc\s+-[el]': 'Netcat listener/connection',
                r'python.*-c': 'Python one-liner',
                r'perl.*-e': 'Perl one-liner',
                r'base64.*-d': 'Base64 decoding (possible obfuscation)'
            }

            suspicious_found = []
            for pattern, description in suspicious_patterns.items():
                if re.search(pattern, crontab_content):
                    suspicious_found.append(description)

            confidence = 100 if has_crontab else 0

            if suspicious_found:
                findings.append(create_finding(
                    "critical",
                    "Suspicious patterns in user crontab",
                    f"Found {len(suspicious_found)} suspicious pattern(s) in crontab: "
                    f"{', '.join(suspicious_found)}. "
                    f"This indicates potential persistence mechanism. "
                    f"Verification confidence: {confidence}%",
                    "Review crontab: crontab -e. Remove unauthorized entries",
                    confidence,
                    confidence >= 95
                ))
            else:
                findings.append(create_finding(
                    "info",
                    "User crontab exists",
                    f"User has {len(crontab_content.split(chr(10)))} crontab entries. "
                    f"Verification confidence: {confidence}%",
                    "Review crontab for unauthorized entries: crontab -l",
                    confidence,
                    confidence >= 95
                ))

        # Check system cron directories with enhanced verification
        cron_dirs = [
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.monthly',
            '/etc/cron.weekly',
            '/var/spool/cron',
            '/var/spool/cron/crontabs'
        ]

        for cron_dir in cron_dirs:
            if not os.path.exists(cron_dir):
                continue

            try:
                for file in os.listdir(cron_dir):
                    filepath = os.path.join(cron_dir, file)

                    if not os.path.isfile(filepath):
                        continue

                    # Use multi-method verification
                    is_writable, write_confidence = verify_writable(filepath)

                    if is_writable:
                        findings.append(create_finding(
                            "critical",
                            f"Writable cron file: {filepath}",
                            f"Cron file is writable by current user. "
                            f"Can be modified to establish persistence. "
                            f"Verification confidence: {write_confidence}%",
                            f"Fix permissions: sudo chmod 644 {filepath} && sudo chown root:root {filepath}",
                            write_confidence,
                            write_confidence >= 95
                        ))

                    # Check file content for suspicious patterns
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read()

                            for pattern, description in suspicious_patterns.items():
                                if re.search(pattern, content):
                                    findings.append(create_finding(
                                        "high",
                                        f"Suspicious cron job in {filepath}",
                                        f"Cron file contains suspicious pattern: {description}. "
                                        f"Verification confidence: 100%",
                                        f"Review and remove suspicious entry from {filepath}",
                                        100,
                                        True
                                    ))
                                    break
                    except:
                        pass

            except Exception:
                pass

        # Check /etc/crontab
        if os.path.exists('/etc/crontab'):
            is_writable, write_confidence = verify_writable('/etc/crontab')

            if is_writable:
                findings.append(create_finding(
                    "critical",
                    "Writable /etc/crontab",
                    f"System crontab is writable by current user. "
                    f"This allows system-wide persistence. "
                    f"Verification confidence: {write_confidence}%",
                    "Fix permissions: sudo chmod 644 /etc/crontab && sudo chown root:root /etc/crontab",
                    write_confidence,
                    write_confidence >= 95
                ))

    except Exception:
        pass

    return findings

def check_systemd_persistence_enhanced():
    """Enhanced systemd service/timer checks"""
    findings = []

    try:
        # Check for writable service files in multiple locations
        service_dirs = [
            '/etc/systemd/system',
            '/lib/systemd/system',
            '/usr/lib/systemd/system',
            '/run/systemd/system',
            os.path.expanduser('~/.config/systemd/user'),
            os.path.expanduser('~/.local/share/systemd/user')
        ]

        for service_dir in service_dirs:
            if not os.path.exists(service_dir):
                continue

            try:
                for root, dirs, files in os.walk(service_dir):
                    for file in files:
                        if not (file.endswith('.service') or file.endswith('.timer') or file.endswith('.socket')):
                            continue

                        filepath = os.path.join(root, file)

                        # Multi-method verification
                        is_writable, write_confidence = verify_writable(filepath)

                        if is_writable:
                            # Check if service/timer is enabled
                            unit_name = file
                            is_enabled = False
                            try:
                                result = subprocess.run(
                                    ['systemctl', 'is-enabled', unit_name],
                                    capture_output=True,
                                    text=True,
                                    timeout=2
                                )
                                is_enabled = result.returncode == 0 and 'enabled' in result.stdout.lower()
                            except:
                                pass

                            severity = "critical" if is_enabled else "high"

                            findings.append(create_finding(
                                severity,
                                f"Writable systemd unit: {filepath}",
                                f"Systemd unit file is writable by current user. "
                                f"Unit is {'enabled - active persistence!' if is_enabled else 'not enabled but still exploitable'}. "
                                f"Can be modified for automatic execution. "
                                f"Verification confidence: {write_confidence}%",
                                f"Fix permissions: sudo chmod 644 {filepath} && sudo chown root:root {filepath}",
                                write_confidence,
                                write_confidence >= 95
                            ))

            except Exception:
                pass

        # Check user systemd units for suspicious content
        user_systemd_dir = os.path.expanduser('~/.config/systemd/user')
        if os.path.exists(user_systemd_dir):
            try:
                for file in os.listdir(user_systemd_dir):
                    if file.endswith(('.service', '.timer')):
                        filepath = os.path.join(user_systemd_dir, file)

                        try:
                            with open(filepath, 'r', errors='ignore') as f:
                                content = f.read()

                                # Look for suspicious ExecStart commands
                                if re.search(r'ExecStart.*(/tmp|/dev/shm|curl|wget|nc)', content):
                                    findings.append(create_finding(
                                        "high",
                                        f"Suspicious user systemd unit: {filepath}",
                                        "User systemd unit contains suspicious execution command. "
                                        "May be used for persistence. "
                                        "Verification confidence: 100%",
                                        f"Review and disable unit: systemctl --user disable {file}",
                                        100,
                                        True
                                    ))
                        except:
                            pass

            except Exception:
                pass

    except Exception:
        pass

    return findings

def check_startup_scripts_enhanced():
    """Enhanced startup script checks"""
    findings = []

    try:
        startup_files = [
            '/etc/rc.local',
            '/etc/rc.d/rc.local'
        ]

        for startup_file in startup_files:
            if not os.path.exists(startup_file):
                continue

            # Multi-method verification
            is_writable, write_confidence = verify_writable(startup_file)

            if is_writable:
                findings.append(create_finding(
                    "critical",
                    f"Writable startup script: {startup_file}",
                    f"Startup script is writable by current user. "
                    f"Executes at system boot with root privileges. "
                    f"Verification confidence: {write_confidence}%",
                    f"Fix permissions: sudo chmod 755 {startup_file} && sudo chown root:root {startup_file}",
                    write_confidence,
                    write_confidence >= 95
                ))

            # Check content
            try:
                with open(startup_file, 'r', errors='ignore') as f:
                    content = f.read()

                    # Skip if just "exit 0"
                    clean_content = content.replace('#!/bin/bash', '').replace('#!/bin/sh', '').strip()
                    clean_content = re.sub(r'#.*', '', clean_content).strip()  # Remove comments

                    if clean_content and clean_content != 'exit 0':
                        # Check for suspicious patterns
                        suspicious_patterns = [
                            'curl', 'wget', 'nc ', 'netcat', '/dev/tcp/',
                            'bash -i', 'sh -i', 'python -c', 'perl -e'
                        ]

                        has_suspicious = any(pattern in content for pattern in suspicious_patterns)

                        if has_suspicious:
                            findings.append(create_finding(
                                "high",
                                f"Suspicious content in startup script: {startup_file}",
                                f"Startup script contains suspicious commands. "
                                f"Verification confidence: 100%",
                                f"Review {startup_file} and remove suspicious commands",
                                100,
                                True
                            ))
                        else:
                            findings.append(create_finding(
                                "medium",
                                f"Startup script has content: {startup_file}",
                                f"Startup script contains commands (length: {len(content)} bytes). "
                                f"Verification confidence: 100%",
                                f"Review {startup_file} for unauthorized commands",
                                100,
                                True
                            ))

            except Exception:
                pass

        # Check /etc/init.d scripts
        if os.path.exists('/etc/init.d'):
            try:
                for file in os.listdir('/etc/init.d'):
                    filepath = os.path.join('/etc/init.d', file)

                    if not os.path.isfile(filepath):
                        continue

                    # Skip common system scripts
                    if file in ['README', 'skeleton', '.placeholder']:
                        continue

                    is_writable, write_confidence = verify_writable(filepath)

                    if is_writable:
                        findings.append(create_finding(
                            "high",
                            f"Writable init script: {filepath}",
                            f"Init.d script is writable by current user. "
                            f"Can be modified for persistence. "
                            f"Verification confidence: {write_confidence}%",
                            f"Fix permissions: sudo chmod 755 {filepath} && sudo chown root:root {filepath}",
                            write_confidence,
                            write_confidence >= 95
                        ))

            except Exception:
                pass

    except Exception:
        pass

    return findings

def check_profile_scripts_enhanced():
    """Enhanced profile script checks with confidence scoring"""
    findings = []

    try:
        profile_files = [
            '~/.bashrc',
            '~/.bash_profile',
            '~/.bash_login',
            '~/.profile',
            '~/.zshrc',
            '~/.zshenv',
            '~/.zprofile',
            '~/.config/fish/config.fish',
            '/etc/profile',
            '/etc/bash.bashrc',
            '/etc/zsh/zshrc'
        ]

        suspicious_patterns = {
            r'curl\s+.*\|\s*bash': 'Remote code execution via curl',
            r'wget\s+.*\|\s*bash': 'Remote code execution via wget',
            r'/dev/tcp/[\d.]+/\d+': 'Reverse shell connection',
            r'nc\s+-[el]': 'Netcat listener',
            r'python.*-c.*socket': 'Python reverse shell',
            r'perl.*-e.*socket': 'Perl reverse shell',
            r'bash\s+-i\s+>&': 'Interactive bash redirection',
            r'base64.*-d.*bash': 'Base64 obfuscated command',
            r'eval\s*\$\(': 'Command substitution (possible obfuscation)',
            r'chmod\s+\+s': 'SUID bit setting'
        }

        for profile_file in profile_files:
            expanded_path = os.path.expanduser(profile_file)

            if not os.path.exists(expanded_path):
                continue

            try:
                checks = []
                exists, _ = verify_file_exists(expanded_path)
                checks.append(exists)

                # Check permissions
                stat_info = os.stat(expanded_path)
                mode = stat_info.st_mode

                # Check if writable by others
                is_world_writable = bool(mode & 0o002)
                checks.append(not is_world_writable)

                confidence = calculate_confidence_score(*checks)

                if is_world_writable:
                    findings.append(create_finding(
                        "critical",
                        f"World-writable profile script: {expanded_path}",
                        f"Profile script is world-writable (mode: {oct(mode)}). "
                        f"Any user can modify it to inject malicious code. "
                        f"Verification confidence: {confidence}%",
                        f"Fix permissions: chmod 644 {expanded_path}",
                        confidence,
                        confidence >= 95
                    ))

                # Check content for suspicious patterns
                with open(expanded_path, 'r', errors='ignore') as f:
                    content = f.read()

                    found_patterns = []
                    for pattern, description in suspicious_patterns.items():
                        if re.search(pattern, content, re.IGNORECASE):
                            found_patterns.append(description)

                    if found_patterns:
                        findings.append(create_finding(
                            "high",
                            f"Suspicious patterns in profile script: {expanded_path}",
                            f"Found {len(found_patterns)} suspicious pattern(s): "
                            f"{', '.join(found_patterns)}. "
                            f"This may indicate persistence mechanism. "
                            f"Verification confidence: {min(100, confidence + 20)}%",
                            f"Review and clean {expanded_path}",
                            min(100, confidence + 20),
                            confidence + 20 >= 95
                        ))

            except Exception:
                pass

    except Exception:
        pass

    return findings

def check_ssh_keys_enhanced():
    """Enhanced SSH authorized_keys checks"""
    findings = []

    try:
        ssh_dir = os.path.expanduser('~/.ssh')

        if not os.path.exists(ssh_dir):
            return findings

        # Check .ssh directory permissions
        stat_info = os.stat(ssh_dir)
        mode = stat_info.st_mode

        has_bad_perms = bool(mode & 0o077)  # Readable/writable by group/others

        if has_bad_perms:
            findings.append(create_finding(
                "high",
                f"Insecure .ssh directory permissions: {ssh_dir}",
                f".ssh directory has incorrect permissions (mode: {oct(mode)}). "
                f"Should be 700. Other users may be able to add authorized keys. "
                f"Verification confidence: 100%",
                f"Fix permissions: chmod 700 {ssh_dir}",
                100,
                True
            ))

        # Check authorized_keys file
        auth_keys_files = [
            os.path.join(ssh_dir, 'authorized_keys'),
            os.path.join(ssh_dir, 'authorized_keys2')
        ]

        for auth_keys in auth_keys_files:
            if not os.path.exists(auth_keys):
                continue

            try:
                # Check permissions
                stat_info = os.stat(auth_keys)
                mode = stat_info.st_mode

                has_bad_perms = bool(mode & 0o077)

                if has_bad_perms:
                    findings.append(create_finding(
                        "critical",
                        f"Insecure authorized_keys permissions: {auth_keys}",
                        f"authorized_keys file has incorrect permissions (mode: {oct(mode)}). "
                        f"Should be 600. Other users may be able to add keys for persistence. "
                        f"Verification confidence: 100%",
                        f"Fix permissions: chmod 600 {auth_keys}",
                        100,
                        True
                    ))

                # Read and analyze keys
                with open(auth_keys, 'r', errors='ignore') as f:
                    keys = [line.strip() for line in f if line.strip() and not line.startswith('#')]

                if keys:
                    # Check for suspicious key options
                    suspicious_options = []
                    for key in keys:
                        if 'command=' in key:
                            suspicious_options.append('forced command')
                        if 'from=' in key:
                            suspicious_options.append('IP restriction')
                        if 'no-pty' in key:
                            suspicious_options.append('no-pty')

                    confidence = 100

                    if suspicious_options:
                        findings.append(create_finding(
                            "medium",
                            f"SSH keys with special options: {auth_keys}",
                            f"Found {len(keys)} key(s) with {len(suspicious_options)} special option(s). "
                            f"Options: {', '.join(set(suspicious_options))}. "
                            f"Review for unauthorized forced commands. "
                            f"Verification confidence: {confidence}%",
                            f"Review {auth_keys} for unauthorized keys and forced commands",
                            confidence,
                            confidence >= 95
                        ))
                    else:
                        findings.append(create_finding(
                            "info",
                            f"SSH authorized_keys exists: {auth_keys}",
                            f"Found {len(keys)} authorized key(s). "
                            f"Verification confidence: {confidence}%",
                            f"Review {auth_keys} for unauthorized keys",
                            confidence,
                            confidence >= 95
                        ))

            except Exception:
                pass

    except Exception:
        pass

    return findings

def check_ld_preload():
    """Check for LD_PRELOAD persistence"""
    findings = []

    try:
        ld_preload_files = [
            '/etc/ld.so.preload',
            os.path.expanduser('~/.ld_preload')
        ]

        for preload_file in ld_preload_files:
            if not os.path.exists(preload_file):
                continue

            # This is a known persistence technique
            try:
                with open(preload_file, 'r', errors='ignore') as f:
                    content = f.read().strip()

                if content:
                    findings.append(create_finding(
                        "critical",
                        f"LD_PRELOAD persistence detected: {preload_file}",
                        f"LD_PRELOAD file exists with content. "
                        f"This is a known persistence technique that loads libraries before all others. "
                        f"Content: {content[:200]}. "
                        f"Verification confidence: 100%",
                        f"Review and remove unauthorized libraries from {preload_file}",
                        100,
                        True
                    ))

            except Exception:
                pass

        # Check /etc/ld.so.conf.d/
        ld_conf_dir = '/etc/ld.so.conf.d'
        if os.path.exists(ld_conf_dir):
            try:
                for file in os.listdir(ld_conf_dir):
                    filepath = os.path.join(ld_conf_dir, file)

                    if os.path.isfile(filepath):
                        is_writable, write_confidence = verify_writable(filepath)

                        if is_writable:
                            findings.append(create_finding(
                                "high",
                                f"Writable ld.so.conf file: {filepath}",
                                f"Library configuration file is writable. "
                                f"Can be used for LD_PRELOAD persistence. "
                                f"Verification confidence: {write_confidence}%",
                                f"Fix permissions: sudo chmod 644 {filepath} && sudo chown root:root {filepath}",
                                write_confidence,
                                write_confidence >= 95
                            ))

            except Exception:
                pass

    except Exception:
        pass

    return findings

def check_pam_modules():
    """Check for malicious PAM modules"""
    findings = []

    try:
        pam_dirs = [
            '/lib/security',
            '/lib64/security',
            '/usr/lib/security',
            '/usr/lib64/security',
            '/lib/x86_64-linux-gnu/security'
        ]

        for pam_dir in pam_dirs:
            if not os.path.exists(pam_dir):
                continue

            # Check for writable PAM directory
            is_writable, write_confidence = verify_writable(pam_dir)

            if is_writable:
                findings.append(create_finding(
                    "critical",
                    f"Writable PAM module directory: {pam_dir}",
                    f"PAM module directory is writable. "
                    f"Attacker can install malicious PAM modules for persistence and credential theft. "
                    f"Verification confidence: {write_confidence}%",
                    f"Fix permissions: sudo chmod 755 {pam_dir} && sudo chown root:root {pam_dir}",
                    write_confidence,
                    write_confidence >= 95
                ))

        # Check PAM configuration files
        pam_configs = [
            '/etc/pam.conf',
            '/etc/pam.d/*'
        ]

        for pattern in pam_configs:
            for filepath in glob.glob(pattern):
                if not os.path.isfile(filepath):
                    continue

                is_writable, write_confidence = verify_writable(filepath)

                if is_writable:
                    findings.append(create_finding(
                        "critical",
                        f"Writable PAM configuration: {filepath}",
                        f"PAM configuration file is writable. "
                        f"Can be modified to load malicious PAM modules. "
                        f"Verification confidence: {write_confidence}%",
                        f"Fix permissions: sudo chmod 644 {filepath} && sudo chown root:root {filepath}",
                        write_confidence,
                        write_confidence >= 95
                    ))

    except Exception:
        pass

    return findings

def check_bashrc_persistence():
    """Check for persistence in .bashrc and similar files"""
    findings = []

    try:
        # Check for hidden files in home directory that execute on shell start
        home_dir = os.path.expanduser('~')

        suspicious_rc_files = []

        try:
            for file in os.listdir(home_dir):
                if file.startswith('.') and (file.endswith('rc') or file.endswith('_profile')):
                    filepath = os.path.join(home_dir, file)

                    if os.path.isfile(filepath):
                        # Check last modified time
                        mtime = os.path.getmtime(filepath)
                        import time
                        age_days = (time.time() - mtime) / 86400

                        # Flag recently modified rc files
                        if age_days < 7:
                            suspicious_rc_files.append((filepath, age_days))

        except Exception:
            pass

        if suspicious_rc_files:
            files_list = ', '.join([f"{f[0]} (modified {f[1]:.1f} days ago)" for f in suspicious_rc_files])

            findings.append(create_finding(
                "medium",
                "Recently modified shell configuration files",
                f"Found {len(suspicious_rc_files)} recently modified shell RC files: {files_list}. "
                f"Review for unauthorized modifications. "
                f"Verification confidence: 100%",
                "Review files for suspicious commands",
                100,
                True
            ))

    except Exception:
        pass

    return findings

def check_cron_at_jobs():
    """Check at jobs for persistence"""
    findings = []

    try:
        # Check at jobs
        result = subprocess.run(
            ['atq'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0 and result.stdout.strip():
            job_count = len(result.stdout.strip().split('\n'))

            findings.append(create_finding(
                "medium",
                f"Found {job_count} at job(s) scheduled",
                f"At jobs can be used for delayed execution/persistence. "
                f"Jobs: {result.stdout[:200]}. "
                f"Verification confidence: 100%",
                "Review at jobs: atq, atrm <job_num> to remove",
                100,
                True
            ))

    except Exception:
        pass

    return findings

# Windows-specific persistence checks

def check_windows_registry_autoruns():
    """Check Windows registry autorun locations"""
    findings = []

    if not is_windows():
        return findings

    try:
        import winreg

        # Common autorun registry locations
        autorun_keys = [
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
            (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
            (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunServices'),
            (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'),
        ]

        for hive, key_path in autorun_keys:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)

                hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"

                # Enumerate values
                i = 0
                autoruns = []
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        autoruns.append((name, value))
                        i += 1
                    except OSError:
                        break

                if autoruns:
                    # Check for suspicious executables
                    suspicious = []
                    for name, value in autoruns:
                        value_str = str(value).lower()
                        if any(susp in value_str for susp in ['tmp', 'temp', 'powershell', 'cmd', 'appdata', 'programdata']):
                            suspicious.append((name, value))

                    if suspicious:
                        findings.append(create_finding(
                            "high",
                            f"Suspicious autorun entries in registry: {hive_name}\\{key_path}",
                            f"Found {len(suspicious)} suspicious autorun entry(ies) out of {len(autoruns)} total. "
                            f"Entries: {suspicious[:3]}. "
                            f"Verification confidence: 100%",
                            f"Review and remove unauthorized entries from {hive_name}\\{key_path}",
                            100,
                            True
                        ))
                    else:
                        findings.append(create_finding(
                            "info",
                            f"Autorun entries in registry: {hive_name}\\{key_path}",
                            f"Found {len(autoruns)} autorun entry(ies). "
                            f"Verification confidence: 100%",
                            f"Review entries in {hive_name}\\{key_path}",
                            100,
                            True
                        ))

                winreg.CloseKey(key)

            except:
                pass

    except Exception:
        pass

    return findings

def check_windows_scheduled_tasks():
    """Check Windows scheduled tasks for persistence"""
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

        output = result.stdout

        # Count tasks
        task_count = output.count('TaskName:')

        # Look for suspicious task locations
        suspicious_patterns = [
            'powershell',
            'cmd.exe',
            '\\AppData\\',
            '\\Temp\\',
            '\\ProgramData\\',
            'rundll32'
        ]

        suspicious_tasks = []
        current_task = {}

        for line in output.split('\n'):
            line = line.strip()

            if line.startswith('TaskName:'):
                if current_task and 'task_to_run' in current_task:
                    task_to_run = current_task['task_to_run'].lower()
                    if any(pattern.lower() in task_to_run for pattern in suspicious_patterns):
                        suspicious_tasks.append(current_task)

                current_task = {'name': line.split(':', 1)[1].strip()}

            elif line.startswith('Task To Run:'):
                current_task['task_to_run'] = line.split(':', 1)[1].strip()

        if suspicious_tasks:
            findings.append(create_finding(
                "high",
                f"Suspicious scheduled tasks found",
                f"Found {len(suspicious_tasks)} suspicious scheduled task(s) out of {task_count} total. "
                f"Tasks may be used for persistence. "
                f"Verification confidence: 100%",
                "Review scheduled tasks: schtasks /query /fo LIST /v",
                100,
                True
            ))
        else:
            findings.append(create_finding(
                "info",
                f"Found {task_count} scheduled tasks",
                f"Review scheduled tasks for unauthorized entries. "
                f"Verification confidence: 100%",
                "Review: schtasks /query",
                100,
                True
            ))

    except Exception:
        pass

    return findings

def check_windows_startup_folders():
    """Check Windows startup folders"""
    findings = []

    if not is_windows():
        return findings

    try:
        startup_folders = [
            os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.expandvars(r'%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.expandvars(r'%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup')
        ]

        for startup_folder in startup_folders:
            if not os.path.exists(startup_folder):
                continue

            try:
                files = os.listdir(startup_folder)
                files = [f for f in files if not f.startswith('.') and f != 'desktop.ini']

                if files:
                    findings.append(create_finding(
                        "medium",
                        f"Files in startup folder: {startup_folder}",
                        f"Found {len(files)} file(s) in startup folder: {', '.join(files)}. "
                        f"These execute at user login. "
                        f"Verification confidence: 100%",
                        f"Review and remove unauthorized files from {startup_folder}",
                        100,
                        True
                    ))

            except Exception:
                pass

    except Exception:
        pass

    return findings

def check_windows_services():
    """Check Windows services for persistence"""
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

        # Count services
        service_count = result.stdout.count('SERVICE_NAME:')

        # Get services with non-standard binary paths
        suspicious_services = []

        services = []
        for line in result.stdout.split('\n'):
            if 'SERVICE_NAME:' in line:
                service_name = line.split(':', 1)[1].strip()
                services.append(service_name)

        # Check each service binary path
        for service in services[:50]:  # Limit to avoid timeout
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
                            path = line.split(':', 1)[1].strip().lower()

                            # Check for suspicious locations
                            if any(loc in path for loc in ['temp', 'appdata', 'programdata', 'users\\']):
                                suspicious_services.append((service, path))
                                break

            except:
                continue

        if suspicious_services:
            findings.append(create_finding(
                "high",
                "Suspicious Windows services found",
                f"Found {len(suspicious_services)} service(s) with suspicious binary locations. "
                f"Services: {suspicious_services[:3]}. "
                f"Verification confidence: 100%",
                "Review services: sc qc <service_name>",
                100,
                True
            ))

    except Exception:
        pass

    return findings

def check_windows_wmi_persistence():
    """Check for WMI persistence mechanisms"""
    findings = []

    if not is_windows():
        return findings

    try:
        # Check for WMI event subscriptions
        result = subprocess.run(
            ['wmic', 'process', 'where', 'name="wmiprvse.exe"', 'get', 'ProcessId,CommandLine'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0 and result.stdout.strip():
            # WMI provider is running
            findings.append(create_finding(
                "info",
                "WMI Provider Service running",
                "WMI provider service is active. "
                "WMI can be used for persistence via event subscriptions. "
                "Verification confidence: 100%",
                "Check WMI subscriptions: Get-WmiObject -Namespace root\\subscription -Class __EventFilter",
                100,
                True
            ))

    except Exception:
        pass

    return findings

def check_windows_dll_hijacking():
    """Check for DLL hijacking opportunities"""
    findings = []

    if not is_windows():
        return findings

    try:
        # Check PATH for writable directories
        path_dirs = os.environ.get('PATH', '').split(';')

        writable_paths = []
        for path_dir in path_dirs:
            if os.path.exists(path_dir):
                try:
                    if os.access(path_dir, os.W_OK):
                        writable_paths.append(path_dir)
                except:
                    pass

        if writable_paths:
            findings.append(create_finding(
                "high",
                f"Writable directories in PATH: {len(writable_paths)}",
                f"Found {len(writable_paths)} writable directories in PATH. "
                f"Can be used for DLL hijacking persistence. "
                f"Directories: {writable_paths[:3]}. "
                f"Verification confidence: 100%",
                "Remove writable directories from PATH or fix permissions",
                100,
                True
            ))

    except Exception:
        pass

    return findings

if __name__ == '__main__':
    # Test module
    import json
    results = check()
    print(json.dumps(results, indent=2))
