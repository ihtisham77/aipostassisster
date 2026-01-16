"""
Common Utilities Module for Security Assessments
Provides shared functions for OS detection, confidence scoring, and verification
"""

import os
import platform
import subprocess
import stat
import re
from pathlib import Path


class ConfidenceLevel:
    """Confidence level constants"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"


def get_os_type():
    """
    Get the operating system type

    Returns:
        str: 'linux', 'windows', 'darwin', or 'unknown'
    """
    system = platform.system().lower()
    if 'linux' in system:
        return 'linux'
    elif 'windows' in system:
        return 'windows'
    elif 'darwin' in system:
        return 'darwin'
    else:
        return 'unknown'


def is_linux():
    """Check if running on Linux"""
    return get_os_type() == 'linux'


def is_windows():
    """Check if running on Windows"""
    return get_os_type() == 'windows'


def is_macos():
    """Check if running on macOS"""
    return get_os_type() == 'darwin'


def calculate_confidence_score(*checks):
    """
    Calculate confidence score based on multiple verification checks

    Args:
        *checks: Boolean values from verification checks

    Returns:
        int: Confidence score (0-100)
    """
    if not checks:
        return 0

    passed = sum(1 for check in checks if check)
    total = len(checks)

    return int((passed / total) * 100)


def get_confidence_level(score):
    """
    Convert numeric confidence score to level

    Args:
        score: Confidence score (0-100)

    Returns:
        str: Confidence level (low, medium, high, verified)
    """
    if score >= 95:
        return ConfidenceLevel.VERIFIED
    elif score >= 75:
        return ConfidenceLevel.HIGH
    elif score >= 50:
        return ConfidenceLevel.MEDIUM
    else:
        return ConfidenceLevel.LOW


def verify_file_exists(filepath):
    """
    Verify a file exists with multiple checks

    Returns:
        tuple: (exists, confidence_score)
    """
    checks = [
        os.path.exists(filepath),
        os.path.isfile(filepath),
        Path(filepath).exists()
    ]

    exists = all(checks)
    confidence = calculate_confidence_score(*checks)

    return exists, confidence


def verify_executable(filepath):
    """
    Verify a file is executable with multiple checks

    Returns:
        tuple: (is_executable, confidence_score)
    """
    if not os.path.exists(filepath):
        return False, 0

    checks = []

    # Check if file exists
    checks.append(os.path.isfile(filepath))

    # Check execute permission
    checks.append(os.access(filepath, os.X_OK))

    # Check file mode on Unix systems
    if is_linux() or is_macos():
        try:
            file_stat = os.stat(filepath)
            checks.append(bool(file_stat.st_mode & stat.S_IXUSR))
        except:
            checks.append(False)

    is_exec = all(checks[:2])  # At minimum, file must exist and be executable
    confidence = calculate_confidence_score(*checks)

    return is_exec, confidence


def verify_suid_binary(filepath):
    """
    Verify SUID bit is set with multiple checks

    Returns:
        tuple: (has_suid, confidence_score)
    """
    if not is_linux() and not is_macos():
        return False, 0

    if not os.path.exists(filepath):
        return False, 0

    checks = []

    try:
        # Method 1: Check using os.stat
        file_stat = os.stat(filepath)
        has_suid_stat = bool(file_stat.st_mode & stat.S_ISUID)
        checks.append(has_suid_stat)

        # Method 2: Check using ls -l
        result = subprocess.run(
            ['ls', '-l', filepath],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            has_suid_ls = 's' in result.stdout.lower()[:10]
            checks.append(has_suid_ls)

        # Method 3: Check using find
        result = subprocess.run(
            ['find', filepath, '-perm', '-4000'],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            has_suid_find = len(result.stdout.strip()) > 0
            checks.append(has_suid_find)

    except Exception:
        pass

    if not checks:
        return False, 0

    has_suid = any(checks)  # If any method confirms SUID
    confidence = calculate_confidence_score(*checks)

    return has_suid, confidence


def verify_writable(filepath):
    """
    Verify file/directory is writable with multiple checks

    Returns:
        tuple: (is_writable, confidence_score)
    """
    if not os.path.exists(filepath):
        return False, 0

    checks = []

    # Method 1: Use os.access
    checks.append(os.access(filepath, os.W_OK))

    # Method 2: Check permissions
    try:
        file_stat = os.stat(filepath)
        if is_linux() or is_macos():
            # Check owner write permission
            checks.append(bool(file_stat.st_mode & stat.S_IWUSR))
            # Check if world-writable
            is_world_writable = bool(file_stat.st_mode & stat.S_IWOTH)
            if is_world_writable:
                checks.append(True)  # Strong indicator
    except:
        pass

    # Method 3: Try to open for writing (careful with this)
    # Only for files, not directories
    if os.path.isfile(filepath):
        try:
            with open(filepath, 'a') as f:
                checks.append(True)
        except (IOError, PermissionError):
            checks.append(False)

    is_writable = any(checks)
    confidence = calculate_confidence_score(*checks)

    return is_writable, confidence


def verify_world_readable(filepath):
    """
    Verify file is world-readable with multiple checks

    Returns:
        tuple: (is_world_readable, confidence_score)
    """
    if not os.path.exists(filepath):
        return False, 0

    checks = []

    try:
        file_stat = os.stat(filepath)

        # Check if readable by others
        is_readable = bool(file_stat.st_mode & stat.S_IROTH)
        checks.append(is_readable)

        # Cross-check with group readable
        is_group_readable = bool(file_stat.st_mode & stat.S_IRGRP)
        if is_group_readable:
            checks.append(True)

        # Verify can actually read
        can_read = os.access(filepath, os.R_OK)
        checks.append(can_read)

    except Exception:
        pass

    if not checks:
        return False, 0

    is_world_readable = checks[0] if checks else False
    confidence = calculate_confidence_score(*checks)

    return is_world_readable, confidence


def verify_process_running(process_name):
    """
    Verify a process is running with multiple checks

    Returns:
        tuple: (is_running, confidence_score, process_list)
    """
    checks = []
    found_processes = []

    try:
        if is_linux() or is_macos():
            # Method 1: ps aux
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                ps_found = process_name.lower() in result.stdout.lower()
                checks.append(ps_found)
                if ps_found:
                    for line in result.stdout.split('\n'):
                        if process_name.lower() in line.lower():
                            found_processes.append(line.strip())

            # Method 2: pgrep
            result = subprocess.run(
                ['pgrep', '-f', process_name],
                capture_output=True,
                text=True,
                timeout=2
            )
            pgrep_found = result.returncode == 0 and len(result.stdout.strip()) > 0
            checks.append(pgrep_found)

        elif is_windows():
            # Method 1: tasklist
            result = subprocess.run(
                ['tasklist'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                tasklist_found = process_name.lower() in result.stdout.lower()
                checks.append(tasklist_found)
                if tasklist_found:
                    for line in result.stdout.split('\n'):
                        if process_name.lower() in line.lower():
                            found_processes.append(line.strip())

    except Exception:
        pass

    if not checks:
        return False, 0, []

    is_running = any(checks)
    confidence = calculate_confidence_score(*checks)

    return is_running, confidence, found_processes


def verify_port_open(port, host='localhost'):
    """
    Verify a port is open/listening

    Returns:
        tuple: (is_open, confidence_score)
    """
    import socket

    checks = []

    # Method 1: Try to connect
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        checks.append(result == 0)
        sock.close()
    except:
        checks.append(False)

    # Method 2: Check with netstat (Linux/Mac) or netstat (Windows)
    try:
        if is_linux() or is_macos():
            result = subprocess.run(
                ['ss', '-tuln'],
                capture_output=True,
                text=True,
                timeout=3
            )
            if result.returncode == 0:
                port_found = f':{port}' in result.stdout
                checks.append(port_found)
        elif is_windows():
            result = subprocess.run(
                ['netstat', '-an'],
                capture_output=True,
                text=True,
                timeout=3
            )
            if result.returncode == 0:
                port_found = f':{port}' in result.stdout
                checks.append(port_found)
    except:
        pass

    if not checks:
        return False, 0

    is_open = any(checks)
    confidence = calculate_confidence_score(*checks)

    return is_open, confidence


def verify_command_exists(command):
    """
    Verify a command exists in PATH

    Returns:
        tuple: (exists, confidence_score, path)
    """
    checks = []
    command_path = None

    try:
        # Method 1: which (Unix) or where (Windows)
        if is_linux() or is_macos():
            result = subprocess.run(
                ['which', command],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                command_path = result.stdout.strip()
                checks.append(True)
            else:
                checks.append(False)
        elif is_windows():
            result = subprocess.run(
                ['where', command],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                command_path = result.stdout.strip().split('\n')[0]
                checks.append(True)
            else:
                checks.append(False)

        # Method 2: Try to execute --version or --help
        try:
            result = subprocess.run(
                [command, '--version'],
                capture_output=True,
                text=True,
                timeout=2
            )
            checks.append(result.returncode == 0)
        except:
            try:
                result = subprocess.run(
                    [command, '--help'],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                checks.append(result.returncode == 0)
            except:
                checks.append(False)

    except Exception:
        pass

    if not checks:
        return False, 0, None

    exists = any(checks)
    confidence = calculate_confidence_score(*checks)

    return exists, confidence, command_path


def create_finding(severity, finding, description, remediation, confidence_score=None, verified=False):
    """
    Create a standardized finding dictionary with confidence scoring

    Args:
        severity: Severity level (critical, high, medium, low, info)
        finding: Short description of the finding
        description: Detailed description
        remediation: Remediation steps
        confidence_score: Numeric confidence score (0-100)
        verified: Whether the finding has been verified by multiple methods

    Returns:
        dict: Standardized finding dictionary
    """
    finding_dict = {
        "severity": severity,
        "finding": finding,
        "description": description,
        "remediation": remediation
    }

    if confidence_score is not None:
        finding_dict["confidence_score"] = confidence_score
        finding_dict["confidence_level"] = get_confidence_level(confidence_score)

    if verified:
        finding_dict["verified"] = True

    return finding_dict


def safe_run_command(command, timeout=5, shell=False):
    """
    Safely run a command with timeout and error handling

    Returns:
        tuple: (success, stdout, stderr)
    """
    try:
        if isinstance(command, str) and not shell:
            import shlex
            command = shlex.split(command)

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell
        )

        return result.returncode == 0, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


# OS-specific dangerous binaries with SUID
DANGEROUS_SUID_BINARIES = {
    'linux': [
        'find', 'vim', 'nano', 'cp', 'mv', 'python', 'python2', 'python3',
        'perl', 'ruby', 'lua', 'php', 'gcc', 'make', 'sh', 'bash', 'dash',
        'zsh', 'ksh', 'tcsh', 'awk', 'sed', 'tar', 'zip', 'unzip',
        'gzip', 'gunzip', 'nmap', 'less', 'more', 'cat', 'tail', 'head',
        'curl', 'wget', 'nc', 'netcat', 'socat', 'telnet', 'ftp', 'ssh'
    ],
    'windows': [
        'cmd.exe', 'powershell.exe', 'python.exe', 'perl.exe', 'ruby.exe',
        'wmic.exe', 'psexec.exe', 'cacls.exe', 'icacls.exe'
    ]
}


def get_dangerous_binaries():
    """Get list of dangerous binaries for current OS"""
    os_type = get_os_type()
    return DANGEROUS_SUID_BINARIES.get(os_type, [])
