"""
Credential Harvesting Assessment Module
Checks for insecurely stored credentials and sensitive information
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
    def verify_world_readable(path):
        try:
            st = os.stat(path)
            return (bool(st.st_mode & 0o044), 100)
        except:
            return (False, 0)
    def calculate_confidence_score(*checks):
        if not checks: return 0
        return int((sum(1 for c in checks if c) / len(checks)) * 100)

def check():
    """
    Check for credential exposure and insecure storage
    OS-specific with confidence scoring
    """
    results = {
        "module": "credential_harvesting",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # OS-specific credential checks
        if is_linux() or is_macos():
            results["findings"].extend(check_unix_credentials())
        elif is_windows():
            results["findings"].extend(check_windows_credentials())
        else:
            results["findings"].append(create_finding(
                "info",
                "Unsupported OS",
                f"Credential harvesting checks not implemented for {platform.system()}",
                "Run module on Linux or Windows system",
                0
            ))

        # Common checks for all OS
        results["findings"].extend(check_environment_variables_enhanced())

    except Exception as e:
        results["error"] = str(e)

    return results

def check_unix_credentials():
    """Unix/Linux-specific credential checks"""
    findings = []

    # Enhanced history file checks
    findings.extend(check_history_files_enhanced())

    # Enhanced config file checks
    findings.extend(check_config_files_enhanced())

    # Enhanced SSH key checks
    findings.extend(check_ssh_keys_enhanced())

    # Enhanced password file checks
    findings.extend(check_password_files_enhanced())

    # Enhanced database config checks
    findings.extend(check_database_configs_enhanced())

    # Browser credential checks
    findings.extend(check_browser_data_enhanced())

    # Additional Unix checks
    findings.extend(check_private_keys())
    findings.extend(check_cloud_credentials())

    return findings

def check_windows_credentials():
    """Windows-specific credential checks"""
    findings = []

    # Windows credential storage checks
    findings.extend(check_windows_credential_manager())

    # Windows registry credentials
    findings.extend(check_windows_registry_credentials())

    # Windows cached credentials
    findings.extend(check_windows_cached_credentials())

    # Windows browser credentials
    findings.extend(check_windows_browser_credentials())

    # PowerShell history
    findings.extend(check_powershell_history())

    # Windows config files
    findings.extend(check_windows_config_files())

    # Unattended install files
    findings.extend(check_unattended_install_files())

    return findings

def check_history_files_enhanced():
    """Enhanced shell history checking with confidence scoring"""
    findings = []

    try:
        history_files = [
            '~/.bash_history',
            '~/.zsh_history',
            '~/.zhistory',
            '~/.mysql_history',
            '~/.psql_history',
            '~/.python_history',
            '~/.node_repl_history',
            '~/.rediscli_history'
        ]

        # Enhanced patterns with context
        sensitive_patterns = {
            r'password\s*[=:]\s*["\']?([^\s"\';]+)': 'password assignment',
            r'passwd\s+([^\s]+)': 'passwd command',
            r'mysql\s+.*-p\s*([^\s]+)': 'MySQL password in command',
            r'psql\s+.*password[=\s]+([^\s]+)': 'PostgreSQL password',
            r'curl\s+.*Authorization[:\s]+[\'"]?([^\s\'"]+)': 'Authorization header',
            r'wget\s+.*password[=\s]+([^\s]+)': 'wget with password',
            r'api[_-]?key\s*[=:]\s*["\']?([^\s"\';]{20,})': 'API key',
            r'token\s*[=:]\s*["\']?([^\s"\';]{20,})': 'authentication token',
            r'secret[_-]?key\s*[=:]\s*["\']?([^\s"\';]{20,})': 'secret key',
            r'aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?([A-Z0-9]{20})': 'AWS access key',
            r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})': 'AWS secret key',
            r'export\s+([A-Z_]*PASSWORD[A-Z_]*=[^\s]+)': 'exported password variable',
            r'(https?://[^:@\s]+:[^@\s]+@[^\s]+)': 'URL with credentials'
        }

        for history_file in history_files:
            expanded_path = os.path.expanduser(history_file)

            # Multi-method verification
            exists, exist_confidence = verify_file_exists(expanded_path)

            if not exists:
                continue

            try:
                checks = []
                checks.append(exists)

                # Check file is readable
                can_read = os.access(expanded_path, os.R_OK)
                checks.append(can_read)

                if not can_read:
                    continue

                with open(expanded_path, 'r', errors='ignore') as f:
                    content = f.read()
                    checks.append(len(content) > 0)

                    matched_patterns = []
                    total_matches = 0

                    for pattern, pattern_desc in sensitive_patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            matched_patterns.append(pattern_desc)
                            total_matches += len(matches)

                    if matched_patterns:
                        # Higher confidence for multiple pattern matches
                        confidence = calculate_confidence_score(*checks)
                        confidence = min(100, confidence + (len(matched_patterns) * 5))

                        findings.append(create_finding(
                            "high",
                            f"Credentials found in history: {expanded_path}",
                            f"Found {total_matches} potential credential(s) matching {len(matched_patterns)} pattern(s): "
                            f"{', '.join(matched_patterns)}. "
                            f"Sensitive data in shell history can be accessed by attackers. "
                            f"Verification confidence: {confidence}%",
                            f"Clear sensitive commands: history -c && rm {expanded_path}. "
                            f"Use secure credential storage and avoid passing credentials on command line",
                            confidence,
                            confidence >= 95
                        ))

                # Check if history file is world-readable
                is_readable, read_confidence = verify_world_readable(expanded_path)

                if is_readable:
                    findings.append(create_finding(
                        "medium",
                        f"History file readable by others: {expanded_path}",
                        f"History file has insecure permissions allowing other users to read command history. "
                        f"May expose sensitive commands and credentials. "
                        f"Verification confidence: {read_confidence}%",
                        f"Fix permissions: chmod 600 {expanded_path}",
                        read_confidence,
                        read_confidence >= 95
                    ))

            except Exception as e:
                pass

    except Exception:
        pass

    return findings

def check_config_files_enhanced():
    """Enhanced configuration file checks with confidence scoring"""
    findings = []

    try:
        # Common config file patterns
        config_patterns = [
            '~/.aws/credentials',
            '~/.aws/config',
            '~/.docker/config.json',
            '~/.netrc',
            '~/.git-credentials',
            '~/.config/gcloud/*',
            '~/.kube/config',
            '~/.env',
            '~/.npmrc',
            '~/.pypirc'
        ]

        for pattern in config_patterns:
            for filepath in glob.glob(os.path.expanduser(pattern)):
                if not os.path.isfile(filepath):
                    continue

                # Multi-method verification
                checks = []
                exists, _ = verify_file_exists(filepath)
                checks.append(exists)

                # Check permissions
                is_readable, read_confidence = verify_world_readable(filepath)
                checks.append(not is_readable)  # Check for proper permissions

                confidence = calculate_confidence_score(*checks)

                if is_readable:
                    findings.append(create_finding(
                        "critical",
                        f"Credential file world-readable: {filepath}",
                        f"Configuration file containing credentials is accessible by other users. "
                        f"This exposes sensitive authentication data. "
                        f"Verification confidence: {min(100, confidence + 20)}%",
                        f"Fix permissions immediately: chmod 600 {filepath}",
                        min(100, confidence + 20),
                        True
                    ))
                else:
                    findings.append(create_finding(
                        "medium",
                        f"Credential file found: {filepath}",
                        f"Configuration file may contain sensitive credentials. "
                        f"Permissions are correct but file should be monitored. "
                        f"Verification confidence: {confidence}%",
                        "Ensure credentials are rotated regularly and not committed to version control",
                        confidence,
                        confidence >= 95
                    ))

        # Search for .env files
        for root, dirs, files in os.walk(os.path.expanduser('~'), topdown=True):
            # Limit search depth and skip common directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'venv', '.git', '__pycache__']]

            if len(root.split(os.sep)) > 8:
                break

            for file in files:
                if file in ['.env', '.env.local', '.env.production', '.env.development', 'credentials.json', 'service-account.json']:
                    filepath = os.path.join(root, file)

                    # Check if contains credentials
                    contains_creds = False
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read(1024)  # Read first 1KB
                            cred_indicators = ['password', 'secret', 'api_key', 'token', 'credential']
                            contains_creds = any(indicator in content.lower() for indicator in cred_indicators)
                    except:
                        pass

                    if contains_creds:
                        is_readable, read_confidence = verify_world_readable(filepath)

                        severity = "high" if is_readable else "medium"
                        confidence = read_confidence if is_readable else 75

                        findings.append(create_finding(
                            severity,
                            f"Environment/credential file found: {filepath}",
                            f"File contains credential indicators. "
                            f"{'World-readable - immediate risk!' if is_readable else 'Permissions OK but monitor file.'} "
                            f"Verification confidence: {confidence}%",
                            f"{'Fix permissions: chmod 600 ' + filepath if is_readable else 'Ensure not committed to version control'}",
                            confidence,
                            confidence >= 95
                        ))

    except Exception:
        pass

    return findings

def check_ssh_keys_enhanced():
    """Enhanced SSH private key checks with confidence scoring"""
    findings = []

    try:
        ssh_dir = os.path.expanduser('~/.ssh')

        if not os.path.exists(ssh_dir):
            return findings

        for file in os.listdir(ssh_dir):
            filepath = os.path.join(ssh_dir, file)

            if not os.path.isfile(filepath):
                continue

            # Skip public keys
            if file.endswith('.pub') or file in ['known_hosts', 'authorized_keys', 'config']:
                continue

            try:
                checks = []

                # Check if it's a private key
                with open(filepath, 'r', errors='ignore') as f:
                    first_line = f.readline()
                    is_private_key = 'PRIVATE KEY' in first_line
                    checks.append(is_private_key)

                if not is_private_key:
                    continue

                # Check permissions using multiple methods
                checks.append(os.path.exists(filepath))

                stat_info = os.stat(filepath)
                mode = stat_info.st_mode

                # Check if readable by group or others
                has_bad_perms = bool(mode & 0o077)
                checks.append(not has_bad_perms)

                confidence = calculate_confidence_score(*checks)

                if has_bad_perms:
                    findings.append(create_finding(
                        "critical",
                        f"SSH private key with insecure permissions: {filepath}",
                        f"Private key is readable/writable by other users (mode: {oct(mode)}). "
                        f"This allows unauthorized access using this key. "
                        f"Verification confidence: {confidence}%",
                        f"Fix permissions immediately: chmod 600 {filepath}",
                        confidence,
                        confidence >= 95
                    ))
                else:
                    findings.append(create_finding(
                        "info",
                        f"SSH private key found: {filepath}",
                        f"Private key is properly secured with correct permissions (mode: {oct(mode)}). "
                        f"Verification confidence: {confidence}%",
                        "Ensure key passphrase is used and key is not shared",
                        confidence,
                        confidence >= 95
                    ))

            except Exception:
                pass

    except Exception:
        pass

    return findings

def check_password_files_enhanced():
    """Enhanced password file checks with confidence scoring"""
    findings = []

    try:
        # Check /etc/shadow readability (should NOT be readable)
        if os.path.exists('/etc/shadow'):
            checks = []
            checks.append(os.path.exists('/etc/shadow'))

            can_read = os.access('/etc/shadow', os.R_OK)
            checks.append(can_read)

            if can_read:
                # Try to actually read it
                try:
                    with open('/etc/shadow', 'r') as f:
                        content = f.read(100)
                        checks.append(len(content) > 0)
                except:
                    checks.append(False)

                confidence = calculate_confidence_score(*checks)

                findings.append(create_finding(
                    "critical",
                    "/etc/shadow is readable by current user",
                    f"Shadow password file contains hashed passwords and is readable. "
                    f"This allows password cracking attacks. "
                    f"This indicates serious privilege escalation or misconfiguration. "
                    f"Verification confidence: {confidence}%",
                    "This is a critical security issue. Check system permissions: sudo chmod 640 /etc/shadow",
                    confidence,
                    confidence >= 95
                ))

        # Check for password backup files
        password_backups = [
            '/etc/passwd-',
            '/etc/shadow-',
            '/etc/group-',
            '/etc/gshadow-',
            '/etc/security/opasswd'
        ]

        for backup in password_backups:
            if os.path.exists(backup):
                checks = []
                checks.append(True)

                can_read = os.access(backup, os.R_OK)
                checks.append(can_read)

                if can_read:
                    confidence = calculate_confidence_score(*checks)

                    findings.append(create_finding(
                        "high",
                        f"Password backup file readable: {backup}",
                        f"Backup password file is accessible. May contain historical password hashes. "
                        f"Verification confidence: {confidence}%",
                        f"Fix permissions: sudo chmod 640 {backup}",
                        confidence,
                        confidence >= 95
                    ))

    except Exception:
        pass

    return findings

def check_database_configs_enhanced():
    """Enhanced database configuration file checks"""
    findings = []

    try:
        db_configs = [
            '/etc/mysql/my.cnf',
            '/etc/mysql/mysql.conf.d/*.cnf',
            '/etc/postgresql/*/main/postgresql.conf',
            '/etc/postgresql/*/main/pg_hba.conf',
            '~/.my.cnf',
            '~/.pgpass',
            '~/mysql_history'
        ]

        credential_patterns = [
            r'password\s*=\s*["\']?([^\s"\';]+)',
            r'passwd\s*=\s*["\']?([^\s"\';]+)',
            r'PASSWORD\s*=\s*["\']?([^\s"\';]+)'
        ]

        for pattern in db_configs:
            for filepath in glob.glob(os.path.expanduser(pattern)):
                if not os.path.isfile(filepath):
                    continue

                checks = []
                exists, _ = verify_file_exists(filepath)
                checks.append(exists)

                can_read = os.access(filepath, os.R_OK)
                checks.append(can_read)

                if not can_read:
                    continue

                # Check for credentials in file
                has_creds = False
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        content = f.read()
                        for cred_pattern in credential_patterns:
                            if re.search(cred_pattern, content, re.IGNORECASE):
                                has_creds = True
                                break
                except:
                    pass

                checks.append(has_creds)

                # Check permissions
                is_readable, read_confidence = verify_world_readable(filepath)

                confidence = calculate_confidence_score(*checks)

                if has_creds and is_readable:
                    findings.append(create_finding(
                        "critical",
                        f"Database config with credentials world-readable: {filepath}",
                        f"Configuration file contains database credentials and is readable by others. "
                        f"Verification confidence: {min(100, confidence + 20)}%",
                        f"Fix permissions immediately: chmod 600 {filepath}",
                        min(100, confidence + 20),
                        True
                    ))
                elif has_creds:
                    findings.append(create_finding(
                        "medium",
                        f"Database config with credentials: {filepath}",
                        f"File contains database credentials. Permissions are OK. "
                        f"Verification confidence: {confidence}%",
                        "Ensure credentials are rotated regularly",
                        confidence,
                        confidence >= 95
                    ))
                elif is_readable:
                    findings.append(create_finding(
                        "low",
                        f"Database config world-readable: {filepath}",
                        f"Configuration file is readable by others but no obvious credentials found. "
                        f"Verification confidence: {read_confidence}%",
                        f"Fix permissions: chmod 640 {filepath}",
                        read_confidence,
                        read_confidence >= 95
                    ))

    except Exception:
        pass

    return findings

def check_browser_data_enhanced():
    """Enhanced browser credential storage checks"""
    findings = []

    try:
        browser_paths = {
            '~/.mozilla/firefox': 'Firefox',
            '~/.config/google-chrome': 'Chrome',
            '~/.config/chromium': 'Chromium',
            '~/Library/Application Support/Firefox': 'Firefox (macOS)',
            '~/Library/Application Support/Google/Chrome': 'Chrome (macOS)'
        }

        for browser_path, browser_name in browser_paths.items():
            expanded_path = os.path.expanduser(browser_path)

            if not os.path.exists(expanded_path):
                continue

            # Look for credential databases
            cred_files = []
            try:
                for root, dirs, files in os.walk(expanded_path):
                    for file in files:
                        if file in ['key4.db', 'key3.db', 'logins.json', 'Login Data', 'Cookies']:
                            cred_files.append(os.path.join(root, file))
            except:
                pass

            if cred_files:
                # Check permissions on credential files
                for cred_file in cred_files:
                    is_readable, read_confidence = verify_world_readable(cred_file)

                    if is_readable:
                        findings.append(create_finding(
                            "high",
                            f"{browser_name} credential database world-readable: {cred_file}",
                            f"Browser credential database is accessible by other users. "
                            f"May allow extraction of saved passwords. "
                            f"Verification confidence: {read_confidence}%",
                            f"Fix permissions: chmod 600 {cred_file}",
                            read_confidence,
                            read_confidence >= 95
                        ))
                    else:
                        findings.append(create_finding(
                            "info",
                            f"{browser_name} credential storage found: {cred_file}",
                            f"Browser stores credentials. Permissions are correct. "
                            f"Verification confidence: {read_confidence}%",
                            "Use browser master password for additional security",
                            read_confidence,
                            read_confidence >= 95
                        ))

    except Exception:
        pass

    return findings

def check_private_keys():
    """Check for various private key types"""
    findings = []

    try:
        # Common private key locations and patterns
        key_patterns = [
            '~/.gnupg/secring.gpg',
            '~/.gnupg/private-keys-v1.d/*',
            '~/.ssh/id_*',
            '~/.aws/*.pem',
            '~/*.pem',
            '~/*.key',
            '~/.*_key'
        ]

        for pattern in key_patterns:
            for filepath in glob.glob(os.path.expanduser(pattern)):
                if not os.path.isfile(filepath):
                    continue

                # Skip public keys
                if filepath.endswith('.pub') or filepath.endswith('.pem.pub'):
                    continue

                # Check if it looks like a private key
                is_private = False
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        content = f.read(200)
                        if 'PRIVATE KEY' in content or 'BEGIN RSA' in content or 'BEGIN ENCRYPTED' in content:
                            is_private = True
                except:
                    # Binary file, might still be a key
                    if any(ext in os.path.basename(filepath) for ext in ['key', 'pem', 'gpg']):
                        is_private = True

                if is_private:
                    is_readable, read_confidence = verify_world_readable(filepath)

                    if is_readable:
                        findings.append(create_finding(
                            "high",
                            f"Private key file world-readable: {filepath}",
                            f"Private key file has insecure permissions. "
                            f"Verification confidence: {read_confidence}%",
                            f"Fix permissions: chmod 600 {filepath}",
                            read_confidence,
                            read_confidence >= 95
                        ))

    except Exception:
        pass

    return findings

def check_cloud_credentials():
    """Check for cloud provider credentials"""
    findings = []

    try:
        cloud_creds = {
            '~/.aws/credentials': 'AWS credentials',
            '~/.aws/config': 'AWS configuration',
            '~/.azure/credentials': 'Azure credentials',
            '~/.config/gcloud/credentials.db': 'Google Cloud credentials',
            '~/.config/gcloud/legacy_credentials': 'Google Cloud legacy credentials',
            '~/.kube/config': 'Kubernetes configuration',
            '~/.docker/config.json': 'Docker credentials'
        }

        for filepath, description in cloud_creds.items():
            expanded_path = os.path.expanduser(filepath)

            if not os.path.exists(expanded_path):
                continue

            exists, exist_confidence = verify_file_exists(expanded_path)

            is_readable, read_confidence = verify_world_readable(expanded_path)

            if is_readable:
                findings.append(create_finding(
                    "critical",
                    f"Cloud credentials world-readable: {expanded_path}",
                    f"{description} file is accessible by other users. "
                    f"This exposes cloud access credentials. "
                    f"Verification confidence: {read_confidence}%",
                    f"Fix permissions immediately: chmod 600 {expanded_path}",
                    read_confidence,
                    read_confidence >= 95
                ))
            else:
                findings.append(create_finding(
                    "medium",
                    f"Cloud credentials found: {expanded_path}",
                    f"{description} file found. Permissions are correct. "
                    f"Verification confidence: {exist_confidence}%",
                    "Rotate credentials regularly and use IAM roles when possible",
                    exist_confidence,
                    exist_confidence >= 95
                ))

    except Exception:
        pass

    return findings

def check_environment_variables_enhanced():
    """Enhanced environment variable checks with confidence scoring"""
    findings = []

    try:
        sensitive_keys = [
            'PASSWORD', 'PASSWD', 'PWD', 'API_KEY', 'APIKEY', 'SECRET',
            'TOKEN', 'ACCESS_KEY', 'SECRET_KEY', 'PRIVATE_KEY',
            'DATABASE_URL', 'DB_PASSWORD', 'DB_PASS', 'AWS_SECRET',
            'AZURE_', 'GCP_', 'GITHUB_TOKEN', 'GITLAB_TOKEN'
        ]

        found_sensitive = []

        for key, value in os.environ.items():
            for sensitive in sensitive_keys:
                if sensitive in key.upper():
                    # Mask the value
                    if len(value) > 6:
                        masked_value = value[:3] + '*' * min(20, len(value) - 6) + value[-3:]
                    elif len(value) > 3:
                        masked_value = value[:2] + '*' * (len(value) - 2)
                    else:
                        masked_value = '***'

                    found_sensitive.append((key, masked_value, len(value)))

        if found_sensitive:
            # Higher confidence if multiple sensitive vars found
            confidence = min(100, 70 + (len(found_sensitive) * 5))

            for key, masked, length in found_sensitive:
                findings.append(create_finding(
                    "medium",
                    f"Sensitive environment variable: {key}",
                    f"Environment variable contains sensitive data (length: {length} chars). "
                    f"Masked value: {masked}. "
                    f"Environment variables can be accessed by child processes. "
                    f"Verification confidence: {confidence}%",
                    "Avoid storing credentials in environment variables when possible. Use secure secret management.",
                    confidence,
                    confidence >= 95
                ))

    except Exception:
        pass

    return findings

# Windows-specific credential checks

def check_windows_credential_manager():
    """Check Windows Credential Manager for stored credentials"""
    findings = []

    if not is_windows():
        return findings

    try:
        # Use cmdkey to list credentials
        result = subprocess.run(
            ['cmdkey', '/list'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            output = result.stdout

            # Count credential entries
            cred_count = output.count('Target:')

            if cred_count > 0:
                findings.append(create_finding(
                    "medium",
                    f"Windows Credential Manager contains {cred_count} stored credentials",
                    f"Credential Manager stores {cred_count} credential(s). "
                    f"These can be extracted by users with appropriate access. "
                    f"Verification confidence: 100%",
                    "Review stored credentials and remove unnecessary ones. Use protected credentials where possible.",
                    100,
                    True
                ))

    except Exception:
        pass

    return findings

def check_windows_registry_credentials():
    """Check Windows registry for stored credentials"""
    findings = []

    if not is_windows():
        return findings

    try:
        import winreg

        # Common registry locations for credentials
        registry_paths = [
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Terminal Server Client\Servers'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'),
        ]

        for hive, key_path in registry_paths:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)

                hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"

                # Check for username/password values
                i = 0
                has_credentials = False
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if any(cred in name.lower() for cred in ['password', 'passwd', 'pwd', 'username', 'user']):
                            has_credentials = True
                            break
                        i += 1
                    except OSError:
                        break

                if has_credentials:
                    findings.append(create_finding(
                        "high",
                        f"Credentials in registry: {hive_name}\\{key_path}",
                        "Registry key contains credential-related values. "
                        "Registry credentials can be extracted. "
                        "Verification confidence: 100%",
                        "Remove credentials from registry and use secure credential storage",
                        100,
                        True
                    ))

                winreg.CloseKey(key)
            except:
                pass

    except Exception:
        pass

    return findings

def check_windows_cached_credentials():
    """Check for Windows cached credentials"""
    findings = []

    if not is_windows():
        return findings

    try:
        # Check for LSA secrets (requires elevation)
        lsa_locations = [
            r'C:\Windows\System32\config\SAM',
            r'C:\Windows\System32\config\SYSTEM',
            r'C:\Windows\System32\config\SECURITY'
        ]

        for location in lsa_locations:
            if os.path.exists(location):
                can_read = os.access(location, os.R_OK)

                if can_read:
                    findings.append(create_finding(
                        "critical",
                        f"LSA secrets file accessible: {location}",
                        "System credential storage file is readable. "
                        "This indicates admin/system level access and allows credential extraction. "
                        "Verification confidence: 100%",
                        "This indicates privilege escalation. Review system security.",
                        100,
                        True
                    ))

    except Exception:
        pass

    return findings

def check_windows_browser_credentials():
    """Check Windows browser credential storage"""
    findings = []

    if not is_windows():
        return findings

    try:
        browser_paths = {
            os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data'): 'Chrome',
            os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles'): 'Firefox',
            os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data'): 'Edge'
        }

        for browser_path, browser_name in browser_paths.items():
            if os.path.exists(browser_path):
                findings.append(create_finding(
                    "info",
                    f"{browser_name} credential storage found: {browser_path}",
                    f"{browser_name} stores credentials that can be extracted with appropriate tools. "
                    "Verification confidence: 100%",
                    "Use browser master password for additional protection",
                    100,
                    True
                ))

    except Exception:
        pass

    return findings

def check_powershell_history():
    """Check PowerShell command history for credentials"""
    findings = []

    if not is_windows():
        return findings

    try:
        ps_history = os.path.expandvars(r'%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')

        if not os.path.exists(ps_history):
            return findings

        # Read and check for credentials
        try:
            with open(ps_history, 'r', errors='ignore') as f:
                content = f.read()

                credential_patterns = [
                    r'password',
                    r'credential',
                    r'ConvertTo-SecureString',
                    r'Get-Credential',
                    r'PSCredential',
                    r'-Password'
                ]

                matches = []
                for pattern in credential_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        matches.append(pattern)

                if matches:
                    findings.append(create_finding(
                        "high",
                        f"Credentials in PowerShell history: {ps_history}",
                        f"PowerShell history contains {len(matches)} credential-related commands. "
                        "Command history may expose sensitive data. "
                        "Verification confidence: 100%",
                        f"Clear PowerShell history: Remove-Item {ps_history}",
                        100,
                        True
                    ))

        except Exception:
            pass

    except Exception:
        pass

    return findings

def check_windows_config_files():
    """Check common Windows configuration files for credentials"""
    findings = []

    if not is_windows():
        return findings

    try:
        config_locations = [
            os.path.expandvars(r'%USERPROFILE%\.aws\credentials'),
            os.path.expandvars(r'%USERPROFILE%\.azure\credentials'),
            os.path.expandvars(r'%USERPROFILE%\.docker\config.json'),
            os.path.expandvars(r'%USERPROFILE%\.kube\config'),
            os.path.expandvars(r'%USERPROFILE%\.gitconfig'),
        ]

        for config_file in config_locations:
            if os.path.exists(config_file):
                findings.append(create_finding(
                    "medium",
                    f"Configuration file with potential credentials: {config_file}",
                    "Configuration file may contain credentials. "
                    "Verification confidence: 100%",
                    "Ensure file is not shared and credentials are rotated regularly",
                    100,
                    True
                ))

    except Exception:
        pass

    return findings

def check_unattended_install_files():
    """Check for unattended installation files with credentials"""
    findings = []

    if not is_windows():
        return findings

    try:
        unattend_files = [
            r'C:\Windows\Panther\Unattend.xml',
            r'C:\Windows\Panther\Unattended.xml',
            r'C:\Windows\System32\Sysprep\Unattend.xml',
            r'C:\Windows\System32\Sysprep\Panther\Unattend.xml',
            r'C:\unattend.xml'
        ]

        for unattend_file in unattend_files:
            if os.path.exists(unattend_file):
                can_read = os.access(unattend_file, os.R_OK)

                if can_read:
                    # Check if contains credentials
                    has_creds = False
                    try:
                        with open(unattend_file, 'r', errors='ignore') as f:
                            content = f.read()
                            if any(tag in content for tag in ['Password', 'password', 'AdministratorPassword']):
                                has_creds = True
                    except:
                        pass

                    if has_creds:
                        findings.append(create_finding(
                            "critical",
                            f"Unattended install file with credentials: {unattend_file}",
                            "Unattended installation file contains credentials (possibly administrator password). "
                            "This is a common privilege escalation vector. "
                            "Verification confidence: 100%",
                            f"Remove or secure file: delete or restrict permissions on {unattend_file}",
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
