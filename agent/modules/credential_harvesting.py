"""
Credential Harvesting Assessment Module
Checks for insecurely stored credentials and sensitive information
"""

import os
import platform
import subprocess
import glob
import re

def check():
    """
    Check for credential exposure and insecure storage
    """
    results = {
        "module": "credential_harvesting",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # Check history files
        history_findings = check_history_files()
        if history_findings:
            results["findings"].extend(history_findings)

        # Check config files for credentials
        config_findings = check_config_files()
        if config_findings:
            results["findings"].extend(config_findings)

        # Check environment variables
        env_findings = check_environment_variables()
        if env_findings:
            results["findings"].extend(env_findings)

        # Check SSH private keys
        ssh_findings = check_ssh_keys()
        if ssh_findings:
            results["findings"].extend(ssh_findings)

        # Check browser data
        browser_findings = check_browser_data()
        if browser_findings:
            results["findings"].extend(browser_findings)

        # Check password files
        password_findings = check_password_files()
        if password_findings:
            results["findings"].extend(password_findings)

        # Check database configuration
        db_findings = check_database_configs()
        if db_findings:
            results["findings"].extend(db_findings)

    except Exception as e:
        results["error"] = str(e)

    return results

def check_history_files():
    """Check shell history for credentials"""
    findings = []

    try:
        history_files = [
            '~/.bash_history',
            '~/.zsh_history',
            '~/.mysql_history',
            '~/.psql_history',
            '~/.python_history'
        ]

        sensitive_patterns = [
            r'password\s*=\s*["\']?[\w!@#$%^&*()]+',
            r'passwd\s+\w+',
            r'mysql.*-p\w+',
            r'psql.*password',
            r'curl.*Authorization',
            r'wget.*password',
            r'api[_-]?key\s*=\s*["\']?[\w-]+',
            r'token\s*=\s*["\']?[\w.-]+',
            r'secret\s*=\s*["\']?[\w-]+'
        ]

        for history_file in history_files:
            expanded_path = os.path.expanduser(history_file)

            if os.path.exists(expanded_path):
                try:
                    with open(expanded_path, 'r', errors='ignore') as f:
                        content = f.read()

                        for pattern in sensitive_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                findings.append({
                                    "severity": "high",
                                    "finding": f"Credentials in history: {expanded_path}",
                                    "description": f"Found {len(matches)} potential credential(s)",
                                    "remediation": "Clear sensitive commands from history and use secure credential storage"
                                })
                                break

                    # Check if history file is world-readable
                    stat_info = os.stat(expanded_path)
                    if stat_info.st_mode & 0o044:  # Readable by group or others
                        findings.append({
                            "severity": "medium",
                            "finding": f"History file readable by others: {expanded_path}",
                            "description": "History file has insecure permissions",
                            "remediation": f"Fix permissions: chmod 600 {expanded_path}"
                        })

                except Exception:
                    pass

    except Exception:
        pass

    return findings

def check_config_files():
    """Check configuration files for hardcoded credentials"""
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
                if os.path.isfile(filepath):
                    # Check permissions
                    stat_info = os.stat(filepath)
                    if stat_info.st_mode & 0o044:  # Readable by group or others
                        findings.append({
                            "severity": "high",
                            "finding": f"Config file with credentials readable: {filepath}",
                            "description": "Configuration file containing credentials is readable by others",
                            "remediation": f"Fix permissions: chmod 600 {filepath}"
                        })

                    findings.append({
                        "severity": "medium",
                        "finding": f"Credential file found: {filepath}",
                        "description": "Configuration file may contain sensitive credentials",
                        "remediation": "Ensure credentials are properly secured"
                    })

        # Search for .env files in current directory tree
        for root, dirs, files in os.walk(os.path.expanduser('~'), topdown=True):
            # Limit search depth
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'venv', '.git']]

            if len(root.split(os.sep)) > 10:
                continue

            for file in files:
                if file in ['.env', '.env.local', '.env.production', 'credentials.json']:
                    filepath = os.path.join(root, file)

                    findings.append({
                        "severity": "medium",
                        "finding": f"Environment file found: {filepath}",
                        "description": "File may contain sensitive environment variables",
                        "remediation": "Ensure file is not committed to version control"
                    })

    except Exception:
        pass

    return findings

def check_environment_variables():
    """Check environment variables for credentials"""
    findings = []

    try:
        sensitive_keys = [
            'PASSWORD', 'PASSWD', 'API_KEY', 'APIKEY', 'SECRET',
            'TOKEN', 'ACCESS_KEY', 'SECRET_KEY', 'PRIVATE_KEY',
            'DATABASE_URL', 'DB_PASSWORD', 'AWS_SECRET'
        ]

        for key, value in os.environ.items():
            for sensitive in sensitive_keys:
                if sensitive in key.upper():
                    # Mask the value
                    masked_value = value[:3] + '*' * (len(value) - 3) if len(value) > 3 else '***'

                    findings.append({
                        "severity": "medium",
                        "finding": f"Sensitive environment variable: {key}",
                        "description": f"Value: {masked_value}",
                        "remediation": "Ensure environment variables are not logged or exposed"
                    })

    except Exception:
        pass

    return findings

def check_ssh_keys():
    """Check for SSH private keys"""
    findings = []

    try:
        ssh_dir = os.path.expanduser('~/.ssh')

        if os.path.exists(ssh_dir):
            for file in os.listdir(ssh_dir):
                filepath = os.path.join(ssh_dir, file)

                if os.path.isfile(filepath):
                    # Check for private keys
                    if not file.endswith('.pub'):
                        try:
                            with open(filepath, 'r') as f:
                                first_line = f.readline()

                                if 'PRIVATE KEY' in first_line:
                                    # Check permissions
                                    stat_info = os.stat(filepath)
                                    if stat_info.st_mode & 0o077:  # Readable by group or others
                                        findings.append({
                                            "severity": "high",
                                            "finding": f"SSH private key with insecure permissions: {filepath}",
                                            "description": "Private key is readable by others",
                                            "remediation": f"Fix permissions: chmod 600 {filepath}"
                                        })
                                    else:
                                        findings.append({
                                            "severity": "info",
                                            "finding": f"SSH private key found: {filepath}",
                                            "description": "Private key is properly secured",
                                            "remediation": "Ensure key is not shared or exposed"
                                        })

                        except Exception:
                            pass

    except Exception:
        pass

    return findings

def check_browser_data():
    """Check for browser credential storage"""
    findings = []

    try:
        browser_paths = [
            '~/.mozilla/firefox',
            '~/.config/google-chrome',
            '~/.config/chromium'
        ]

        for browser_path in browser_paths:
            expanded_path = os.path.expanduser(browser_path)

            if os.path.exists(expanded_path):
                findings.append({
                    "severity": "info",
                    "finding": f"Browser data directory found: {expanded_path}",
                    "description": "Browser may store saved passwords and credentials",
                    "remediation": "Use browser password manager with master password"
                })

    except Exception:
        pass

    return findings

def check_password_files():
    """Check for common password file locations"""
    findings = []

    try:
        # Check /etc/passwd and /etc/shadow readability
        if os.path.exists('/etc/shadow'):
            if os.access('/etc/shadow', os.R_OK):
                findings.append({
                    "severity": "critical",
                    "finding": "/etc/shadow is readable",
                    "description": "Shadow password file is readable by current user",
                    "remediation": "Fix permissions: chmod 640 /etc/shadow"
                })

        # Check for password backup files
        password_backups = [
            '/etc/passwd-',
            '/etc/shadow-',
            '/etc/group-',
            '/etc/gshadow-'
        ]

        for backup in password_backups:
            if os.path.exists(backup) and os.access(backup, os.R_OK):
                findings.append({
                    "severity": "high",
                    "finding": f"Password backup file readable: {backup}",
                    "description": "Backup password file is accessible",
                    "remediation": f"Fix permissions: chmod 640 {backup}"
                })

    except Exception:
        pass

    return findings

def check_database_configs():
    """Check database configuration files"""
    findings = []

    try:
        db_configs = [
            '/etc/mysql/my.cnf',
            '/etc/postgresql/*/main/postgresql.conf',
            '~/.my.cnf',
            '~/.pgpass'
        ]

        for pattern in db_configs:
            for filepath in glob.glob(os.path.expanduser(pattern)):
                if os.path.isfile(filepath):
                    # Check if readable
                    if os.access(filepath, os.R_OK):
                        findings.append({
                            "severity": "medium",
                            "finding": f"Database config file found: {filepath}",
                            "description": "File may contain database credentials",
                            "remediation": "Ensure file permissions are restrictive"
                        })

                        # Check permissions
                        stat_info = os.stat(filepath)
                        if stat_info.st_mode & 0o044:
                            findings.append({
                                "severity": "high",
                                "finding": f"Database config readable by others: {filepath}",
                                "description": "Configuration file is world-readable",
                                "remediation": f"Fix permissions: chmod 600 {filepath}"
                            })

    except Exception:
        pass

    return findings

if __name__ == '__main__':
    # Test module
    import json
    results = check()
    print(json.dumps(results, indent=2))
