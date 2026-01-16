"""
Data Access Assessment Module - PRODUCTION ENHANCED
Checks for accessible sensitive data and files with confidence scoring
"""

import os
import platform
import subprocess
import glob
import stat

# Import common utilities for OS detection and confidence scoring
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
    Check for accessible sensitive data with OS-specific enhanced checks
    """
    results = {
        "module": "data_access",
        "platform": platform.system(),
        "os_type": common_utils.get_os_type(),
        "findings": []
    }

    try:
        # Sensitive files (All OS)
        sensitive_findings = check_sensitive_files_enhanced()
        results["findings"].extend(sensitive_findings)

        # Database files (All OS)
        db_findings = check_database_files_enhanced()
        results["findings"].extend(db_findings)

        # Backup files (All OS)
        backup_findings = check_backup_files_enhanced()
        results["findings"].extend(backup_findings)

        # World-readable files (Linux/macOS)
        if not common_utils.is_windows():
            readable_findings = check_world_readable_enhanced()
            results["findings"].extend(readable_findings)

        # Home directories (All OS)
        home_findings = check_home_directories_enhanced()
        results["findings"].extend(home_findings)

        # Browser data (All OS)
        browser_findings = check_browser_data()
        results["findings"].extend(browser_findings)

        # Cloud credentials (All OS)
        cloud_findings = check_cloud_credentials()
        results["findings"].extend(cloud_findings)

    except Exception as e:
        results["error"] = str(e)

    return results


def check_sensitive_files_enhanced():
    """Enhanced sensitive file detection with multi-method verification"""
    findings = []

    try:
        sensitive_patterns = {
            'certificates': ['*.pem', '*.key', '*.p12', '*.pfx', '*.crt', '*.cer'],
            'databases': ['*.sql', '*.db', '*.sqlite', '*.sqlite3', '*.mdb'],
            'credentials': ['*password*', '*credential*', '*secret*', '*.pgpass'],
            'configs': ['*.env', '.env.*', 'config.json', 'settings.json', 'app.config'],
            'keys': ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', '*.ppk']
        }

        if common_utils.is_windows():
            search_dirs = [
                os.path.expanduser('~'),
                'C:\\inetpub',
                'C:\\xampp',
                'C:\\wamp'
            ]
        else:
            search_dirs = [
                os.path.expanduser('~'),
                '/opt',
                '/var/www',
                '/srv',
                '/home'
            ]

        found_by_category = {}
        methods_used = ['filesystem_scan']

        for category, patterns in sensitive_patterns.items():
            found_by_category[category] = []

            for search_dir in search_dirs:
                if not os.path.exists(search_dir):
                    continue

                for pattern in patterns:
                    try:
                        # Method 1: glob search
                        files = glob.glob(os.path.join(search_dir, '**', pattern), recursive=True)

                        for filepath in files[:10]:  # Limit per pattern
                            if os.path.isfile(filepath):
                                # Method 2: Verify readability
                                is_readable = os.access(filepath, os.R_OK)

                                # Method 3: Verify file actually exists and get size
                                try:
                                    file_stat = os.stat(filepath)
                                    file_size = file_stat.st_size
                                    exists = True
                                except:
                                    exists = False
                                    file_size = 0

                                if is_readable and exists:
                                    found_by_category[category].append((filepath, file_size))

                                    if len(found_by_category[category]) >= 10:
                                        break
                    except Exception:
                        continue

                    if len(found_by_category[category]) >= 10:
                        break

                if len(found_by_category[category]) >= 10:
                    break

        # Create findings by category
        for category, files in found_by_category.items():
            if files:
                total_size = sum(size for _, size in files)
                file_list = [f for f, _ in files[:5]]

                severity_map = {
                    'certificates': 'high',
                    'databases': 'high',
                    'credentials': 'critical',
                    'configs': 'high',
                    'keys': 'critical'
                }

                findings.append(create_finding(
                    severity_map.get(category, 'medium'),
                    f"Sensitive {category} files accessible: {len(files)}",
                    f"Found {len(files)} {category} files totaling {total_size} bytes. "
                    f"Sample files: {', '.join(file_list)}. "
                    f"These files may contain credentials or sensitive data.",
                    f"Secure {category} files with chmod 600 or move to encrypted storage",
                    100,
                    True
                ))

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

    except Exception:
        pass

    return findings


def check_database_files_enhanced():
    """Enhanced database file detection with OS-specific checks"""
    findings = []

    try:
        methods_used = []

        if common_utils.is_linux():
            db_locations = {
                '/var/lib/mysql': 'MySQL',
                '/var/lib/postgresql': 'PostgreSQL',
                '/var/lib/mongodb': 'MongoDB',
                '/var/lib/redis': 'Redis',
                '/var/lib/influxdb': 'InfluxDB'
            }

            for db_loc, db_name in db_locations.items():
                if os.path.exists(db_loc):
                    is_readable = os.access(db_loc, os.R_OK)
                    is_writable = os.access(db_loc, os.W_OK)

                    if is_readable or is_writable:
                        methods_used.append(f'{db_name}_location')

                        severity = "critical" if is_writable else "high"
                        access = "readable and writable" if is_writable else "readable"

                        findings.append(create_finding(
                            severity,
                            f"{db_name} database directory {access}: {db_loc}",
                            f"Database directory is {access} by current user. "
                            f"Direct access to database files enables data extraction.",
                            f"Restrict permissions on {db_loc}",
                            100,
                            True
                        ))

        # SQLite databases (All OS)
        sqlite_patterns = ['*.db', '*.sqlite', '*.sqlite3']
        sqlite_found = []

        search_paths = [os.path.expanduser('~')]
        if common_utils.is_windows():
            search_paths.extend(['C:\\Users', 'C:\\ProgramData'])
        else:
            search_paths.extend(['/var', '/opt'])

        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue

            for pattern in sqlite_patterns:
                try:
                    files = glob.glob(os.path.join(search_path, '**', pattern), recursive=True)
                    for filepath in files[:5]:
                        if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                            try:
                                size = os.path.getsize(filepath)
                                if size > 1024:  # Only report non-empty databases
                                    sqlite_found.append((filepath, size))
                                    methods_used.append('sqlite_scan')

                                    if len(sqlite_found) >= 5:
                                        break
                            except:
                                pass
                except Exception:
                    continue

                if len(sqlite_found) >= 5:
                    break

            if len(sqlite_found) >= 5:
                break

        if sqlite_found:
            total_size = sum(size for _, size in sqlite_found)
            file_list = [f for f, _ in sqlite_found]

            findings.append(create_finding(
                "high",
                f"SQLite databases accessible: {len(sqlite_found)}",
                f"Found {len(sqlite_found)} SQLite databases totaling {total_size/1024:.1f}KB. "
                f"Databases: {', '.join(file_list)}. "
                f"SQLite databases often contain application data and credentials.",
                "Review database contents and secure with encryption",
                100,
                True
            ))

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

    except Exception:
        pass

    return findings


def check_backup_files_enhanced():
    """Enhanced backup file detection"""
    findings = []

    try:
        backup_patterns = [
            '*.bak', '*.backup', '*.old', '*.orig',
            '*.tar', '*.tar.gz', '*.tgz', '*.zip',
            '*.7z', '*.rar', '*~', '*.swp'
        ]

        search_dirs = [os.path.expanduser('~')]
        if common_utils.is_windows():
            search_dirs.extend(['C:\\backup', 'C:\\Users\\Public'])
        else:
            search_dirs.extend(['/var/backups', '/backup', '/opt'])

        found_backups = []
        methods_used = ['filesystem_scan']

        for search_dir in search_dirs:
            if not os.path.exists(search_dir):
                continue

            for pattern in backup_patterns:
                try:
                    files = glob.glob(os.path.join(search_dir, '**', pattern), recursive=True)

                    for filepath in files[:10]:
                        if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                            try:
                                size = os.path.getsize(filepath)
                                found_backups.append((filepath, size))

                                if len(found_backups) >= 20:
                                    break
                            except:
                                pass
                except Exception:
                    continue

                if len(found_backups) >= 20:
                    break

            if len(found_backups) >= 20:
                break

        if found_backups:
            total_size = sum(size for _, size in found_backups)
            file_list = [f for f, _ in found_backups[:5]]

            findings.append(create_finding(
                "medium",
                f"Backup files accessible: {len(found_backups)}",
                f"Found {len(found_backups)} backup files totaling {total_size/1024/1024:.1f}MB. "
                f"Sample files: {', '.join(file_list)}. "
                f"Backup files may contain older versions of sensitive data.",
                "Review and secure backup files",
                100,
                True
            ))

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

    except Exception:
        pass

    return findings


def check_world_readable_enhanced():
    """Enhanced world-readable file detection (Unix)"""
    findings = []

    if common_utils.is_windows():
        return findings

    try:
        # Check for world-readable files in sensitive locations
        sensitive_dirs = [
            os.path.expanduser('~/.ssh'),
            os.path.expanduser('~/.gnupg'),
            '/etc/shadow',
            '/etc/sudoers'
        ]

        world_readable = []
        methods_used = []

        for location in sensitive_dirs:
            if not os.path.exists(location):
                continue

            try:
                file_stat = os.stat(location)
                mode = file_stat.st_mode

                # Check if world-readable (others can read)
                if mode & stat.S_IROTH:
                    world_readable.append(location)
                    methods_used.append('stat')

                    severity = "critical" if location in ['/etc/shadow', '/etc/sudoers'] else "high"

                    findings.append(create_finding(
                        severity,
                        f"World-readable sensitive file: {location}",
                        f"File {location} is readable by all users (mode: {oct(mode)}). "
                        f"This allows unauthorized access to sensitive data.",
                        f"Fix permissions: chmod 600 {location}",
                        100,
                        True
                    ))
            except Exception:
                pass

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

    except Exception:
        pass

    return findings


def check_home_directories_enhanced():
    """Enhanced home directory enumeration"""
    findings = []

    try:
        methods_used = []

        if common_utils.is_windows():
            users_dir = 'C:\\Users'
            if os.path.exists(users_dir):
                try:
                    user_dirs = [d for d in os.listdir(users_dir)
                                if os.path.isdir(os.path.join(users_dir, d))]
                    methods_used.append('windows_users')

                    findings.append(create_finding(
                        "info",
                        f"User home directories enumerated: {len(user_dirs)}",
                        f"Found {len(user_dirs)} user directories: {', '.join(user_dirs[:10])}. "
                        f"Home directories may contain user data and credentials.",
                        "Review user directories for sensitive data",
                        100,
                        True
                    ))
                except Exception:
                    pass
        else:
            home_dir = '/home'
            if os.path.exists(home_dir):
                try:
                    user_dirs = [d for d in os.listdir(home_dir)
                                if os.path.isdir(os.path.join(home_dir, d))]
                    methods_used.append('linux_users')

                    findings.append(create_finding(
                        "info",
                        f"User home directories enumerated: {len(user_dirs)}",
                        f"Found {len(user_dirs)} user directories: {', '.join(user_dirs[:10])}. "
                        f"Home directories may contain user data and credentials.",
                        "Review user directories for sensitive data",
                        100,
                        True
                    ))
                except Exception:
                    pass

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

    except Exception:
        pass

    return findings


def check_browser_data():
    """Check for accessible browser data (cookies, passwords, history)"""
    findings = []

    try:
        browser_paths = []

        if common_utils.is_windows():
            appdata = os.environ.get('APPDATA', '')
            localappdata = os.environ.get('LOCALAPPDATA', '')

            browser_paths = [
                (os.path.join(localappdata, 'Google\\Chrome\\User Data'), 'Chrome'),
                (os.path.join(localappdata, 'Microsoft\\Edge\\User Data'), 'Edge'),
                (os.path.join(appdata, 'Mozilla\\Firefox\\Profiles'), 'Firefox'),
            ]
        else:
            home = os.path.expanduser('~')
            browser_paths = [
                (os.path.join(home, '.config/google-chrome'), 'Chrome'),
                (os.path.join(home, '.mozilla/firefox'), 'Firefox'),
                (os.path.join(home, 'Library/Application Support/Google/Chrome'), 'Chrome'),
                (os.path.join(home, 'Library/Application Support/Firefox'), 'Firefox'),
            ]

        found_browsers = []

        for path, browser_name in browser_paths:
            if os.path.exists(path):
                # Check for cookies and login data
                sensitive_files = ['Cookies', 'Login Data', 'Web Data', 'History']
                found_files = []

                try:
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            if file in sensitive_files:
                                filepath = os.path.join(root, file)
                                if os.access(filepath, os.R_OK):
                                    found_files.append(file)

                        if len(found_files) >= 5:
                            break
                except:
                    pass

                if found_files:
                    found_browsers.append((browser_name, len(found_files)))

        if found_browsers:
            browser_list = [f"{name} ({count} files)" for name, count in found_browsers]

            findings.append(create_finding(
                "high",
                f"Browser data accessible: {len(found_browsers)} browsers",
                f"Found accessible browser data for: {', '.join(browser_list)}. "
                f"Browser databases contain cookies, saved passwords, and history. "
                f"These can be extracted using browser decryption tools.",
                "Browser data can reveal credentials and browsing history",
                95,
                True
            ))

    except Exception:
        pass

    return findings


def check_cloud_credentials():
    """Check for cloud provider credential files"""
    findings = []

    try:
        cloud_creds = {
            '~/.aws/credentials': 'AWS',
            '~/.azure': 'Azure',
            '~/.config/gcloud': 'GCP',
            '~/.kube/config': 'Kubernetes',
            '~/.docker/config.json': 'Docker'
        }

        found_creds = []

        for cred_path, provider in cloud_creds.items():
            expanded_path = os.path.expanduser(cred_path)
            if os.path.exists(expanded_path):
                is_readable = os.access(expanded_path, os.R_OK)

                if is_readable:
                    try:
                        if os.path.isfile(expanded_path):
                            size = os.path.getsize(expanded_path)
                        else:
                            size = sum(os.path.getsize(os.path.join(dirpath, filename))
                                      for dirpath, dirnames, filenames in os.walk(expanded_path)
                                      for filename in filenames)

                        found_creds.append((provider, expanded_path, size))
                    except:
                        found_creds.append((provider, expanded_path, 0))

        if found_creds:
            cred_list = [f"{provider} ({path})" for provider, path, _ in found_creds]

            findings.append(create_finding(
                "critical",
                f"Cloud credentials accessible: {len(found_creds)} providers",
                f"Found credential files for: {', '.join(cred_list)}. "
                f"These provide access to cloud resources and infrastructure.",
                "Secure cloud credentials or use instance profiles/managed identities",
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
