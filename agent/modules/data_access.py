"""
Data Access Assessment Module
Checks for accessible sensitive data and files
"""

import os
import platform
import subprocess
import glob

def check():
    """
    Check for accessible sensitive data
    """
    results = {
        "module": "data_access",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # Check for sensitive files
        sensitive_findings = check_sensitive_files()
        if sensitive_findings:
            results["findings"].extend(sensitive_findings)

        # Check database files
        db_findings = check_database_files()
        if db_findings:
            results["findings"].extend(db_findings)

        # Check backup files
        backup_findings = check_backup_files()
        if backup_findings:
            results["findings"].extend(backup_findings)

        # Check world-readable files
        readable_findings = check_world_readable()
        if readable_findings:
            results["findings"].extend(readable_findings)

        # Check home directories
        home_findings = check_home_directories()
        if home_findings:
            results["findings"].extend(home_findings)

    except Exception as e:
        results["error"] = str(e)

    return results

def check_sensitive_files():
    """Check for sensitive files"""
    findings = []

    try:
        sensitive_patterns = [
            '*.pem', '*.key', '*.p12', '*.pfx', '*.crt',
            '*.sql', '*.db', '*.sqlite', '*.mdb',
            '*password*', '*credential*', '*secret*',
            '*.env', '.env.*', 'config.json', 'settings.json'
        ]

        search_dirs = [
            os.path.expanduser('~'),
            '/opt',
            '/var/www',
            '/srv'
        ]

        found_files = []

        for search_dir in search_dirs:
            if not os.path.exists(search_dir):
                continue

            for pattern in sensitive_patterns:
                try:
                    for filepath in glob.glob(os.path.join(search_dir, '**', pattern), recursive=True):
                        if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                            found_files.append(filepath)

                            if len(found_files) >= 20:
                                break
                except Exception:
                    continue

                if len(found_files) >= 20:
                    break

            if len(found_files) >= 20:
                break

        if found_files:
            findings.append({
                "severity": "high",
                "finding": f"Sensitive files accessible: {len(found_files)}",
                "description": f"Files: {', '.join(found_files[:10])}",
                "remediation": "Secure sensitive files with appropriate permissions"
            })

    except Exception:
        pass

    return findings

def check_database_files():
    """Check for accessible database files"""
    findings = []

    try:
        db_locations = [
            '/var/lib/mysql',
            '/var/lib/postgresql',
            '/var/lib/mongodb',
            '/var/lib/redis'
        ]

        for db_loc in db_locations:
            if os.path.exists(db_loc) and os.access(db_loc, os.R_OK):
                findings.append({
                    "severity": "high",
                    "finding": f"Database directory accessible: {db_loc}",
                    "description": "Database files may be readable",
                    "remediation": f"Restrict access to {db_loc}"
                })

        # Look for SQLite databases
        sqlite_patterns = ['*.db', '*.sqlite', '*.sqlite3']

        for pattern in sqlite_patterns:
            try:
                for filepath in glob.glob(os.path.join(os.path.expanduser('~'), '**', pattern), recursive=True):
                    if os.path.isfile(filepath):
                        findings.append({
                            "severity": "medium",
                            "finding": f"SQLite database found: {filepath}",
                            "description": "Database file may contain sensitive data",
                            "remediation": "Ensure database is properly secured"
                        })

                        if len([f for f in findings if 'SQLite' in f['finding']]) >= 5:
                            break
            except Exception:
                continue

    except Exception:
        pass

    return findings

def check_backup_files():
    """Check for backup files"""
    findings = []

    try:
        backup_patterns = [
            '*.bak', '*.backup', '*.old', '*.save',
            '*.tar', '*.tar.gz', '*.tgz', '*.zip',
            '*.7z', '*.rar', 'backup*', '*backup*'
        ]

        search_dirs = [
            os.path.expanduser('~'),
            '/tmp',
            '/var/tmp',
            '/backup',
            '/var/backup'
        ]

        backup_files = []

        for search_dir in search_dirs:
            if not os.path.exists(search_dir):
                continue

            for pattern in backup_patterns:
                try:
                    for filepath in glob.glob(os.path.join(search_dir, pattern)):
                        if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                            backup_files.append(filepath)

                            if len(backup_files) >= 10:
                                break
                except Exception:
                    continue

                if len(backup_files) >= 10:
                    break

            if len(backup_files) >= 10:
                break

        if backup_files:
            findings.append({
                "severity": "medium",
                "finding": f"Backup files found: {len(backup_files)}",
                "description": f"Files: {', '.join(backup_files[:5])}",
                "remediation": "Backup files may contain sensitive data"
            })

    except Exception:
        pass

    return findings

def check_world_readable():
    """Check for world-readable sensitive files"""
    findings = []

    try:
        sensitive_dirs = [
            '/etc',
            '/var/www',
            '/opt'
        ]

        for sensitive_dir in sensitive_dirs:
            if not os.path.exists(sensitive_dir):
                continue

            try:
                result = subprocess.run(
                    ['find', sensitive_dir, '-type', 'f', '-perm', '-004', '2>/dev/null'],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=False
                )

                world_readable = result.stdout.strip().split('\n')
                world_readable = [f for f in world_readable if f][:10]

                if world_readable:
                    findings.append({
                        "severity": "medium",
                        "finding": f"World-readable files in {sensitive_dir}",
                        "description": f"Files: {', '.join(world_readable[:5])}",
                        "remediation": "Review and restrict permissions on sensitive files"
                    })

            except Exception:
                continue

    except Exception:
        pass

    return findings

def check_home_directories():
    """Check home directory access"""
    findings = []

    try:
        home_dir = os.path.expanduser('~')

        # Check for interesting subdirectories
        interesting_dirs = [
            'Documents', 'Downloads', 'Desktop',
            '.ssh', '.aws', '.docker', '.kube',
            'projects', 'code', 'workspace'
        ]

        for dir_name in interesting_dirs:
            dir_path = os.path.join(home_dir, dir_name)

            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                try:
                    file_count = len(os.listdir(dir_path))

                    findings.append({
                        "severity": "info",
                        "finding": f"Directory accessible: {dir_path}",
                        "description": f"Contains {file_count} items",
                        "remediation": "Review directory contents for sensitive data"
                    })
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
