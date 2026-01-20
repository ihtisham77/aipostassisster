"""
Exfiltration Assessment Module - PRODUCTION ENHANCED
Comprehensive assessment of data exfiltration opportunities including:
- Accessible sensitive data
- Network exfiltration channels
- External storage devices
- Cloud storage tools and credentials
- Network connectivity and protocols
"""

import os
import platform
import subprocess
import psutil
import glob
import stat
import socket
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
    Comprehensive exfiltration assessment with OS-specific checks
    """
    results = {
        "module": "exfiltration",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # 1. Check accessible sensitive data
        sensitive_findings = check_sensitive_data()
        if sensitive_findings:
            results["findings"].extend(sensitive_findings)

        # 2. Check network exfiltration channels
        network_findings = check_network_exfiltration()
        if network_findings:
            results["findings"].extend(network_findings)

        # 3. Check external storage devices
        storage_findings = check_external_storage()
        if storage_findings:
            results["findings"].extend(storage_findings)

        # 4. Check cloud storage tools and credentials
        cloud_findings = check_cloud_storage()
        if cloud_findings:
            results["findings"].extend(cloud_findings)

        # 5. Check data transfer tools
        transfer_findings = check_transfer_tools()
        if transfer_findings:
            results["findings"].extend(transfer_findings)

        # 6. Check database files
        db_findings = check_database_files()
        if db_findings:
            results["findings"].extend(db_findings)

        # 7. Check browser data
        browser_findings = check_browser_data()
        if browser_findings:
            results["findings"].extend(browser_findings)

    except Exception as e:
        results["error"] = str(e)

    return results


def check_sensitive_data():
    """Check for accessible sensitive files and credentials"""
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

        for category, patterns in sensitive_patterns.items():
            found_by_category[category] = []

            for search_dir in search_dirs:
                if not os.path.exists(search_dir):
                    continue

                for pattern in patterns:
                    try:
                        files = glob.glob(os.path.join(search_dir, '**', pattern), recursive=True)

                        for filepath in files[:10]:
                            if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                                try:
                                    file_size = os.path.getsize(filepath)
                                    found_by_category[category].append((filepath, file_size))

                                    if len(found_by_category[category]) >= 10:
                                        break
                                except:
                                    pass
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
                    f"Sensitive {category} files accessible for exfiltration: {len(files)}",
                    f"Found {len(files)} {category} files totaling {total_size} bytes that could be exfiltrated. "
                    f"Sample files: {', '.join(file_list)}. "
                    f"These files may contain credentials or sensitive data.",
                    f"Secure {category} files with chmod 600 or move to encrypted storage; implement DLP",
                    100,
                    True
                ))

    except Exception:
        pass

    return findings


def check_network_exfiltration():
    """Check network exfiltration channels and connectivity"""
    findings = []

    try:
        # Test standard HTTP/HTTPS egress
        common_ports = [
            (80, 'HTTP', 'Standard web traffic'),
            (443, 'HTTPS', 'Encrypted web traffic'),
            (8080, 'HTTP-Alt', 'Alternative HTTP port'),
            (8443, 'HTTPS-Alt', 'Alternative HTTPS port')
        ]

        open_ports = []
        port_tests = []

        for port, protocol, description in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('8.8.8.8', port))
                sock.close()

                if result == 0:
                    open_ports.append(f"{protocol} (port {port})")
                    port_tests.append(True)
                else:
                    port_tests.append(False)
            except Exception:
                port_tests.append(False)

        if open_ports:
            confidence = common_utils.calculate_confidence_score(*port_tests)
            findings.append(create_finding(
                "high",
                f"Network exfiltration channels available: {len(open_ports)}",
                f"Outbound connectivity available on: {', '.join(open_ports)}. "
                f"These ports can be used for data exfiltration via HTTP/HTTPS. "
                f"Data can be uploaded to attacker-controlled servers or cloud services.",
                "Implement DPI (Deep Packet Inspection) and egress filtering; monitor outbound data transfers",
                confidence,
                True
            ))

        # Test DNS for DNS tunneling
        try:
            test_domain = 'google.com'
            resolved_ip = socket.gethostbyname(test_domain)

            findings.append(create_finding(
                "high",
                "DNS resolution available - DNS tunneling possible",
                f"System can resolve external domains (test: {test_domain} -> {resolved_ip}). "
                f"DNS queries can be used for data exfiltration via DNS tunneling. "
                f"Data is encoded in DNS queries and responses, bypassing many firewalls.",
                "Monitor DNS queries for unusually long hostnames or high query volume to single domains",
                100,
                True
            ))
        except Exception:
            pass

        # Test ICMP egress
        try:
            if common_utils.is_linux() or common_utils.is_macos():
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', '8.8.8.8'],
                    capture_output=True,
                    timeout=5
                )
            elif common_utils.is_windows():
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '2000', '8.8.8.8'],
                    capture_output=True,
                    timeout=5
                )

            if result.returncode == 0:
                findings.append(create_finding(
                    "medium",
                    "ICMP egress available for data exfiltration",
                    "System can send ICMP packets to external hosts. ICMP can be used "
                    "for covert data exfiltration by encoding data in ICMP echo requests.",
                    "Block or monitor ICMP traffic to external networks",
                    100,
                    True
                ))
        except Exception:
            pass

        # Check active outbound connections
        try:
            outbound_connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    outbound_connections.append({
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "local_port": conn.laddr.port
                    })

            if outbound_connections:
                findings.append(create_finding(
                    "medium",
                    f"Active outbound connections detected: {len(outbound_connections)}",
                    f"System has {len(outbound_connections)} active external connections. "
                    f"Top connections: {', '.join([c['remote'] for c in outbound_connections[:5]])}. "
                    f"These channels can be leveraged for data exfiltration.",
                    "Monitor outbound connections for unusual data transfer patterns",
                    95,
                    True
                ))
        except Exception:
            pass

    except Exception:
        pass

    return findings


def check_external_storage():
    """Check for external storage devices"""
    findings = []

    try:
        if common_utils.is_linux() or common_utils.is_macos():
            usb_mounts = []

            # Check mount command
            try:
                result = subprocess.run(
                    ['mount'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if any(indicator in line.lower() for indicator in ['usb', '/media/', '/mnt/', 'external']):
                            usb_mounts.append(line.strip())
            except Exception:
                pass

            # Check /media directory
            try:
                if os.path.exists('/media'):
                    for item in os.listdir('/media'):
                        item_path = os.path.join('/media', item)
                        if os.path.ismount(item_path):
                            usb_mounts.append(item_path)
            except Exception:
                pass

            # Check /mnt directory
            try:
                if os.path.exists('/mnt'):
                    mnt_contents = os.listdir('/mnt')
                    if mnt_contents:
                        for item in mnt_contents[:5]:
                            usb_mounts.append(f"/mnt/{item}")
            except Exception:
                pass

            if usb_mounts:
                usb_mounts = list(set(usb_mounts))
                findings.append(create_finding(
                    "high",
                    f"External storage devices for physical exfiltration: {len(usb_mounts)}",
                    f"External storage provides physical data exfiltration path. "
                    f"Mounted devices: {', '.join(usb_mounts[:5])}. "
                    f"Data can be copied to these devices without network detection.",
                    "Monitor file access to external storage; implement DLP for USB devices",
                    100,
                    True
                ))

        elif common_utils.is_windows():
            removable_drives = []

            # Use wmic to list removable drives
            try:
                result = subprocess.run(
                    ['wmic', 'logicaldisk', 'where', 'drivetype=2', 'get', 'deviceid,volumename'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')[1:]
                    for line in lines:
                        if line.strip():
                            removable_drives.append(line.strip())
            except Exception:
                pass

            if removable_drives:
                findings.append(create_finding(
                    "high",
                    f"Removable storage detected for physical exfiltration: {len(removable_drives)}",
                    f"Windows removable drives found: {', '.join(removable_drives)}. "
                    f"These provide physical exfiltration channels.",
                    "Disable USB storage via Group Policy; implement endpoint DLP",
                    95,
                    True
                ))

    except Exception:
        pass

    return findings


def check_cloud_storage():
    """Check for cloud storage tools and credentials"""
    findings = []

    try:
        # Check for cloud CLI tools
        cloud_tools = [
            ('aws', 'AWS CLI'),
            ('gcloud', 'Google Cloud SDK'),
            ('az', 'Azure CLI'),
            ('rclone', 'Rclone'),
            ('s3cmd', 'S3cmd'),
            ('gsutil', 'gsutil'),
            ('dropbox', 'Dropbox CLI'),
            ('gdrive', 'Google Drive CLI')
        ]

        detected_tools = []
        tool_paths = []

        for tool, name in cloud_tools:
            exists, confidence, path = common_utils.verify_command_exists(tool)
            if exists:
                detected_tools.append(name)
                if path:
                    tool_paths.append(f"{name}: {path}")

        if detected_tools:
            findings.append(create_finding(
                "high",
                f"Cloud storage exfiltration tools detected: {len(detected_tools)}",
                f"Cloud CLI tools available for exfiltration: {', '.join(detected_tools)}. "
                f"These tools can exfiltrate large volumes of data to cloud storage. "
                f"Locations: {'; '.join(tool_paths[:5])}",
                "Monitor cloud tool usage; block cloud storage domains if not needed",
                90,
                True
            ))

        # Check for cloud credentials
        cloud_cred_locations = {
            '~/.aws/credentials': 'AWS credentials',
            '~/.aws/config': 'AWS configuration',
            '~/.config/gcloud': 'Google Cloud credentials',
            '~/.azure': 'Azure credentials',
            '~/.s3cfg': 'S3cmd configuration',
            '~/.rclone.conf': 'Rclone configuration',
            '~/.kube/config': 'Kubernetes',
            '~/.docker/config.json': 'Docker'
        }

        found_credentials = []
        for cred_file, description in cloud_cred_locations.items():
            expanded = os.path.expanduser(cred_file)
            if os.path.exists(expanded) and os.access(expanded, os.R_OK):
                found_credentials.append(f"{description} ({expanded})")

        if found_credentials:
            findings.append(create_finding(
                "critical",
                f"Cloud credentials accessible for exfiltration: {len(found_credentials)}",
                f"Cloud provider credentials found: {', '.join(found_credentials)}. "
                f"These credentials enable direct data exfiltration to cloud storage "
                f"services. Attackers can upload data without detection.",
                "Rotate cloud credentials; implement MFA; monitor cloud API usage",
                100,
                True
            ))

    except Exception:
        pass

    return findings


def check_transfer_tools():
    """Check for data transfer tools"""
    findings = []

    try:
        tool_categories = {
            'Network Transfer': [
                ('curl', 'curl'),
                ('wget', 'wget'),
                ('nc', 'netcat'),
                ('ncat', 'ncat'),
                ('socat', 'socat'),
                ('telnet', 'telnet')
            ],
            'Secure Transfer': [
                ('scp', 'scp'),
                ('sftp', 'sftp'),
                ('rsync', 'rsync'),
                ('ssh', 'ssh')
            ],
            'Programming Languages': [
                ('python', 'Python'),
                ('python3', 'Python3'),
                ('perl', 'Perl'),
                ('ruby', 'Ruby'),
                ('node', 'Node.js'),
                ('php', 'PHP')
            ],
            'Legacy Protocols': [
                ('ftp', 'FTP'),
                ('tftp', 'TFTP')
            ]
        }

        detected_by_category = {}
        total_tools = 0

        for category, tools in tool_categories.items():
            category_tools = []
            for tool, name in tools:
                exists, confidence, path = common_utils.verify_command_exists(tool)
                if exists:
                    category_tools.append(name)
                    total_tools += 1

            if category_tools:
                detected_by_category[category] = category_tools

        if detected_by_category:
            category_summary = []
            for category, tools in detected_by_category.items():
                category_summary.append(f"{category}: {', '.join(tools)}")

            findings.append(create_finding(
                "medium",
                f"Data exfiltration tools available: {total_tools} tools across {len(detected_by_category)} categories",
                f"Multiple data exfiltration tools detected:\n" + "\n".join(category_summary) +
                f"\n\nThese tools can transfer data via network protocols. "
                f"Scripting languages can implement custom exfiltration methods.",
                "Monitor outbound connections from these tools; implement application whitelisting",
                85,
                True
            ))

        # Check for encoding tools (used to obfuscate exfiltrated data)
        encoding_tools = [
            ('base64', 'base64'),
            ('openssl', 'OpenSSL'),
            ('gpg', 'GPG')
        ]

        detected_encoders = []
        for tool, name in encoding_tools:
            exists, confidence, path = common_utils.verify_command_exists(tool)
            if exists:
                detected_encoders.append(name)

        if detected_encoders:
            findings.append(create_finding(
                "info",
                f"Data encoding tools for obfuscation: {', '.join(detected_encoders)}",
                f"Encoding tools can obfuscate exfiltrated data to bypass DLP. "
                f"Tools: {', '.join(detected_encoders)}",
                "Monitor use of encoding tools in data exfiltration contexts",
                90,
                True
            ))

    except Exception:
        pass

    return findings


def check_database_files():
    """Check for accessible database files"""
    findings = []

    try:
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
                        severity = "critical" if is_writable else "high"
                        access = "readable and writable" if is_writable else "readable"

                        findings.append(create_finding(
                            severity,
                            f"{db_name} database accessible for exfiltration: {db_loc}",
                            f"Database directory is {access} by current user. "
                            f"Direct access to database files enables data extraction and exfiltration.",
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
                                if size > 1024:
                                    sqlite_found.append((filepath, size))

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
                f"SQLite databases accessible for exfiltration: {len(sqlite_found)}",
                f"Found {len(sqlite_found)} SQLite databases totaling {total_size/1024:.1f}KB. "
                f"Databases: {', '.join(file_list)}. "
                f"SQLite databases often contain application data and credentials that can be exfiltrated.",
                "Review database contents and secure with encryption; monitor database file access",
                100,
                True
            ))

    except Exception:
        pass

    return findings


def check_browser_data():
    """Check for accessible browser data"""
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
                f"Browser data accessible for exfiltration: {len(found_browsers)} browsers",
                f"Found accessible browser data for: {', '.join(browser_list)}. "
                f"Browser databases contain cookies, saved passwords, and history that can be exfiltrated. "
                f"These can be extracted using browser decryption tools.",
                "Secure browser data; implement endpoint DLP; monitor browser data file access",
                95,
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
