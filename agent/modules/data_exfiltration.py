"""
Data Exfiltration Assessment Module - PRODUCTION ENHANCED
Checks for data exfiltration channels and opportunities with OS-specific detection
"""

import os
import platform
import subprocess
import psutil
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
    Check for data exfiltration opportunities with OS-specific multi-method verification
    """
    results = {
        "module": "data_exfiltration",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # Check network egress with multi-protocol verification
        egress_findings = check_network_egress_enhanced()
        if egress_findings:
            results["findings"].extend(egress_findings)

        # Check external storage with OS-specific detection
        storage_findings = check_external_storage_enhanced()
        if storage_findings:
            results["findings"].extend(storage_findings)

        # Check cloud storage tools and credentials
        cloud_findings = check_cloud_tools_enhanced()
        if cloud_findings:
            results["findings"].extend(cloud_findings)

        # Check data transfer tools with comprehensive enumeration
        transfer_findings = check_transfer_tools_enhanced()
        if transfer_findings:
            results["findings"].extend(transfer_findings)

        # Check firewall rules for egress restrictions
        firewall_findings = check_firewall_rules_enhanced()
        if firewall_findings:
            results["findings"].extend(firewall_findings)

    except Exception as e:
        results["error"] = str(e)

    return results


def check_network_egress_enhanced():
    """Enhanced network egress testing with multi-protocol verification"""
    findings = []
    methods_verified = []

    try:
        # Method 1: Check active outbound connections
        outbound_connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    outbound_connections.append({
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "local_port": conn.laddr.port
                    })

            if outbound_connections:
                methods_verified.append(True)
                findings.append(create_finding(
                    "medium",
                    f"Active outbound connections detected: {len(outbound_connections)}",
                    f"System has {len(outbound_connections)} active external connections. "
                    f"Top connections: {', '.join([c['remote'] for c in outbound_connections[:5]])}. "
                    f"These channels can be used for data exfiltration.",
                    "Monitor outbound connections for unusual data transfer patterns",
                    95,
                    True
                ))
        except Exception:
            methods_verified.append(False)

        # Method 2: Test HTTP/HTTPS egress
        http_methods = []
        protocols_tested = []

        # Test HTTP (port 80)
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('8.8.8.8', 80))
            sock.close()

            if result == 0:
                http_methods.append('HTTP (port 80)')
                protocols_tested.append(True)
            else:
                protocols_tested.append(False)
        except Exception:
            protocols_tested.append(False)

        # Test HTTPS (port 443)
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('8.8.8.8', 443))
            sock.close()

            if result == 0:
                http_methods.append('HTTPS (port 443)')
                protocols_tested.append(True)
            else:
                protocols_tested.append(False)
        except Exception:
            protocols_tested.append(False)

        if http_methods:
            confidence = common_utils.calculate_confidence_score(*protocols_tested)
            findings.append(create_finding(
                "high",
                f"HTTP/HTTPS egress available: {', '.join(http_methods)}",
                f"System can establish outbound connections on standard web ports. "
                f"Protocols available: {', '.join(http_methods)}. These are the most common "
                f"data exfiltration channels and are often allowed by firewalls.",
                "Implement DPI (Deep Packet Inspection) and monitor HTTP/HTTPS traffic for data exfiltration",
                confidence,
                True
            ))

        # Method 3: Test DNS resolution for DNS tunneling
        try:
            if common_utils.is_linux() or common_utils.is_macos():
                result = subprocess.run(
                    ['nslookup', 'google.com'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            elif common_utils.is_windows():
                result = subprocess.run(
                    ['nslookup', 'google.com'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

            if result.returncode == 0:
                methods_verified.append(True)
                findings.append(create_finding(
                    "high",
                    "DNS resolution available - DNS tunneling possible",
                    "System can resolve external domains. DNS queries can be used for "
                    "data exfiltration via DNS tunneling (encoding data in DNS queries). "
                    "This technique is stealthy and often bypasses firewalls.",
                    "Monitor DNS queries for unusually long hostnames or high query volume to single domains",
                    100,
                    True
                ))
            else:
                methods_verified.append(False)
        except Exception:
            methods_verified.append(False)

        # Method 4: Test ICMP egress (ping)
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
                methods_verified.append(True)
                findings.append(create_finding(
                    "medium",
                    "ICMP egress available (ping successful)",
                    "System can send ICMP packets to external hosts. ICMP can be used "
                    "for covert data exfiltration by encoding data in ICMP echo requests.",
                    "Block or monitor ICMP traffic to external networks",
                    100,
                    True
                ))
            else:
                methods_verified.append(False)
        except Exception:
            methods_verified.append(False)

        # Overall egress assessment
        if not findings:
            findings.append(create_finding(
                "low",
                "Limited network egress detected",
                "No common egress channels were detected. Network may be heavily restricted.",
                "Network restrictions are effective at preventing data exfiltration",
                common_utils.calculate_confidence_score(*methods_verified) if methods_verified else 50,
                len(methods_verified) > 0
            ))

    except Exception as e:
        findings.append(create_finding(
            "info",
            "Network egress check failed",
            f"Could not complete network egress testing: {str(e)}",
            "Manual verification required",
            0,
            False
        ))

    return findings


def check_external_storage_enhanced():
    """Enhanced external storage detection with OS-specific checks"""
    findings = []

    try:
        if common_utils.is_linux() or common_utils.is_macos():
            # Linux/macOS: Check mounted USB/external drives
            methods = []
            usb_mounts = []

            # Method 1: Parse mount command
            try:
                result = subprocess.run(
                    ['mount'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    methods.append(True)
                    for line in result.stdout.split('\n'):
                        # Look for USB, media, mnt indicators
                        if any(indicator in line.lower() for indicator in ['usb', '/media/', '/mnt/', 'external']):
                            usb_mounts.append(line.strip())
                else:
                    methods.append(False)
            except Exception:
                methods.append(False)

            # Method 2: Check /media directory
            try:
                if os.path.exists('/media'):
                    media_contents = []
                    for item in os.listdir('/media'):
                        item_path = os.path.join('/media', item)
                        # Skip user directories, look for actual mounts
                        if os.path.ismount(item_path):
                            media_contents.append(item_path)

                    if media_contents:
                        methods.append(True)
                        usb_mounts.extend(media_contents)
                    else:
                        methods.append(False)
            except Exception:
                methods.append(False)

            # Method 3: Check /mnt directory
            try:
                if os.path.exists('/mnt'):
                    mnt_contents = os.listdir('/mnt')
                    if mnt_contents:
                        methods.append(True)
                        for item in mnt_contents[:5]:
                            usb_mounts.append(f"/mnt/{item}")
                    else:
                        methods.append(False)
            except Exception:
                methods.append(False)

            if usb_mounts:
                # Remove duplicates
                usb_mounts = list(set(usb_mounts))
                confidence = common_utils.calculate_confidence_score(*methods)

                findings.append(create_finding(
                    "high",
                    f"External storage devices mounted: {len(usb_mounts)}",
                    f"External storage provides physical data exfiltration path. "
                    f"Mounted devices: {', '.join(usb_mounts[:5])}. "
                    f"Data can be copied to these devices without network detection.",
                    "Monitor file access to external storage; implement DLP for USB devices",
                    confidence,
                    True
                ))

        elif common_utils.is_windows():
            # Windows: Check for removable drives
            methods = []
            removable_drives = []

            # Method 1: Use wmic to list removable drives
            try:
                result = subprocess.run(
                    ['wmic', 'logicaldisk', 'where', 'drivetype=2', 'get', 'deviceid,volumename'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    methods.append(True)
                    lines = result.stdout.strip().split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            removable_drives.append(line.strip())
                else:
                    methods.append(False)
            except Exception:
                methods.append(False)

            # Method 2: Check for common removable drive letters
            try:
                common_letters = ['D:', 'E:', 'F:', 'G:', 'H:']
                for drive in common_letters:
                    try:
                        if os.path.exists(drive) and os.path.ismount(drive):
                            # Try to check if it's removable (simplified check)
                            removable_drives.append(drive)
                            methods.append(True)
                    except:
                        continue
            except Exception:
                methods.append(False)

            if removable_drives:
                removable_drives = list(set(removable_drives))
                confidence = common_utils.calculate_confidence_score(*methods)

                findings.append(create_finding(
                    "high",
                    f"Removable storage detected: {len(removable_drives)}",
                    f"Windows removable drives found: {', '.join(removable_drives)}. "
                    f"These provide physical exfiltration channels.",
                    "Disable USB storage via Group Policy; implement endpoint DLP",
                    confidence,
                    True
                ))

    except Exception:
        pass

    return findings


def check_cloud_tools_enhanced():
    """Enhanced cloud storage tools and credentials detection"""
    findings = []

    try:
        # Check for cloud CLI tools with verification
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
                f"Cloud storage tools detected: {len(detected_tools)}",
                f"Cloud CLI tools available: {', '.join(detected_tools)}. "
                f"These tools can exfiltrate large volumes of data to cloud storage. "
                f"Locations: {'; '.join(tool_paths[:5])}",
                "Monitor cloud tool usage; block cloud storage domains if not needed",
                90,
                True
            ))

        # Check for cloud credentials with multi-method verification
        cloud_cred_locations = {
            '~/.aws/credentials': 'AWS credentials',
            '~/.aws/config': 'AWS configuration',
            '~/.config/gcloud': 'Google Cloud credentials',
            '~/.azure': 'Azure credentials',
            '~/.s3cfg': 'S3cmd configuration',
            '~/.rclone.conf': 'Rclone configuration'
        }

        found_credentials = []
        for cred_file, description in cloud_cred_locations.items():
            expanded = os.path.expanduser(cred_file)
            if os.path.exists(expanded):
                is_readable = os.access(expanded, os.R_OK)
                if is_readable:
                    found_credentials.append(f"{description} ({expanded})")

        if found_credentials:
            findings.append(create_finding(
                "critical",
                f"Cloud credentials accessible: {len(found_credentials)}",
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


def check_transfer_tools_enhanced():
    """Enhanced data transfer tools enumeration with categorization"""
    findings = []

    try:
        # Categorize transfer tools
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
                f"Data transfer tools available: {total_tools} tools across {len(detected_by_category)} categories",
                f"Multiple data exfiltration tools detected:\n" + "\n".join(category_summary) +
                f"\n\nThese tools can transfer data via network protocols. "
                f"Scripting languages can implement custom exfiltration protocols.",
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
                f"Data encoding tools available: {', '.join(detected_encoders)}",
                f"Encoding tools can obfuscate exfiltrated data to bypass DLP. "
                f"Tools: {', '.join(detected_encoders)}",
                "Monitor use of encoding tools in data exfiltration contexts",
                90,
                True
            ))

    except Exception:
        pass

    return findings


def check_firewall_rules_enhanced():
    """Enhanced firewall rule analysis for egress restrictions"""
    findings = []

    try:
        if common_utils.is_linux():
            # Check iptables OUTPUT chain
            methods = []

            try:
                result = subprocess.run(
                    ['iptables', '-L', 'OUTPUT', '-n', '-v'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    methods.append(True)
                    output_rules = result.stdout

                    # Check default policy
                    if 'policy ACCEPT' in output_rules:
                        drop_count = output_rules.lower().count('drop') + output_rules.lower().count('reject')

                        if drop_count == 0:
                            findings.append(create_finding(
                                "high",
                                "No egress filtering detected (iptables)",
                                "Firewall allows all outbound traffic (policy ACCEPT with no DROP/REJECT rules). "
                                "This enables unrestricted data exfiltration.",
                                "Implement egress filtering: default DROP policy with explicit ALLOW rules for required traffic",
                                100,
                                True
                            ))
                        else:
                            findings.append(create_finding(
                                "medium",
                                f"Partial egress filtering: {drop_count} blocking rules",
                                f"Some outbound traffic is filtered ({drop_count} DROP/REJECT rules), "
                                f"but default policy is ACCEPT. Review rules for bypass opportunities.",
                                "Review and tighten egress rules; consider default DROP policy",
                                95,
                                True
                            ))
                    elif 'policy DROP' in output_rules or 'policy REJECT' in output_rules:
                        accept_count = output_rules.lower().count('accept')
                        findings.append(create_finding(
                            "info",
                            f"Egress filtering active (default DROP/REJECT with {accept_count} ACCEPT rules)",
                            "Firewall has restrictive egress policy. Data exfiltration is limited to allowed ports/protocols.",
                            "Regularly review ACCEPT rules for unauthorized changes",
                            100,
                            True
                        ))
                else:
                    methods.append(False)
            except subprocess.CalledProcessError:
                methods.append(False)
                findings.append(create_finding(
                    "info",
                    "Cannot check iptables rules (insufficient privileges)",
                    "Requires root/sudo to check firewall rules. Egress filtering status unknown.",
                    "Firewall configuration cannot be assessed",
                    50,
                    False
                ))

            # Check nftables if iptables failed
            if not methods or not methods[0]:
                try:
                    result = subprocess.run(
                        ['nft', 'list', 'ruleset'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )

                    if result.returncode == 0 and result.stdout.strip():
                        findings.append(create_finding(
                            "info",
                            "nftables firewall detected",
                            "System uses nftables for firewall. Manual review of egress rules recommended.",
                            "Review nftables egress rules: nft list ruleset",
                            80,
                            True
                        ))
                except:
                    pass

        elif common_utils.is_windows():
            # Check Windows Firewall outbound rules
            try:
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    if 'ON' in result.stdout:
                        findings.append(create_finding(
                            "info",
                            "Windows Firewall is enabled",
                            "Windows Firewall is active. Outbound filtering may be configured.",
                            "Review outbound rules: netsh advfirewall firewall show rule name=all dir=out",
                            90,
                            True
                        ))
                    else:
                        findings.append(create_finding(
                            "high",
                            "Windows Firewall is disabled",
                            "Windows Firewall is not active. No network-level egress filtering.",
                            "Enable Windows Firewall and configure outbound rules",
                            100,
                            True
                        ))
            except:
                pass

        elif common_utils.is_macos():
            # Check macOS firewall (pf)
            try:
                result = subprocess.run(
                    ['pfctl', '-s', 'rules'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    findings.append(create_finding(
                        "info",
                        "macOS packet filter (pf) rules detected",
                        "System has pf rules configured. Manual review recommended.",
                        "Review pf rules for egress restrictions",
                        80,
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
