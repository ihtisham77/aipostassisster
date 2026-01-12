"""
Data Exfiltration Assessment Module
Checks for data exfiltration channels and opportunities
"""

import os
import platform
import subprocess
import psutil

def check():
    """
    Check for data exfiltration opportunities
    """
    results = {
        "module": "data_exfiltration",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # Check network egress
        egress_findings = check_network_egress()
        if egress_findings:
            results["findings"].extend(egress_findings)

        # Check external storage
        storage_findings = check_external_storage()
        if storage_findings:
            results["findings"].extend(storage_findings)

        # Check cloud storage tools
        cloud_findings = check_cloud_tools()
        if cloud_findings:
            results["findings"].extend(cloud_findings)

        # Check data transfer tools
        transfer_findings = check_transfer_tools()
        if transfer_findings:
            results["findings"].extend(transfer_findings)

        # Check firewall rules
        firewall_findings = check_firewall_rules()
        if firewall_findings:
            results["findings"].extend(firewall_findings)

    except Exception as e:
        results["error"] = str(e)

    return results

def check_network_egress():
    """Check network egress capabilities"""
    findings = []

    try:
        # Check for established outbound connections
        outbound_connections = []

        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                outbound_connections.append({
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "local_port": conn.laddr.port
                })

        if outbound_connections:
            findings.append({
                "severity": "info",
                "finding": f"Active outbound connections: {len(outbound_connections)}",
                "description": f"Connections: {', '.join([c['remote'] for c in outbound_connections[:5]])}",
                "remediation": "These connections could be used for data exfiltration"
            })

        # Check DNS resolution
        try:
            result = subprocess.run(
                ['nslookup', 'google.com'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                findings.append({
                    "severity": "medium",
                    "finding": "DNS resolution available",
                    "description": "System can resolve external domains",
                    "remediation": "DNS queries can be used for data exfiltration"
                })
        except Exception:
            pass

        # Check ICMP capability
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '8.8.8.8'],
                capture_output=True,
                timeout=5
            )

            if result.returncode == 0:
                findings.append({
                    "severity": "medium",
                    "finding": "ICMP egress available",
                    "description": "System can send ICMP packets",
                    "remediation": "ICMP can be used for data exfiltration"
                })
        except Exception:
            pass

    except Exception:
        pass

    return findings

def check_external_storage():
    """Check for external storage devices"""
    findings = []

    try:
        # Check mounted USB/external drives
        result = subprocess.run(
            ['mount'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            usb_mounts = []

            for line in result.stdout.split('\n'):
                if 'usb' in line.lower() or '/media/' in line or '/mnt/' in line:
                    usb_mounts.append(line.strip())

            if usb_mounts:
                findings.append({
                    "severity": "high",
                    "finding": f"External storage mounted: {len(usb_mounts)}",
                    "description": f"Mounts: {', '.join(usb_mounts[:3])}",
                    "remediation": "External storage provides physical exfiltration path"
                })

        # Check /media and /mnt directories
        for mount_dir in ['/media', '/mnt']:
            if os.path.exists(mount_dir):
                try:
                    contents = os.listdir(mount_dir)
                    if contents:
                        findings.append({
                            "severity": "medium",
                            "finding": f"Mount point has contents: {mount_dir}",
                            "description": f"Contents: {', '.join(contents)}",
                            "remediation": "Check for external storage devices"
                        })
                except Exception:
                    pass

    except Exception:
        pass

    return findings

def check_cloud_tools():
    """Check for cloud storage tools"""
    findings = []

    try:
        cloud_tools = [
            ('aws', 'AWS CLI'),
            ('gcloud', 'Google Cloud SDK'),
            ('az', 'Azure CLI'),
            ('rclone', 'Rclone'),
            ('s3cmd', 'S3cmd'),
            ('gsutil', 'gsutil'),
            ('dropbox', 'Dropbox'),
            ('gdrive', 'Google Drive CLI')
        ]

        detected_tools = []

        for tool, name in cloud_tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, timeout=2)
                if result.returncode == 0:
                    detected_tools.append(name)
            except Exception:
                continue

        if detected_tools:
            findings.append({
                "severity": "high",
                "finding": f"Cloud storage tools detected: {len(detected_tools)}",
                "description": f"Tools: {', '.join(detected_tools)}",
                "remediation": "Cloud tools can exfiltrate data to cloud storage"
            })

        # Check for cloud credentials
        cloud_cred_files = [
            '~/.aws/credentials',
            '~/.config/gcloud',
            '~/.azure'
        ]

        for cred_file in cloud_cred_files:
            expanded = os.path.expanduser(cred_file)
            if os.path.exists(expanded):
                findings.append({
                    "severity": "high",
                    "finding": f"Cloud credentials found: {expanded}",
                    "description": "Credentials enable cloud storage exfiltration",
                    "remediation": "Monitor cloud storage usage for unauthorized access"
                })

    except Exception:
        pass

    return findings

def check_transfer_tools():
    """Check for data transfer tools"""
    findings = []

    try:
        transfer_tools = [
            ('curl', 'curl'),
            ('wget', 'wget'),
            ('nc', 'netcat'),
            ('socat', 'socat'),
            ('scp', 'scp'),
            ('sftp', 'sftp'),
            ('ftp', 'ftp'),
            ('rsync', 'rsync'),
            ('python', 'Python'),
            ('python3', 'Python3'),
            ('perl', 'Perl'),
            ('ruby', 'Ruby')
        ]

        available_tools = []

        for tool, name in transfer_tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, timeout=2)
                if result.returncode == 0:
                    available_tools.append(name)
            except Exception:
                continue

        if available_tools:
            findings.append({
                "severity": "medium",
                "finding": f"Data transfer tools available: {len(available_tools)}",
                "description": f"Tools: {', '.join(available_tools[:10])}",
                "remediation": "These tools can be used for data exfiltration"
            })

        # Check for base64 (encoding for exfiltration)
        try:
            result = subprocess.run(['which', 'base64'], capture_output=True, timeout=2)
            if result.returncode == 0:
                findings.append({
                    "severity": "info",
                    "finding": "base64 encoding available",
                    "description": "Data can be encoded for exfiltration",
                    "remediation": "base64 is commonly used to encode exfiltrated data"
                })
        except Exception:
            pass

    except Exception:
        pass

    return findings

def check_firewall_rules():
    """Check firewall rules for egress restrictions"""
    findings = []

    try:
        # Check iptables OUTPUT chain
        result = subprocess.run(
            ['iptables', '-L', 'OUTPUT', '-n', '-v'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            output_rules = result.stdout

            if 'policy ACCEPT' in output_rules.lower():
                findings.append({
                    "severity": "medium",
                    "finding": "Firewall allows outbound traffic",
                    "description": "No egress filtering detected",
                    "remediation": "Implement egress filtering to prevent data exfiltration"
                })

            # Count DROP/REJECT rules
            drop_count = output_rules.lower().count('drop') + output_rules.lower().count('reject')

            if drop_count > 0:
                findings.append({
                    "severity": "info",
                    "finding": f"Egress filtering rules detected: {drop_count}",
                    "description": "Some outbound traffic is filtered",
                    "remediation": "Review egress rules for bypass opportunities"
                })
            else:
                findings.append({
                    "severity": "high",
                    "finding": "No egress filtering detected",
                    "description": "All outbound traffic appears to be allowed",
                    "remediation": "Lack of egress filtering enables data exfiltration"
                })

    except subprocess.CalledProcessError:
        findings.append({
            "severity": "info",
            "finding": "Cannot check firewall rules",
            "description": "Insufficient privileges to check iptables",
            "remediation": "Firewall rules unknown"
        })
    except Exception:
        pass

    return findings

if __name__ == '__main__':
    # Test module
    import json
    results = check()
    print(json.dumps(results, indent=2))
