"""
Lateral Movement Assessment Module - PRODUCTION ENHANCED
Checks for lateral movement opportunities and misconfigurations with confidence scoring
"""

import os
import platform
import subprocess
import socket
import glob
import re

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
    Check for lateral movement opportunities with OS-specific enhanced checks
    """
    results = {
        "module": "lateral_movement",
        "platform": platform.system(),
        "os_type": common_utils.get_os_type(),
        "findings": []
    }

    try:
        # SSH configurations (Linux/macOS)
        ssh_findings = check_ssh_config_enhanced()
        results["findings"].extend(ssh_findings)

        # Saved credentials (All OS)
        cred_findings = check_saved_credentials_enhanced()
        results["findings"].extend(cred_findings)

        # Network shares (All OS)
        share_findings = check_network_shares_enhanced()
        results["findings"].extend(share_findings)

        # Network reconnaissance (All OS)
        network_findings = scan_local_network_enhanced()
        results["findings"].extend(network_findings)

        # Trust relationships (All OS)
        trust_findings = check_trust_relationships_enhanced()
        results["findings"].extend(trust_findings)

        # Windows-specific checks
        if common_utils.is_windows():
            rdp_findings = check_rdp_credentials()
            results["findings"].extend(rdp_findings)

            winrm_findings = check_winrm_config()
            results["findings"].extend(winrm_findings)

        # Cloud metadata access (All OS)
        cloud_findings = check_cloud_metadata_access()
        results["findings"].extend(cloud_findings)

    except Exception as e:
        results["error"] = str(e)

    return results


def check_ssh_config_enhanced():
    """Enhanced SSH configuration checks with multi-method verification"""
    findings = []

    if common_utils.is_windows():
        return findings  # Skip on Windows (unless OpenSSH is installed)

    try:
        ssh_dir = os.path.expanduser('~/.ssh')
        methods_used = []

        # Check SSH directory existence
        if not os.path.exists(ssh_dir):
            return findings

        # Method 1: Check SSH config file
        ssh_config = os.path.join(ssh_dir, 'config')
        if os.path.exists(ssh_config):
            try:
                with open(ssh_config, 'r') as f:
                    content = f.read()
                    methods_used.append('ssh_config')

                    # Check for proxy/jump hosts
                    if 'ProxyJump' in content or 'ProxyCommand' in content:
                        findings.append(create_finding(
                            "medium",
                            "SSH jump host configuration detected",
                            "SSH is configured with ProxyJump/ProxyCommand for lateral movement through bastion hosts. "
                            "These configurations reveal network topology and potential pivot points.",
                            "Review jump host security and ensure proper authentication",
                            100,
                            True
                        ))

                    # Check for ForwardAgent
                    if 'ForwardAgent yes' in content:
                        findings.append(create_finding(
                            "high",
                            "SSH agent forwarding enabled",
                            "Agent forwarding is enabled in SSH config. This allows forwarded authentication to remote systems, "
                            "enabling lateral movement without re-authentication.",
                            "Disable agent forwarding unless specifically required",
                            100,
                            True
                        ))

                    # Count configured hosts
                    host_count = content.count('Host ')
                    if host_count > 0:
                        findings.append(create_finding(
                            "info",
                            f"SSH config contains {host_count} host configurations",
                            f"SSH configuration defines {host_count} host entries, revealing potential lateral movement targets.",
                            "These hosts are known connection targets",
                            100,
                            True
                        ))
            except Exception:
                pass

        # Method 2: Check known_hosts
        known_hosts = os.path.join(ssh_dir, 'known_hosts')
        if os.path.exists(known_hosts):
            try:
                with open(known_hosts, 'r') as f:
                    hosts = [line for line in f if line.strip() and not line.startswith('#')]
                    methods_used.append('known_hosts')

                    if hosts:
                        findings.append(create_finding(
                            "info",
                            f"SSH known_hosts contains {len(hosts)} entries",
                            f"Found {len(hosts)} previously accessed systems in known_hosts. "
                            "These represent historical SSH connections and potential lateral movement targets.",
                            "Review known_hosts for lateral movement opportunities",
                            100,
                            True
                        ))
            except Exception:
                pass

        # Method 3: Check SSH private keys
        key_files = []
        for item in os.listdir(ssh_dir):
            item_path = os.path.join(ssh_dir, item)
            if os.path.isfile(item_path) and not item.endswith('.pub'):
                try:
                    with open(item_path, 'r', encoding='utf-8', errors='ignore') as f:
                        first_line = f.readline()
                        if 'PRIVATE KEY' in first_line:
                            # Check if encrypted
                            f.seek(0)
                            content = f.read(500)
                            is_encrypted = 'ENCRYPTED' in content
                            key_files.append((item, is_encrypted))
                            methods_used.append(f'key_{item}')
                except Exception:
                    pass

        if key_files:
            unencrypted_keys = [k for k, enc in key_files if not enc]
            if unencrypted_keys:
                findings.append(create_finding(
                    "high",
                    f"Unencrypted SSH private keys found: {len(unencrypted_keys)}",
                    f"Found {len(unencrypted_keys)} unencrypted SSH private keys: {', '.join(unencrypted_keys)}. "
                    "These keys enable passwordless authentication to remote systems for lateral movement.",
                    "Encrypt SSH private keys with passphrases",
                    100,
                    True
                ))
            else:
                findings.append(create_finding(
                    "medium",
                    f"Encrypted SSH private keys found: {len(key_files)}",
                    f"Found {len(key_files)} encrypted SSH private keys. Keys are encrypted but can still be used for lateral movement if passphrase is obtained.",
                    "SSH keys present - monitor for unauthorized usage",
                    100,
                    True
                ))

        # Method 4: Check SSH agent
        if 'SSH_AUTH_SOCK' in os.environ:
            methods_used.append('ssh_agent')

            # Try to list loaded keys
            try:
                result = subprocess.run(['ssh-add', '-l'], capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and result.stdout.strip():
                    key_count = len([l for l in result.stdout.split('\n') if l.strip()])
                    findings.append(create_finding(
                        "high",
                        f"SSH agent running with {key_count} loaded keys",
                        f"SSH agent contains {key_count} loaded private keys available for passwordless authentication. "
                        "Agent forwarding enables lateral movement to multiple systems without re-authentication.",
                        "Monitor SSH agent usage and consider disabling agent forwarding",
                        100,
                        True
                    ))
            except Exception:
                findings.append(create_finding(
                    "medium",
                    "SSH agent is running",
                    "SSH agent is active (SSH_AUTH_SOCK set). May contain loaded keys for lateral movement.",
                    "Verify SSH agent key usage",
                    95,
                    True
                ))

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

    except Exception:
        pass

    return findings


def check_saved_credentials_enhanced():
    """Enhanced saved credentials detection with multi-method verification"""
    findings = []

    try:
        methods_used = []
        credentials_found = []

        # Check .netrc (FTP/HTTP credentials)
        netrc = os.path.expanduser('~/.netrc')
        if os.path.exists(netrc):
            try:
                with open(netrc, 'r') as f:
                    content = f.read()
                    # Count machine entries
                    machine_count = content.count('machine ')
                    credentials_found.append(f'.netrc ({machine_count} machines)')
                    methods_used.append('netrc')

                    findings.append(create_finding(
                        "high",
                        f".netrc file with {machine_count} stored credentials",
                        ".netrc contains cleartext credentials for remote FTP/HTTP authentication. "
                        "These credentials enable lateral movement to network services.",
                        "Remove .netrc or restrict permissions (chmod 600)",
                        100,
                        True
                    ))
            except Exception:
                pass

        # Check git credentials
        git_creds = os.path.expanduser('~/.git-credentials')
        if os.path.exists(git_creds):
            try:
                with open(git_creds, 'r') as f:
                    lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                    credentials_found.append(f'git-credentials ({len(lines)} entries)')
                    methods_used.append('git_credentials')

                    findings.append(create_finding(
                        "medium",
                        f"Git credentials file with {len(lines)} entries",
                        "Git credentials stored in cleartext. Provides access to source code repositories "
                        "which may contain additional credentials or infrastructure information.",
                        "Use SSH keys or credential helpers instead",
                        100,
                        True
                    ))
            except Exception:
                pass

        # Check kubeconfig (Kubernetes)
        kubeconfig = os.path.expanduser('~/.kube/config')
        if os.path.exists(kubeconfig):
            try:
                with open(kubeconfig, 'r') as f:
                    content = f.read()
                    cluster_count = content.count('cluster:')
                    credentials_found.append(f'kubeconfig ({cluster_count} clusters)')
                    methods_used.append('kubeconfig')

                    # Check for embedded credentials
                    has_client_cert = 'client-certificate-data:' in content
                    has_token = 'token:' in content

                    severity = "critical" if (has_client_cert or has_token) else "high"

                    findings.append(create_finding(
                        severity,
                        f"Kubernetes config with {cluster_count} cluster(s)",
                        f"Kubeconfig provides access to {cluster_count} Kubernetes cluster(s). "
                        f"Contains embedded credentials: {has_client_cert or has_token}. "
                        "Enables container and cluster lateral movement.",
                        "Secure kubeconfig with appropriate RBAC restrictions",
                        100,
                        True
                    ))
            except Exception:
                pass

        # Check Docker config
        docker_config = os.path.expanduser('~/.docker/config.json')
        if os.path.exists(docker_config):
            try:
                with open(docker_config, 'r') as f:
                    content = f.read()
                    has_auths = '"auths"' in content
                    credentials_found.append('docker config')
                    methods_used.append('docker_config')

                    if has_auths:
                        findings.append(create_finding(
                            "medium",
                            "Docker config with registry credentials",
                            "Docker config contains authentication for container registries. "
                            "Provides access to private container images and registries.",
                            "Use credential helpers instead of embedded auth",
                            100,
                            True
                        ))
            except Exception:
                pass

        # Check AWS credentials
        aws_creds = os.path.expanduser('~/.aws/credentials')
        if os.path.exists(aws_creds):
            try:
                with open(aws_creds, 'r') as f:
                    content = f.read()
                    profile_count = content.count('[')
                    credentials_found.append(f'AWS credentials ({profile_count} profiles)')
                    methods_used.append('aws_credentials')

                    findings.append(create_finding(
                        "critical",
                        f"AWS credentials with {profile_count} profile(s)",
                        f"AWS credentials file contains {profile_count} profile(s) with API keys. "
                        "Provides access to AWS cloud resources for lateral movement.",
                        "Use IAM roles instead of long-term credentials",
                        100,
                        True
                    ))
            except Exception:
                pass

        # Check Azure CLI credentials
        azure_dir = os.path.expanduser('~/.azure')
        if os.path.exists(azure_dir):
            methods_used.append('azure_cli')
            findings.append(create_finding(
                "high",
                "Azure CLI credentials directory found",
                "Azure CLI configuration directory present. May contain access tokens for Azure resources.",
                "Review Azure credentials and use managed identities",
                95,
                True
            ))

        # Check GCP credentials
        gcp_creds = os.path.expanduser('~/.config/gcloud')
        if os.path.exists(gcp_creds):
            methods_used.append('gcp_credentials')
            findings.append(create_finding(
                "high",
                "GCP credentials directory found",
                "Google Cloud credentials directory present. May contain service account keys for GCP resources.",
                "Use workload identity instead of service account keys",
                95,
                True
            ))

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

    except Exception:
        pass

    return findings


def check_network_shares_enhanced():
    """Enhanced network shares detection with OS-specific checks"""
    findings = []

    try:
        methods_used = []

        if common_utils.is_linux():
            # Check /etc/fstab
            if os.path.exists('/etc/fstab'):
                try:
                    with open('/etc/fstab', 'r') as f:
                        network_mounts = []
                        for line in f:
                            if any(fs in line for fs in ['nfs', 'cifs', 'smb', 'smbfs']):
                                network_mounts.append(line.strip())

                        if network_mounts:
                            methods_used.append('fstab')
                            findings.append(create_finding(
                                "medium",
                                f"Network shares in fstab: {len(network_mounts)}",
                                f"Found {len(network_mounts)} configured network shares. "
                                "These provide persistent lateral movement paths to network resources.",
                                "Review network share access and credentials",
                                100,
                                True
                            ))
                except Exception:
                    pass

            # Check currently mounted
            try:
                result = subprocess.run(['mount'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    mounted_shares = [line for line in result.stdout.split('\n')
                                     if any(fs in line for fs in ['nfs', 'cifs', 'smb'])]

                    if mounted_shares:
                        methods_used.append('mount')
                        findings.append(create_finding(
                            "info",
                            f"Active network mounts: {len(mounted_shares)}",
                            f"Currently mounted network shares: {len(mounted_shares)}. "
                            "Active connections to network file systems.",
                            "Monitor network share usage",
                            100,
                            True
                        ))
            except Exception:
                pass

        elif common_utils.is_windows():
            # Check mapped drives
            try:
                result = subprocess.run(['net', 'use'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    mapped_drives = [l for l in lines if '\\\\' in l]

                    if mapped_drives:
                        methods_used.append('net_use')
                        findings.append(create_finding(
                            "medium",
                            f"Mapped network drives: {len(mapped_drives)}",
                            f"Found {len(mapped_drives)} mapped network drives. "
                            "These UNC paths provide lateral movement to network resources.",
                            "Review mapped drives and credentials",
                            100,
                            True
                        ))
            except Exception:
                pass

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

    except Exception:
        pass

    return findings


def scan_local_network_enhanced():
    """Enhanced local network reconnaissance"""
    findings = []

    try:
        methods_used = []

        if common_utils.is_linux():
            # Get subnet info
            try:
                result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    subnets = []
                    for line in result.stdout.split('\n'):
                        if 'proto kernel' in line or 'link' in line:
                            parts = line.split()
                            if parts and '/' in parts[0]:
                                subnets.append(parts[0])

                    if subnets:
                        methods_used.append('ip_route')
                        findings.append(create_finding(
                            "info",
                            f"Local subnets identified: {len(subnets)}",
                            f"Found {len(subnets)} local subnets: {', '.join(subnets[:5])}. "
                            "These are potential lateral movement targets.",
                            "Scan subnets for accessible systems",
                            100,
                            True
                        ))
            except Exception:
                pass

            # Check ARP cache
            try:
                result = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    neighbors = []
                    for line in result.stdout.split('\n'):
                        if 'REACHABLE' in line or 'STALE' in line:
                            parts = line.split()
                            if parts:
                                neighbors.append(parts[0])

                    if neighbors:
                        methods_used.append('arp_cache')
                        findings.append(create_finding(
                            "info",
                            f"ARP cache: {len(neighbors)} neighboring systems",
                            f"Found {len(neighbors)} systems in ARP cache: {', '.join(neighbors[:10])}. "
                            "These systems are on the same network segment.",
                            "Potential lateral movement targets",
                            100,
                            True
                        ))
            except Exception:
                pass

        elif common_utils.is_windows():
            # Check ARP cache
            try:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    neighbor_count = len([l for l in lines if 'dynamic' in l.lower() or 'static' in l.lower()])

                    if neighbor_count > 0:
                        methods_used.append('arp')
                        findings.append(create_finding(
                            "info",
                            f"ARP cache: {neighbor_count} neighboring systems",
                            f"Found {neighbor_count} systems in ARP cache. "
                            "These are potential lateral movement targets on local network.",
                            "Enumerate and assess neighboring systems",
                            100,
                            True
                        ))
            except Exception:
                pass

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

    except Exception:
        pass

    return findings


def check_trust_relationships_enhanced():
    """Enhanced trust relationship detection"""
    findings = []

    try:
        methods_used = []

        # Check /etc/hosts (Linux/macOS) or C:\Windows\System32\drivers\etc\hosts (Windows)
        if common_utils.is_windows():
            hosts_file = r'C:\Windows\System32\drivers\etc\hosts'
        else:
            hosts_file = '/etc/hosts'

        if os.path.exists(hosts_file):
            try:
                with open(hosts_file, 'r') as f:
                    custom_hosts = []
                    for line in f:
                        if not line.startswith('#') and line.strip():
                            parts = line.split()
                            if len(parts) >= 2 and parts[0] not in ['127.0.0.1', '::1', 'localhost']:
                                custom_hosts.append(f"{parts[1]} ({parts[0]})")

                    if custom_hosts:
                        methods_used.append('hosts_file')
                        findings.append(create_finding(
                            "info",
                            f"Custom hosts entries: {len(custom_hosts)}",
                            f"Found {len(custom_hosts)} custom host mappings: {', '.join(custom_hosts[:5])}. "
                            "These represent known systems for lateral movement.",
                            "Review custom hosts for lateral movement targets",
                            100,
                            True
                        ))
            except Exception:
                pass

        # Check for Windows domain membership
        if common_utils.is_windows():
            try:
                result = subprocess.run(
                    ['systeminfo'],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                if result.returncode == 0:
                    if 'Domain:' in result.stdout:
                        for line in result.stdout.split('\n'):
                            if line.strip().startswith('Domain:'):
                                domain = line.split(':', 1)[1].strip()
                                if domain.lower() not in ['workgroup', 'workgroup.local']:
                                    methods_used.append('domain_membership')
                                    findings.append(create_finding(
                                        "high",
                                        f"System is domain-joined: {domain}",
                                        f"System is member of Active Directory domain: {domain}. "
                                        "Domain credentials enable lateral movement to other domain systems.",
                                        "Enumerate domain for lateral movement opportunities",
                                        100,
                                        True
                                    ))
            except Exception:
                pass

        confidence = common_utils.calculate_confidence_score(*[True] * len(methods_used))

    except Exception:
        pass

    return findings


def check_rdp_credentials():
    """Check for saved RDP credentials (Windows)"""
    findings = []

    if not common_utils.is_windows():
        return findings

    try:
        # Check for saved RDP connections
        try:
            result = subprocess.run(
                ['cmdkey', '/list'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                rdp_entries = [line for line in result.stdout.split('\n') if 'TERMSRV' in line.upper()]

                if rdp_entries:
                    findings.append(create_finding(
                        "high",
                        f"Saved RDP credentials: {len(rdp_entries)}",
                        f"Found {len(rdp_entries)} saved RDP (Terminal Services) credentials. "
                        "These enable passwordless lateral movement via Remote Desktop.",
                        "Review saved RDP credentials and remove if unnecessary",
                        100,
                        True
                    ))
        except Exception:
            pass

        # Check RDP connection history
        rdp_history_key = r'Software\Microsoft\Terminal Server Client\Servers'
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rdp_history_key, 0, winreg.KEY_READ)

            server_count = 0
            try:
                i = 0
                while True:
                    server = winreg.EnumKey(key, i)
                    server_count += 1
                    i += 1
            except OSError:
                pass

            winreg.CloseKey(key)

            if server_count > 0:
                findings.append(create_finding(
                    "info",
                    f"RDP connection history: {server_count} servers",
                    f"Found {server_count} servers in RDP connection history. "
                    "These represent previously accessed systems for lateral movement.",
                    "Review RDP history for lateral movement targets",
                    100,
                    True
                ))
        except Exception:
            pass

    except Exception:
        pass

    return findings


def check_winrm_config():
    """Check WinRM configuration (Windows)"""
    findings = []

    if not common_utils.is_windows():
        return findings

    try:
        # Check if WinRM is running
        result = subprocess.run(
            ['powershell', '-Command', 'Get-Service WinRM | Select-Object -ExpandProperty Status'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0 and 'Running' in result.stdout:
            findings.append(create_finding(
                "medium",
                "WinRM service is running",
                "Windows Remote Management (WinRM) service is active. "
                "WinRM enables PowerShell remoting for lateral movement to other Windows systems.",
                "WinRM can be used for lateral movement with valid credentials",
                100,
                True
            ))

            # Check trusted hosts
            try:
                result = subprocess.run(
                    ['powershell', '-Command', 'Get-Item WSMan:\\localhost\\Client\\TrustedHosts | Select-Object -ExpandProperty Value'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0 and result.stdout.strip():
                    trusted_hosts = result.stdout.strip()
                    findings.append(create_finding(
                        "info",
                        f"WinRM trusted hosts configured: {trusted_hosts}",
                        f"WinRM trusted hosts: {trusted_hosts}. "
                        "These systems can be accessed via PowerShell remoting.",
                        "Potential lateral movement targets via WinRM",
                        100,
                        True
                    ))
            except Exception:
                pass

    except Exception:
        pass

    return findings


def check_cloud_metadata_access():
    """Check access to cloud metadata services (All OS)"""
    findings = []

    try:
        cloud_services = {
            'AWS': ('169.254.169.254', 80, '/latest/meta-data/'),
            'Azure': ('169.254.169.254', 80, '/metadata/instance?api-version=2021-02-01'),
            'GCP': ('metadata.google.internal', 80, '/computeMetadata/v1/')
        }

        for cloud_provider, (host, port, path) in cloud_services.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)

                # Resolve hostname if needed
                if not host.replace('.', '').isdigit():
                    try:
                        host = socket.gethostbyname(host)
                    except:
                        continue

                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    findings.append(create_finding(
                        "critical",
                        f"{cloud_provider} metadata service accessible",
                        f"System can access {cloud_provider} metadata service at {host}. "
                        "Metadata service provides IAM credentials, instance information, and user-data. "
                        "This enables cloud-based lateral movement and privilege escalation.",
                        f"Restrict metadata service access or use IMDSv2 ({cloud_provider})",
                        95,
                        True
                    ))
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
