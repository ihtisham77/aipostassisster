"""
Lateral Movement Assessment Module
Checks for lateral movement opportunities and misconfigurations
"""

import os
import platform
import subprocess
import socket
import glob

def check():
    """
    Check for lateral movement opportunities
    """
    results = {
        "module": "lateral_movement",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # Check SSH configurations
        ssh_findings = check_ssh_config()
        if ssh_findings:
            results["findings"].extend(ssh_findings)

        # Check for saved credentials
        cred_findings = check_saved_credentials()
        if cred_findings:
            results["findings"].extend(cred_findings)

        # Check network shares
        share_findings = check_network_shares()
        if share_findings:
            results["findings"].extend(share_findings)

        # Check for other systems on network
        network_findings = scan_local_network()
        if network_findings:
            results["findings"].extend(network_findings)

        # Check trust relationships
        trust_findings = check_trust_relationships()
        if trust_findings:
            results["findings"].extend(trust_findings)

    except Exception as e:
        results["error"] = str(e)

    return results

def check_ssh_config():
    """Check SSH configuration for lateral movement"""
    findings = []

    try:
        ssh_config = os.path.expanduser('~/.ssh/config')

        if os.path.exists(ssh_config):
            with open(ssh_config, 'r') as f:
                content = f.read()

                findings.append({
                    "severity": "info",
                    "finding": "SSH config file exists",
                    "description": "SSH configuration may contain host information",
                    "remediation": "Review SSH config for sensitive information"
                })

                # Check for specific patterns
                if 'ProxyJump' in content or 'ProxyCommand' in content:
                    findings.append({
                        "severity": "medium",
                        "finding": "SSH proxy/jump host configured",
                        "description": "SSH is configured to use jump hosts for lateral movement",
                        "remediation": "Ensure jump hosts are properly secured"
                    })

        # Check known_hosts
        known_hosts = os.path.expanduser('~/.ssh/known_hosts')
        if os.path.exists(known_hosts):
            try:
                with open(known_hosts, 'r') as f:
                    hosts = f.readlines()

                findings.append({
                    "severity": "info",
                    "finding": f"SSH known_hosts contains {len(hosts)} entries",
                    "description": "Known hosts file reveals previously accessed systems",
                    "remediation": "Systems in known_hosts may be lateral movement targets"
                })
            except Exception:
                pass

        # Check for SSH agent
        if 'SSH_AUTH_SOCK' in os.environ:
            findings.append({
                "severity": "medium",
                "finding": "SSH agent is running",
                "description": "SSH agent may contain loaded keys for passwordless access",
                "remediation": "Agent forwarding can be used for lateral movement"
            })

    except Exception:
        pass

    return findings

def check_saved_credentials():
    """Check for saved credentials that could be used for lateral movement"""
    findings = []

    try:
        # Check .netrc
        netrc = os.path.expanduser('~/.netrc')
        if os.path.exists(netrc):
            findings.append({
                "severity": "high",
                "finding": ".netrc file exists",
                "description": "File may contain credentials for remote systems",
                "remediation": "Review .netrc for credentials to other systems"
            })

        # Check git credentials
        git_creds = os.path.expanduser('~/.git-credentials')
        if os.path.exists(git_creds):
            findings.append({
                "severity": "medium",
                "finding": "Git credentials file exists",
                "description": "May contain credentials for git repositories",
                "remediation": "Git credentials could provide access to code repositories"
            })

        # Check for kubeconfig
        kubeconfig = os.path.expanduser('~/.kube/config')
        if os.path.exists(kubeconfig):
            findings.append({
                "severity": "high",
                "finding": "Kubernetes config found",
                "description": "Kubeconfig may provide access to Kubernetes clusters",
                "remediation": "Kubernetes access enables container/cluster lateral movement"
            })

        # Check for Docker config
        docker_config = os.path.expanduser('~/.docker/config.json')
        if os.path.exists(docker_config):
            findings.append({
                "severity": "medium",
                "finding": "Docker config found",
                "description": "May contain registry credentials",
                "remediation": "Docker credentials could provide access to container registries"
            })

    except Exception:
        pass

    return findings

def check_network_shares():
    """Check for mounted network shares"""
    findings = []

    try:
        # Check /etc/fstab for network mounts
        if os.path.exists('/etc/fstab'):
            with open('/etc/fstab', 'r') as f:
                for line in f:
                    if 'nfs' in line or 'cifs' in line or 'smb' in line:
                        findings.append({
                            "severity": "medium",
                            "finding": "Network share in fstab",
                            "description": f"Mount entry: {line.strip()}",
                            "remediation": "Network shares may provide lateral movement paths"
                        })

        # Check currently mounted filesystems
        result = subprocess.run(
            ['mount'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'nfs' in line or 'cifs' in line or 'smb' in line:
                    findings.append({
                        "severity": "info",
                        "finding": "Network share mounted",
                        "description": f"Mount: {line.strip()}",
                        "remediation": "Mounted shares may provide access to other systems"
                    })

    except Exception:
        pass

    return findings

def scan_local_network():
    """Identify other systems on the local network"""
    findings = []

    try:
        # Get local subnet
        result = subprocess.run(
            ['ip', 'route', 'show'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            subnets = []
            for line in result.stdout.split('\n'):
                if 'proto kernel' in line or 'link' in line:
                    parts = line.split()
                    if parts and '/' in parts[0]:
                        subnets.append(parts[0])

            findings.append({
                "severity": "info",
                "finding": "Local network subnets",
                "description": f"Subnets: {', '.join(subnets[:5])}",
                "remediation": "Scan these subnets for lateral movement targets"
            })

        # Check ARP cache for neighboring systems
        result = subprocess.run(
            ['ip', 'neigh', 'show'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            neighbors = []
            for line in result.stdout.split('\n'):
                if 'REACHABLE' in line or 'STALE' in line:
                    parts = line.split()
                    if parts:
                        neighbors.append(parts[0])

            if neighbors:
                findings.append({
                    "severity": "info",
                    "finding": f"Neighboring systems found: {len(neighbors)}",
                    "description": f"Systems: {', '.join(neighbors[:10])}",
                    "remediation": "These systems are potential lateral movement targets"
                })

    except Exception:
        pass

    return findings

def check_trust_relationships():
    """Check for trust relationships with other systems"""
    findings = []

    try:
        # Check /etc/hosts for defined systems
        if os.path.exists('/etc/hosts'):
            with open('/etc/hosts', 'r') as f:
                hosts = []
                for line in f:
                    if not line.startswith('#') and line.strip():
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] not in ['127.0.0.1', '::1']:
                            hosts.append(f"{parts[0]} ({parts[1]})")

                if hosts:
                    findings.append({
                        "severity": "info",
                        "finding": f"Custom hosts entries: {len(hosts)}",
                        "description": f"Entries: {', '.join(hosts[:5])}",
                        "remediation": "These hosts may be lateral movement targets"
                    })

        # Check for AWS metadata service access
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('169.254.169.254', 80))
            sock.close()

            if result == 0:
                findings.append({
                    "severity": "high",
                    "finding": "AWS metadata service accessible",
                    "description": "System appears to be an AWS EC2 instance",
                    "remediation": "Metadata service may reveal IAM credentials and instance information"
                })
        except Exception:
            pass

        # Check for cloud-init data
        cloud_dirs = ['/var/lib/cloud', '/etc/cloud']
        for cloud_dir in cloud_dirs:
            if os.path.exists(cloud_dir):
                findings.append({
                    "severity": "medium",
                    "finding": "Cloud-init directory found",
                    "description": f"Directory: {cloud_dir}",
                    "remediation": "Cloud configuration may reveal infrastructure details"
                })
                break

    except Exception:
        pass

    return findings

if __name__ == '__main__':
    # Test module
    import json
    results = check()
    print(json.dumps(results, indent=2))
