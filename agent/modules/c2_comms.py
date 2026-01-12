"""
C2 Communication Assessment Module
Checks for C2 communication opportunities and detection evasion
"""

import os
import platform
import subprocess
import socket

def check():
    """
    Check for C2 communication capabilities
    """
    results = {
        "module": "c2_comms",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # Check network connectivity
        network_findings = check_network_connectivity()
        if network_findings:
            results["findings"].extend(network_findings)

        # Check proxy configuration
        proxy_findings = check_proxy_config()
        if proxy_findings:
            results["findings"].extend(proxy_findings)

        # Check DNS capabilities
        dns_findings = check_dns_capabilities()
        if dns_findings:
            results["findings"].extend(dns_findings)

        # Check alternative protocols
        protocol_findings = check_alternative_protocols()
        if protocol_findings:
            results["findings"].extend(protocol_findings)

        # Check monitoring
        monitoring_findings = check_monitoring()
        if monitoring_findings:
            results["findings"].extend(monitoring_findings)

    except Exception as e:
        results["error"] = str(e)

    return results

def check_network_connectivity():
    """Check network connectivity for C2"""
    findings = []

    try:
        # Check HTTP/HTTPS connectivity
        common_ports = [
            (80, 'HTTP'),
            (443, 'HTTPS'),
            (8080, 'HTTP-Alt'),
            (8443, 'HTTPS-Alt')
        ]

        open_ports = []

        for port, protocol in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('8.8.8.8', port))
                sock.close()

                if result == 0:
                    open_ports.append(f"{protocol} ({port})")
            except Exception:
                continue

        if open_ports:
            findings.append({
                "severity": "high",
                "finding": f"Outbound ports accessible: {len(open_ports)}",
                "description": f"Ports: {', '.join(open_ports)}",
                "remediation": "These ports can be used for C2 communication"
            })

        # Check non-standard ports
        non_standard = [53, 123, 445, 3389, 5000, 5985, 9001]

        for port in non_standard:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('8.8.8.8', port))
                sock.close()

                if result == 0:
                    findings.append({
                        "severity": "medium",
                        "finding": f"Non-standard port accessible: {port}",
                        "description": f"Port {port} can be used for C2 traffic",
                        "remediation": "Monitor traffic on non-standard ports"
                    })
            except Exception:
                continue

    except Exception:
        pass

    return findings

def check_proxy_config():
    """Check proxy configuration"""
    findings = []

    try:
        # Check environment variables
        proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'ALL_PROXY']

        configured_proxies = []

        for var in proxy_vars:
            if var in os.environ:
                configured_proxies.append(f"{var}={os.environ[var]}")

        if configured_proxies:
            findings.append({
                "severity": "medium",
                "finding": "Proxy configuration detected",
                "description": f"Proxies: {', '.join(configured_proxies)}",
                "remediation": "C2 traffic can be tunneled through proxy"
            })
        else:
            findings.append({
                "severity": "info",
                "finding": "No proxy configuration detected",
                "description": "Direct internet access available",
                "remediation": "Direct connections are easier to detect"
            })

        # Check system proxy settings
        proxy_files = [
            '/etc/environment',
            '~/.bash_profile',
            '~/.bashrc'
        ]

        for proxy_file in proxy_files:
            expanded = os.path.expanduser(proxy_file)
            if os.path.exists(expanded):
                try:
                    with open(expanded, 'r') as f:
                        content = f.read()
                        if 'proxy' in content.lower():
                            findings.append({
                                "severity": "info",
                                "finding": f"Proxy settings in {expanded}",
                                "description": "System-level proxy configuration exists",
                                "remediation": "Proxy configuration affects C2 traffic routing"
                            })
                            break
                except Exception:
                    pass

    except Exception:
        pass

    return findings

def check_dns_capabilities():
    """Check DNS capabilities for C2"""
    findings = []

    try:
        # Test DNS resolution
        try:
            socket.gethostbyname('google.com')

            findings.append({
                "severity": "high",
                "finding": "DNS resolution available",
                "description": "Can resolve external domains",
                "remediation": "DNS can be used for C2 (DNS tunneling)"
            })
        except Exception:
            findings.append({
                "severity": "info",
                "finding": "DNS resolution failed",
                "description": "Limited DNS capabilities",
                "remediation": "Direct DNS-based C2 may not work"
            })

        # Check DNS servers
        try:
            with open('/etc/resolv.conf', 'r') as f:
                dns_servers = [line.split()[1] for line in f if line.startswith('nameserver')]

                findings.append({
                    "severity": "info",
                    "finding": f"DNS servers configured: {len(dns_servers)}",
                    "description": f"Servers: {', '.join(dns_servers)}",
                    "remediation": "DNS traffic goes through these servers"
                })
        except Exception:
            pass

        # Check if DNS tools are available
        dns_tools = ['dig', 'nslookup', 'host']

        available_tools = []
        for tool in dns_tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, timeout=2)
                if result.returncode == 0:
                    available_tools.append(tool)
            except Exception:
                continue

        if available_tools:
            findings.append({
                "severity": "medium",
                "finding": f"DNS tools available: {', '.join(available_tools)}",
                "description": "Tools can be used for DNS-based C2",
                "remediation": "Monitor DNS queries for anomalies"
            })

    except Exception:
        pass

    return findings

def check_alternative_protocols():
    """Check for alternative C2 protocols"""
    findings = []

    try:
        # Check for SSH
        try:
            result = subprocess.run(['which', 'ssh'], capture_output=True, timeout=2)
            if result.returncode == 0:
                findings.append({
                    "severity": "medium",
                    "finding": "SSH client available",
                    "description": "SSH can be used for C2 tunneling",
                    "remediation": "Monitor SSH connections to external hosts"
                })
        except Exception:
            pass

        # Check for TLS/SSL tools
        tls_tools = ['openssl', 'gnutls-cli']

        for tool in tls_tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, timeout=2)
                if result.returncode == 0:
                    findings.append({
                        "severity": "medium",
                        "finding": f"TLS tool available: {tool}",
                        "description": "Can establish encrypted C2 channels",
                        "remediation": "TLS/SSL encryption hides C2 traffic"
                    })
                    break
            except Exception:
                continue

        # Check for scripting languages (for custom C2)
        script_langs = [
            ('python', 'Python'),
            ('python3', 'Python3'),
            ('perl', 'Perl'),
            ('ruby', 'Ruby'),
            ('node', 'Node.js'),
            ('php', 'PHP')
        ]

        available_langs = []
        for cmd, name in script_langs:
            try:
                result = subprocess.run(['which', cmd], capture_output=True, timeout=2)
                if result.returncode == 0:
                    available_langs.append(name)
            except Exception:
                continue

        if available_langs:
            findings.append({
                "severity": "high",
                "finding": f"Scripting languages available: {len(available_langs)}",
                "description": f"Languages: {', '.join(available_langs)}",
                "remediation": "Can implement custom C2 protocols"
            })

    except Exception:
        pass

    return findings

def check_monitoring():
    """Check for network monitoring"""
    findings = []

    try:
        # Check for common monitoring tools
        monitoring_tools = [
            'tcpdump', 'wireshark', 'tshark', 'snort',
            'suricata', 'bro', 'zeek', 'ossec'
        ]

        detected_monitors = []

        for tool in monitoring_tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, timeout=2)
                if result.returncode == 0:
                    detected_monitors.append(tool)
            except Exception:
                continue

        if detected_monitors:
            findings.append({
                "severity": "high",
                "finding": f"Network monitoring tools detected: {len(detected_monitors)}",
                "description": f"Tools: {', '.join(detected_monitors)}",
                "remediation": "C2 traffic may be monitored and detected"
            })
        else:
            findings.append({
                "severity": "info",
                "finding": "No network monitoring tools detected",
                "description": "Less likely to have network traffic inspection",
                "remediation": "C2 traffic less likely to be detected"
            })

        # Check for running monitoring processes
        try:
            import psutil

            monitoring_procs = []

            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()

                    if any(mon in proc_name for mon in ['tcpdump', 'wireshark', 'snort', 'suricata']):
                        monitoring_procs.append(proc.info['name'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if monitoring_procs:
                findings.append({
                    "severity": "high",
                    "finding": "Active network monitoring detected",
                    "description": f"Processes: {', '.join(monitoring_procs)}",
                    "remediation": "Network traffic is being actively monitored"
                })

        except ImportError:
            pass

    except Exception:
        pass

    return findings

if __name__ == '__main__':
    # Test module
    import json
    results = check()
    print(json.dumps(results, indent=2))
