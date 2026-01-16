"""
C2 Communication Assessment Module - PRODUCTION ENHANCED
Checks for C2 communication capabilities with multi-protocol verification
"""

import os
import platform
import subprocess
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
    Check for C2 communication capabilities with comprehensive protocol testing
    """
    results = {
        "module": "c2_comms",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # Check network connectivity with multi-protocol verification
        network_findings = check_network_connectivity_enhanced()
        if network_findings:
            results["findings"].extend(network_findings)

        # Check proxy configuration
        proxy_findings = check_proxy_config_enhanced()
        if proxy_findings:
            results["findings"].extend(proxy_findings)

        # Check DNS capabilities for C2 channels
        dns_findings = check_dns_capabilities_enhanced()
        if dns_findings:
            results["findings"].extend(dns_findings)

        # Check alternative protocols
        protocol_findings = check_alternative_protocols_enhanced()
        if protocol_findings:
            results["findings"].extend(protocol_findings)

        # Check monitoring and detection
        monitoring_findings = check_monitoring_enhanced()
        if monitoring_findings:
            results["findings"].extend(monitoring_findings)

    except Exception as e:
        results["error"] = str(e)

    return results


def check_network_connectivity_enhanced():
    """Enhanced network connectivity testing with comprehensive protocol verification"""
    findings = []

    try:
        # Test standard HTTP/HTTPS ports with multi-method verification
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
                f"Standard C2 ports accessible: {len(open_ports)}",
                f"Outbound connectivity available on common C2 ports: {', '.join(open_ports)}. "
                f"These ports are commonly used by C2 frameworks (Cobalt Strike, Metasploit, Empire) "
                f"and are often allowed by firewalls, making them ideal for C2 communication.",
                "Implement egress filtering and DPI to inspect traffic on these ports",
                confidence,
                True
            ))

        # Test non-standard ports commonly used by C2
        non_standard_ports = [
            (53, 'DNS', 'Can be used for DNS tunneling C2'),
            (123, 'NTP', 'Network Time Protocol - covert channel'),
            (445, 'SMB', 'Windows file sharing - lateral movement'),
            (3389, 'RDP', 'Remote Desktop - used by some C2'),
            (5985, 'WinRM', 'Windows Remote Management'),
            (9001, 'Tor', 'Tor network default port'),
            (4444, 'Metasploit', 'Default Metasploit listener port'),
            (50050, 'Cobalt Strike', 'Common Cobalt Strike port')
        ]

        accessible_nonstandard = []
        nonstandard_tests = []

        for port, protocol, description in non_standard_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('8.8.8.8', port))
                sock.close()

                if result == 0:
                    accessible_nonstandard.append(f"{protocol} (port {port})")
                    nonstandard_tests.append(True)

                    findings.append(create_finding(
                        "medium",
                        f"Non-standard C2 port accessible: {protocol} (port {port})",
                        f"Port {port} ({protocol}) is accessible. {description}. "
                        f"This port can be used for covert C2 communication.",
                        f"Block or monitor traffic on port {port}; investigate legitimate use cases",
                        95,
                        True
                    ))
                else:
                    nonstandard_tests.append(False)
            except Exception:
                nonstandard_tests.append(False)

        # Test ICMP for C2 channel (some C2 frameworks support ICMP tunneling)
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
                    "ICMP protocol available for C2",
                    "ICMP echo (ping) is functional. Some C2 frameworks (e.g., ICMPsh, Ping Tunnel) "
                    "use ICMP for covert communication channels. ICMP tunneling is stealthy and "
                    "often bypasses firewalls.",
                    "Monitor ICMP traffic for unusual patterns (large payloads, high frequency)",
                    100,
                    True
                ))
        except Exception:
            pass

        # Overall connectivity assessment
        total_methods = len(port_tests) + len(nonstandard_tests)
        if total_methods == 0 or not findings:
            findings.append(create_finding(
                "low",
                "Limited outbound connectivity detected",
                "No standard C2 communication channels are accessible. Network egress is heavily restricted.",
                "Continue enforcing strict egress filtering",
                50,
                False
            ))

    except Exception:
        pass

    return findings


def check_proxy_config_enhanced():
    """Enhanced proxy configuration detection with OS-specific checks"""
    findings = []

    try:
        # Method 1: Check environment variables
        proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'ALL_PROXY', 'NO_PROXY']
        configured_proxies = []
        methods = []

        for var in proxy_vars:
            if var in os.environ:
                configured_proxies.append(f"{var}={os.environ[var]}")
                methods.append(True)

        # Method 2: Check system proxy configuration files
        proxy_files = []

        if common_utils.is_linux() or common_utils.is_macos():
            proxy_locations = [
                '/etc/environment',
                '~/.bash_profile',
                '~/.bashrc',
                '~/.zshrc',
                '/etc/profile'
            ]

            for proxy_file in proxy_locations:
                expanded = os.path.expanduser(proxy_file)
                if os.path.exists(expanded):
                    try:
                        with open(expanded, 'r') as f:
                            content = f.read()
                            if 'proxy' in content.lower():
                                proxy_files.append(expanded)
                                methods.append(True)
                    except Exception:
                        methods.append(False)

        elif common_utils.is_windows():
            # Check Windows registry for proxy settings (simplified)
            try:
                result = subprocess.run(
                    ['reg', 'query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', '/v', 'ProxyServer'],
                    capture_output=True,
                    text=True,
                    timeout=3
                )

                if result.returncode == 0 and 'ProxyServer' in result.stdout:
                    proxy_line = [line for line in result.stdout.split('\n') if 'ProxyServer' in line]
                    if proxy_line:
                        configured_proxies.append(f"Windows Registry: {proxy_line[0].strip()}")
                        methods.append(True)
            except Exception:
                methods.append(False)

        if configured_proxies or proxy_files:
            confidence = common_utils.calculate_confidence_score(*methods) if methods else 90

            proxy_details = []
            if configured_proxies:
                proxy_details.append(f"Environment variables: {', '.join(configured_proxies[:3])}")
            if proxy_files:
                proxy_details.append(f"Configuration files: {', '.join(proxy_files[:3])}")

            findings.append(create_finding(
                "medium",
                "Proxy configuration detected",
                f"System is configured to use proxy servers:\n{chr(10).join(proxy_details)}\n\n"
                f"C2 traffic can be tunneled through the proxy to blend with legitimate traffic. "
                f"This makes C2 communication harder to detect and block.",
                "Monitor proxy logs for suspicious traffic patterns; implement SSL inspection",
                confidence,
                True
            ))
        else:
            findings.append(create_finding(
                "info",
                "No proxy configuration detected",
                "System appears to use direct internet access without proxy. "
                "C2 traffic will be directly observable on network perimeter.",
                "Direct connections are easier to monitor and block",
                80,
                True
            ))

    except Exception:
        pass

    return findings


def check_dns_capabilities_enhanced():
    """Enhanced DNS capabilities assessment for DNS-based C2"""
    findings = []

    try:
        methods = []

        # Method 1: Test DNS resolution
        try:
            test_domain = 'google.com'
            resolved_ip = socket.gethostbyname(test_domain)
            methods.append(True)

            findings.append(create_finding(
                "high",
                "DNS resolution available - DNS-based C2 possible",
                f"System can resolve external domains (test: {test_domain} -> {resolved_ip}). "
                f"DNS queries can be used for C2 communication via DNS tunneling. "
                f"C2 frameworks that support DNS: Cobalt Strike, DNSCat2, Iodine, dnscat2. "
                f"DNS tunneling encodes data in DNS queries/responses and is highly stealthy.",
                "Monitor DNS queries for suspicious patterns: long hostnames, high query frequency to single domains, unusual TXT record queries",
                100,
                True
            ))
        except Exception:
            methods.append(False)
            findings.append(create_finding(
                "info",
                "DNS resolution failed",
                "Cannot resolve external domains. DNS-based C2 channels are not viable.",
                "Limited DNS capabilities restrict C2 options",
                100,
                True
            ))

        # Method 2: Identify DNS servers
        dns_servers = []

        if common_utils.is_linux() or common_utils.is_macos():
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            server = line.split()[1]
                            dns_servers.append(server)
                    methods.append(True)
            except Exception:
                methods.append(False)

        elif common_utils.is_windows():
            try:
                result = subprocess.run(
                    ['ipconfig', '/all'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'DNS Servers' in line:
                            # Parse DNS server IPs (simplified)
                            parts = line.split(':')
                            if len(parts) > 1:
                                dns_servers.append(parts[1].strip())
                    methods.append(True)
            except Exception:
                methods.append(False)

        if dns_servers:
            findings.append(create_finding(
                "info",
                f"DNS servers identified: {len(dns_servers)}",
                f"System uses these DNS servers: {', '.join(dns_servers[:5])}. "
                f"All DNS queries (including C2 traffic) will be routed through these servers.",
                "Monitor DNS server logs for anomalous queries",
                95,
                True
            ))

        # Method 3: Check for DNS tools (useful for C2 operators)
        dns_tools = [
            ('dig', 'dig (DNS query tool)'),
            ('nslookup', 'nslookup'),
            ('host', 'host'),
            ('drill', 'drill (DNS tool)')
        ]

        available_dns_tools = []
        for tool, name in dns_tools:
            exists, confidence, path = common_utils.verify_command_exists(tool)
            if exists:
                available_dns_tools.append(name)

        if available_dns_tools:
            findings.append(create_finding(
                "medium",
                f"DNS query tools available: {len(available_dns_tools)}",
                f"DNS tools detected: {', '.join(available_dns_tools)}. "
                f"These tools can be used to test and implement DNS-based C2 channels.",
                "Monitor usage of DNS tools for suspicious query patterns",
                90,
                True
            ))

    except Exception:
        pass

    return findings


def check_alternative_protocols_enhanced():
    """Enhanced alternative protocol detection for C2 channels"""
    findings = []

    try:
        # Check for SSH (tunneling and C2 channel)
        ssh_exists, ssh_confidence, ssh_path = common_utils.verify_command_exists('ssh')
        if ssh_exists:
            findings.append(create_finding(
                "medium",
                f"SSH client available: {ssh_path}",
                "SSH client can establish encrypted C2 channels and tunnels. "
                "SSH is commonly used for: reverse tunnels, SOCKS proxies, port forwarding. "
                "C2 frameworks can tunnel traffic through SSH to evade detection.",
                "Monitor SSH connections to external hosts; implement SSH bastion architecture",
                ssh_confidence,
                True
            ))

        # Check for TLS/SSL tools
        tls_tools = [
            ('openssl', 'OpenSSL'),
            ('gnutls-cli', 'GnuTLS'),
            ('s_client', 's_client')
        ]

        detected_tls = []
        for tool, name in tls_tools:
            exists, confidence, path = common_utils.verify_command_exists(tool)
            if exists:
                detected_tls.append(f"{name} ({path})")
                break  # Only report once

        if detected_tls:
            findings.append(create_finding(
                "medium",
                f"TLS/SSL tools available: {detected_tls[0]}",
                "TLS tools can establish encrypted C2 connections. "
                "TLS encryption makes C2 traffic analysis difficult. "
                "Many C2 frameworks use TLS for command channels (Cobalt Strike, Sliver, etc.).",
                "Implement SSL/TLS inspection; monitor certificate anomalies",
                90,
                True
            ))

        # Check for scripting languages (custom C2 implementation)
        script_langs = [
            ('python', 'Python'),
            ('python3', 'Python3'),
            ('perl', 'Perl'),
            ('ruby', 'Ruby'),
            ('node', 'Node.js'),
            ('php', 'PHP'),
            ('bash', 'Bash'),
            ('powershell', 'PowerShell')
        ]

        available_langs = []
        for cmd, name in script_langs:
            exists, confidence, path = common_utils.verify_command_exists(cmd)
            if exists:
                available_langs.append(name)

        if available_langs:
            findings.append(create_finding(
                "high",
                f"Scripting languages for custom C2: {len(available_langs)} available",
                f"Detected: {', '.join(available_langs)}. "
                f"Scripting languages enable implementation of custom C2 protocols and agents. "
                f"Attackers can write lightweight C2 agents in these languages to evade detection. "
                f"Python is particularly popular for C2 due to its extensive networking libraries.",
                "Monitor script execution; implement application whitelisting; use EDR solutions",
                85,
                True
            ))

        # Check for netcat/socat (swiss army knife of networking)
        netcat_variants = [
            ('nc', 'netcat'),
            ('ncat', 'ncat (Nmap netcat)'),
            ('netcat', 'netcat'),
            ('socat', 'socat')
        ]

        detected_netcat = []
        for cmd, name in netcat_variants:
            exists, confidence, path = common_utils.verify_command_exists(cmd)
            if exists:
                detected_netcat.append(f"{name} ({path})")

        if detected_netcat:
            findings.append(create_finding(
                "high",
                f"Network utility tools detected: {len(detected_netcat)}",
                f"Tools: {', '.join(detected_netcat)}. "
                f"These tools can create reverse shells, bind shells, and proxy connections. "
                f"Commonly used in manual C2 operations and as fallback communication channels.",
                "Monitor netcat/socat usage; restrict with AppArmor/SELinux",
                95,
                True
            ))

        # Check for curl/wget (HTTP-based C2)
        http_tools = []
        for tool in ['curl', 'wget']:
            exists, confidence, path = common_utils.verify_command_exists(tool)
            if exists:
                http_tools.append(f"{tool} ({path})")

        if http_tools:
            findings.append(create_finding(
                "medium",
                f"HTTP client tools available: {', '.join(http_tools)}",
                "curl/wget can be used for HTTP-based C2 communication. "
                "Simple beacon scripts can use these tools to check in with C2 servers.",
                "Monitor curl/wget usage to external IPs; check for scheduled tasks using these tools",
                90,
                True
            ))

    except Exception:
        pass

    return findings


def check_monitoring_enhanced():
    """Enhanced network monitoring detection"""
    findings = []

    try:
        # Check for network monitoring tools
        monitoring_tools = [
            ('tcpdump', 'tcpdump', 'Packet capture'),
            ('wireshark', 'Wireshark', 'Packet analyzer'),
            ('tshark', 'TShark', 'Wireshark CLI'),
            ('snort', 'Snort', 'IDS/IPS'),
            ('suricata', 'Suricata', 'IDS/IPS'),
            ('zeek', 'Zeek/Bro', 'Network security monitor'),
            ('bro', 'Bro', 'Network security monitor'),
            ('ossec', 'OSSEC', 'Host IDS')
        ]

        detected_monitors = []
        tool_descriptions = []

        for cmd, name, description in monitoring_tools:
            exists, confidence, path = common_utils.verify_command_exists(cmd)
            if exists:
                detected_monitors.append(name)
                tool_descriptions.append(f"{name} ({description})")

        if detected_monitors:
            findings.append(create_finding(
                "high",
                f"Network monitoring tools detected: {len(detected_monitors)}",
                f"Security monitoring tools installed:\n" + "\n".join(f"- {desc}" for desc in tool_descriptions) +
                f"\n\nThese tools can detect C2 traffic patterns. "
                f"C2 operators must use stealthy communication methods and protocols to avoid detection.",
                "Ensure monitoring tools are properly configured and alerts are actively reviewed",
                95,
                True
            ))
        else:
            findings.append(create_finding(
                "info",
                "No network monitoring tools detected",
                "No common network monitoring or IDS/IPS tools found. "
                "C2 traffic is less likely to be actively monitored or detected.",
                "Consider deploying network monitoring solutions (Suricata, Zeek, etc.)",
                90,
                True
            ))

        # Check for running monitoring processes
        try:
            import psutil

            monitoring_procs = []
            monitor_keywords = ['tcpdump', 'wireshark', 'tshark', 'snort', 'suricata', 'zeek', 'bro']

            for proc in psutil.process_iter(['name', 'cmdline']):
                try:
                    proc_name = proc.info['name'].lower()

                    if any(keyword in proc_name for keyword in monitor_keywords):
                        monitoring_procs.append(proc.info['name'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if monitoring_procs:
                # Remove duplicates
                monitoring_procs = list(set(monitoring_procs))

                findings.append(create_finding(
                    "critical",
                    f"Active network monitoring detected: {len(monitoring_procs)} processes",
                    f"Network traffic is being actively monitored by: {', '.join(monitoring_procs)}. "
                    f"All network traffic, including C2 communications, may be captured and analyzed. "
                    f"Use encrypted protocols and domain fronting to evade detection.",
                    "Continue active monitoring; implement automated alerting for suspicious patterns",
                    100,
                    True
                ))

        except ImportError:
            pass

        # Check for EDR/AV solutions
        if common_utils.is_windows():
            edr_solutions = [
                'MsMpEng.exe',  # Windows Defender
                'CylanceSvc.exe',  # Cylance
                'CSFalconService.exe',  # CrowdStrike
                'SentinelAgent.exe',  # SentinelOne
                'cb.exe'  # Carbon Black
            ]

            detected_edr = []
            try:
                import psutil
                for proc in psutil.process_iter(['name']):
                    try:
                        if proc.info['name'] in edr_solutions:
                            detected_edr.append(proc.info['name'])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                if detected_edr:
                    findings.append(create_finding(
                        "critical",
                        f"EDR/AV solutions active: {len(detected_edr)}",
                        f"Endpoint security detected: {', '.join(set(detected_edr))}. "
                        f"These solutions provide behavioral analysis and can detect C2 activity.",
                        "EDR is providing protection against C2 implants",
                        100,
                        True
                    ))
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
