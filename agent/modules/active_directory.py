"""
Active Directory Assessment Module - COMPREHENSIVE
Specialized module for Active Directory enumeration and attack path discovery
Covers: Kerberos attacks, delegation abuse, trust exploitation, credential attacks
"""

import os
import platform
import subprocess
import socket
import re
from . import common_utils


def create_finding(severity, finding, description, remediation, confidence=100, verified=True):
    """Create a standardized finding"""
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
    Comprehensive Active Directory security assessment
    """
    results = {
        "module": "active_directory",
        "platform": platform.system(),
        "findings": []
    }

    try:
        # Check if system is domain-joined
        if not is_domain_joined():
            results["findings"].append(create_finding(
                "info",
                "System is not domain-joined",
                "This system is not part of an Active Directory domain. AD-specific checks skipped.",
                "N/A - Not applicable for standalone systems",
                100,
                True
            ))
            return results

        # 1. Domain enumeration
        domain_findings = enumerate_domain()
        if domain_findings:
            results["findings"].extend(domain_findings)

        # 2. Kerberos attack opportunities
        kerberos_findings = check_kerberos_attacks()
        if kerberos_findings:
            results["findings"].extend(kerberos_findings)

        # 3. Delegation abuse opportunities
        delegation_findings = check_delegation_abuse()
        if delegation_findings:
            results["findings"].extend(delegation_findings)

        # 4. LDAP enumeration
        ldap_findings = enumerate_ldap()
        if ldap_findings:
            results["findings"].extend(ldap_findings)

        # 5. Trust relationships
        trust_findings = check_trust_relationships()
        if trust_findings:
            results["findings"].extend(trust_findings)

        # 6. GPO abuse opportunities
        gpo_findings = check_gpo_abuse()
        if gpo_findings:
            results["findings"].extend(gpo_findings)

        # 7. NTLM relay opportunities
        ntlm_findings = check_ntlm_relay()
        if ntlm_findings:
            results["findings"].extend(ntlm_findings)

        # 8. Domain admin hunting
        admin_findings = hunt_domain_admins()
        if admin_findings:
            results["findings"].extend(admin_findings)

        # 9. Certificate Services abuse
        cert_findings = check_certificate_services()
        if cert_findings:
            results["findings"].extend(cert_findings)

    except Exception as e:
        results["error"] = str(e)

    return results


def is_domain_joined():
    """Check if system is domain-joined"""
    try:
        if common_utils.is_windows():
            # Check if part of domain
            result = subprocess.run(
                ['systeminfo'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout.lower()
                if 'domain:' in output and 'workgroup' not in output:
                    return True

        elif common_utils.is_linux():
            # Check for domain membership
            checks = [
                os.path.exists('/etc/krb5.keytab'),
                os.path.exists('/etc/sssd/sssd.conf'),
                os.path.exists('/etc/samba/smb.conf')
            ]

            if any(checks):
                return True

            # Check realm membership
            result = subprocess.run(
                ['realm', 'list'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0 and result.stdout.strip():
                return True

    except Exception:
        pass

    return False


def enumerate_domain():
    """Enumerate domain information"""
    findings = []

    try:
        if common_utils.is_windows():
            # Get domain info
            result = subprocess.run(
                ['systeminfo'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout

                # Extract domain name
                domain_match = re.search(r'Domain:\s+(.+)', output)
                if domain_match:
                    domain_name = domain_match.group(1).strip()

                    findings.append(create_finding(
                        "info",
                        f"Domain-joined system: {domain_name}",
                        f"System is member of Active Directory domain: {domain_name}. "
                        f"This enables AD-specific attack paths including Kerberos attacks, "
                        f"lateral movement, and privilege escalation via domain credentials.",
                        "Review domain security posture and apply least-privilege principles",
                        100,
                        True
                    ))

            # Get domain controller
            result = subprocess.run(
                ['nltest', '/dsgetdc:'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                dc_match = re.search(r'DC:\s+\\\\(.+)', result.stdout)
                if dc_match:
                    dc_name = dc_match.group(1).strip()

                    findings.append(create_finding(
                        "medium",
                        f"Domain Controller accessible: {dc_name}",
                        f"Domain Controller {dc_name} is accessible from this system. "
                        f"This is a high-value target for privilege escalation and lateral movement. "
                        f"DCSync, Zerologon, and other DC-specific attacks may be possible.",
                        "Implement network segmentation to limit DC access; enable advanced DC security features",
                        95,
                        True
                    ))

        elif common_utils.is_linux():
            # Check Kerberos configuration
            if os.path.exists('/etc/krb5.conf'):
                try:
                    with open('/etc/krb5.conf', 'r') as f:
                        content = f.read()

                        realm_match = re.search(r'default_realm\s*=\s*(\S+)', content)
                        if realm_match:
                            realm = realm_match.group(1)

                            findings.append(create_finding(
                                "info",
                                f"Kerberos realm configured: {realm}",
                                f"System is configured for Kerberos authentication to realm {realm}. "
                                f"Kerberos tickets may be available for credential theft and replay attacks.",
                                "Secure Kerberos configuration and monitor ticket usage",
                                100,
                                True
                            ))
                except:
                    pass

    except Exception:
        pass

    return findings


def check_kerberos_attacks():
    """Check for Kerberos attack opportunities"""
    findings = []

    try:
        if common_utils.is_windows():
            # Check for Kerberos tickets in memory
            result = subprocess.run(
                ['klist'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0 and 'Cached Tickets' in result.stdout:
                ticket_count = result.stdout.count('Server:')

                if ticket_count > 0:
                    findings.append(create_finding(
                        "high",
                        f"Kerberos tickets in memory: {ticket_count} ticket(s)",
                        f"Found {ticket_count} cached Kerberos ticket(s) in memory. "
                        f"These tickets can be extracted and used for: "
                        f"Pass-the-Ticket attacks, credential theft, lateral movement. "
                        f"If TGT is present, attacker can request service tickets for any SPN.",
                        "Implement Credential Guard; reduce ticket lifetime; monitor for suspicious Kerberos activity",
                        100,
                        True
                    ))

            # Check for AS-REP Roasting opportunity
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and result.stdout.strip():
                findings.append(create_finding(
                    "critical",
                    "AS-REP Roasting possible: Users without Kerberos pre-authentication",
                    "Found user accounts with 'Do not require Kerberos preauthentication' enabled. "
                    "Attackers can request AS-REP responses for these accounts without authentication "
                    "and crack them offline to obtain passwords. This is AS-REP Roasting attack.",
                    "Remove 'Do not require Kerberos preauthentication' flag from all user accounts",
                    90,
                    False
                ))

            # Check for SPN accounts (Kerberoasting targets)
            result = subprocess.run(
                ['setspn', '-Q', '*/*'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                spn_count = result.stdout.count('CN=')

                if spn_count > 0:
                    findings.append(create_finding(
                        "high",
                        f"Service Principal Names (SPNs) found: {spn_count} accounts",
                        f"Found {spn_count} accounts with Service Principal Names (SPNs). "
                        f"These accounts are vulnerable to Kerberoasting attacks where "
                        f"attackers can request service tickets and crack them offline to obtain passwords. "
                        f"Service accounts often have high privileges.",
                        "Use managed service accounts (gMSA); require AES encryption; monitor for TGS-REQ anomalies",
                        85,
                        True
                    ))

        elif common_utils.is_linux():
            # Check for cached Kerberos tickets
            ccache_locations = [
                '/tmp/krb5cc_*',
                f'/tmp/krb5cc_{os.getuid()}',
                os.path.expanduser('~/.krb5/cache')
            ]

            found_tickets = []
            for location in ccache_locations:
                import glob
                for ticket_file in glob.glob(location):
                    if os.path.exists(ticket_file) and os.access(ticket_file, os.R_OK):
                        found_tickets.append(ticket_file)

            if found_tickets:
                findings.append(create_finding(
                    "high",
                    f"Kerberos ticket cache files accessible: {len(found_tickets)} file(s)",
                    f"Found {len(found_tickets)} Kerberos credential cache file(s): {', '.join(found_tickets[:3])}. "
                    f"These tickets can be extracted and used for Pass-the-Ticket attacks and lateral movement.",
                    "Secure ticket cache files with proper permissions; reduce ticket lifetime",
                    100,
                    True
                ))

    except Exception:
        pass

    return findings


def check_delegation_abuse():
    """Check for delegation abuse opportunities"""
    findings = []

    try:
        if common_utils.is_windows():
            # Check for unconstrained delegation
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and result.stdout.strip():
                findings.append(create_finding(
                    "critical",
                    "Unconstrained delegation enabled on computer accounts",
                    "Found computer accounts with unconstrained delegation enabled. "
                    "When users authenticate to these systems, their TGTs are cached. "
                    "Attackers with access to these systems can extract TGTs and impersonate any user, "
                    "including Domain Admins. This is a critical privilege escalation path.",
                    "Remove unconstrained delegation; use constrained or resource-based constrained delegation instead",
                    90,
                    False
                ))

            # Check for constrained delegation
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and result.stdout.strip():
                findings.append(create_finding(
                    "high",
                    "Constrained delegation configured",
                    "Found accounts with constrained delegation configured. "
                    "If compromised, attackers can impersonate any user to specific services. "
                    "This can enable lateral movement and privilege escalation.",
                    "Review and minimize delegation configurations; use resource-based constrained delegation",
                    85,
                    False
                ))

            # Check for resource-based constrained delegation
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -ne "$null"} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and result.stdout.strip():
                findings.append(create_finding(
                    "high",
                    "Resource-based constrained delegation (RBCD) configured",
                    "Found computers with resource-based constrained delegation. "
                    "If attackers can modify msDS-AllowedToActOnBehalfOfOtherIdentity attribute, "
                    "they can configure RBCD for privilege escalation. This is exploitable via WriteDACL rights.",
                    "Monitor for changes to msDS-AllowedToActOnBehalfOfOtherIdentity; implement least privilege",
                    85,
                    False
                ))

    except Exception:
        pass

    return findings


def enumerate_ldap():
    """Enumerate LDAP for sensitive information"""
    findings = []

    try:
        if common_utils.is_windows():
            # Check for LDAP signing requirement
            result = subprocess.run(
                ['reg', 'query', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters', '/v', 'LDAPServerIntegrity'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0 or 'LDAPServerIntegrity' not in result.stdout:
                findings.append(create_finding(
                    "high",
                    "LDAP signing not enforced",
                    "LDAP signing is not required on this domain. "
                    "Attackers can perform man-in-the-middle attacks against LDAP traffic, "
                    "including NTLM relay attacks to escalate privileges. "
                    "Combined with NTLM authentication, this enables relay to LDAPS.",
                    "Enable LDAP signing on all domain controllers; configure 'Domain controller: LDAP server signing requirements' to 'Require signature'",
                    90,
                    True
                ))

            # Check for LDAP channel binding
            result = subprocess.run(
                ['reg', 'query', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters', '/v', 'LdapEnforceChannelBinding'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0 or 'LdapEnforceChannelBinding' not in result.stdout:
                findings.append(create_finding(
                    "medium",
                    "LDAP channel binding not enforced",
                    "LDAP channel binding is not enabled. This allows NTLM relay attacks "
                    "even when LDAP signing is enforced. Attackers can relay NTLM authentication "
                    "to perform unauthorized LDAP operations.",
                    "Enable LDAP channel binding on all domain controllers",
                    85,
                    True
                ))

    except Exception:
        pass

    return findings


def check_trust_relationships():
    """Check domain trust relationships"""
    findings = []

    try:
        if common_utils.is_windows():
            # Enumerate domain trusts
            result = subprocess.run(
                ['nltest', '/domain_trusts'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                trusts = result.stdout.count('Flags:')

                if trusts > 0:
                    findings.append(create_finding(
                        "medium",
                        f"Domain trust relationships detected: {trusts} trust(s)",
                        f"Found {trusts} domain trust relationship(s). Trust relationships can be exploited "
                        f"for lateral movement between domains. Attackers can abuse: "
                        f"SID history injection, inter-forest TGT delegation, and trust key compromise. "
                        f"Bidirectional trusts are especially risky.",
                        "Review and minimize trust relationships; use SID filtering; monitor cross-domain activity",
                        80,
                        True
                    ))

                    # Check for forest trusts
                    if 'FOREST' in result.stdout.upper():
                        findings.append(create_finding(
                            "high",
                            "Forest trust relationship detected",
                            "Forest trust detected. Forest trusts enable access across entire forests. "
                            "If one domain in the forest is compromised, attackers can potentially "
                            "compromise the entire forest through trust exploitation.",
                            "Implement selective authentication for forest trusts; use SID filtering",
                            85,
                            True
                        ))

    except Exception:
        pass

    return findings


def check_gpo_abuse():
    """Check for GPO abuse opportunities"""
    findings = []

    try:
        if common_utils.is_windows():
            # Check if user can modify GPOs
            result = subprocess.run(
                ['gpresult', '/R'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                gpo_count = result.stdout.count('GPO:')

                if gpo_count > 0:
                    findings.append(create_finding(
                        "info",
                        f"Group Policy Objects applied: {gpo_count} GPO(s)",
                        f"System has {gpo_count} GPOs applied. If attacker gains write access to GPOs, "
                        f"they can deploy malicious configurations, create scheduled tasks, "
                        f"modify startup scripts, and achieve domain-wide code execution. "
                        f"This is a common privilege escalation and persistence mechanism.",
                        "Implement least privilege for GPO modification; monitor GPO changes; use LAPS for local admin passwords",
                        75,
                        True
                    ))

    except Exception:
        pass

    return findings


def check_ntlm_relay():
    """Check for NTLM relay opportunities"""
    findings = []

    try:
        if common_utils.is_windows():
            # Check SMB signing requirement
            result = subprocess.run(
                ['reg', 'query', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters', '/v', 'RequireSecuritySignature'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if 'RequireSecuritySignature' in result.stdout:
                if 'REG_DWORD' in result.stdout and '0x0' in result.stdout:
                    findings.append(create_finding(
                        "critical",
                        "SMB signing not required",
                        "SMB signing is not required on this system. Attackers can perform NTLM relay attacks "
                        "by relaying authentication to this system or from this system to other services. "
                        "Combined with lack of LDAP signing, this enables privilege escalation to Domain Admin. "
                        "This is exploited in attacks like PetitPotam and PrinterBug.",
                        "Enable SMB signing: 'Microsoft network server: Digitally sign communications (always)'",
                        100,
                        True
                    ))

            # Check for IPv6 enabled (for MITM attacks)
            result = subprocess.run(
                ['powershell', '-Command', 'Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object {$_.Enabled -eq $true}'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0 and result.stdout.strip():
                findings.append(create_finding(
                    "medium",
                    "IPv6 enabled on network adapters",
                    "IPv6 is enabled. Attackers can perform MITM attacks via rogue IPv6 DNS "
                    "to capture NTLM authentication and relay it. Tools like mitm6 exploit this. "
                    "Combined with NTLM relay, this can lead to domain compromise.",
                    "Disable IPv6 if not used; implement IPv6 security controls if required",
                    80,
                    True
                ))

    except Exception:
        pass

    return findings


def hunt_domain_admins():
    """Hunt for Domain Admin sessions"""
    findings = []

    try:
        if common_utils.is_windows():
            # Check for Domain Admin processes
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-WmiObject Win32_Process | Select-Object Name,ProcessId,@{l="UserName";e={$_.GetOwner().Domain+"\\"+$_.GetOwner().User}}'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout.lower()

                if 'domain admins' in output or 'administrator' in output:
                    findings.append(create_finding(
                        "critical",
                        "Privileged user session detected on system",
                        "Found processes running under privileged domain accounts. "
                        "If these credentials are in memory, attackers can extract them using: "
                        "Mimikatz, ProcDump+Mimikatz, or live memory analysis. "
                        "This enables immediate privilege escalation to Domain Admin.",
                        "Implement Credential Guard; use admin workstations; restrict DA logons to DCs only",
                        90,
                        True
                    ))

    except Exception:
        pass

    return findings


def check_certificate_services():
    """Check for AD Certificate Services vulnerabilities"""
    findings = []

    try:
        if common_utils.is_windows():
            # Check for ADCS
            result = subprocess.run(
                ['certutil', '-config', '-'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0 and 'Server' in result.stdout:
                findings.append(create_finding(
                    "high",
                    "Active Directory Certificate Services (ADCS) detected",
                    "AD Certificate Services is present in the domain. ADCS can be exploited via: "
                    "ESC1-ESC8 privilege escalation techniques (Certified Pre-Owned attacks), "
                    "certificate template abuse, web enrollment attacks (PetitPotam + ADCS), "
                    "and NTLM relay to certificate enrollment endpoints.",
                    "Review certificate templates; disable NTLM on web enrollment; implement enrollment restrictions",
                    85,
                    True
                ))

            # Check for web enrollment
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-Service | Where-Object {$_.Name -like "*CertSvc*"}'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0 and 'certsvc' in result.stdout.lower():
                findings.append(create_finding(
                    "high",
                    "Certificate Services running on this system",
                    "This system runs Certificate Services. It may be vulnerable to: "
                    "NTLM relay attacks (PetitPotam), certificate template abuse, "
                    "and ESC escalation techniques. Web enrollment interface is a common target.",
                    "Disable NTLM authentication on CA web enrollment; enable EPA; review template permissions",
                    90,
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
