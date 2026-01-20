"""
Risk Scoring and OPSEC Analysis System
Provides intelligent risk/noise scoring and stealth recommendations
"""

import re
from typing import Dict, List, Any, Tuple


class RiskScorer:
    """
    Analyzes findings and assigns risk/noise scores for intelligent decision-making
    """

    # Detection likelihood scores
    DETECTION_SCORES = {
        'kernel_exploit': 90,
        'lsass_access': 85,
        'dll_injection': 80,
        'process_injection': 80,
        'wmi_execution': 70,
        'scheduled_task': 60,
        'registry_modification': 50,
        'file_creation': 40,
        'enumeration': 20,
        'passive_recon': 5
    }

    # Security control indicators
    EDR_INDICATORS = [
        'crowdstrike', 'carbon black', 'sentinel', 'defender atp',
        'cortex xdr', 'cylance', 'sophos', 'trellix', 'edr'
    ]

    AV_INDICATORS = [
        'windows defender', 'mcafee', 'symantec', 'norton',
        'kaspersky', 'avg', 'avast', 'malwarebytes'
    ]

    SIEM_INDICATORS = [
        'splunk', 'elk', 'sentinel', 'qradar', 'sumologic',
        'log forwarding', 'syslog', 'eventlog forwarding'
    ]

    def __init__(self):
        self.environment_context = {
            'has_edr': False,
            'has_av': False,
            'has_siem': False,
            'is_domain_joined': False,
            'privilege_level': 'user',
            'os_hardening': 'unknown',
            'network_monitoring': 'unknown'
        }

    def analyze_environment(self, reconnaissance_results: Dict) -> Dict:
        """
        Analyze recon results to understand the security posture

        Returns environment context for risk calculation
        """
        findings = reconnaissance_results.get('findings', [])

        context = self.environment_context.copy()

        for finding in findings:
            description = finding.get('description', '').lower()
            finding_text = finding.get('finding', '').lower()

            # Check for security controls
            if any(edr in description or edr in finding_text for edr in self.EDR_INDICATORS):
                context['has_edr'] = True

            if any(av in description or av in finding_text for av in self.AV_INDICATORS):
                context['has_av'] = True

            if any(siem in description or siem in finding_text for siem in self.SIEM_INDICATORS):
                context['has_siem'] = True

            # Check domain membership
            if 'domain' in description and 'joined' in description:
                context['is_domain_joined'] = True

            # Check privilege level
            if 'administrator' in description or 'root' in description or 'system' in description:
                context['privilege_level'] = 'admin'
            elif 'sudo' in description or 'local admin' in description:
                context['privilege_level'] = 'elevated'

        self.environment_context = context
        return context

    def score_finding(self, finding: Dict, module: str) -> Dict:
        """
        Score a single finding for risk and noise

        Returns enhanced finding with risk scores
        """
        severity = finding.get('severity', 'info')
        description = finding.get('description', '').lower()

        # Base impact score by severity
        impact_scores = {
            'critical': 100,
            'high': 80,
            'medium': 50,
            'low': 30,
            'info': 10
        }

        impact = impact_scores.get(severity, 50)

        # Calculate noise/detection risk
        noise = self._calculate_noise_score(finding, module)

        # Calculate feasibility
        feasibility = self._calculate_feasibility(finding, module)

        # Calculate stealth rating
        stealth = 100 - noise

        # Generate recommendation
        recommendation = self._generate_recommendation(finding, module, impact, noise, feasibility)

        # Add risk metadata
        finding['risk_analysis'] = {
            'impact_score': impact,
            'noise_score': noise,
            'feasibility_score': feasibility,
            'stealth_score': stealth,
            'detection_likelihood': self._get_detection_likelihood(noise),
            'recommendation': recommendation,
            'requires_privileges': self._requires_elevated_privileges(finding),
            'opsec_safe': stealth >= 60
        }

        return finding

    def _calculate_noise_score(self, finding: Dict, module: str) -> int:
        """Calculate how noisy/detectable an action would be"""
        base_noise = 30  # Default moderate noise

        description = finding.get('description', '').lower()
        finding_text = finding.get('finding', '').lower()

        # Module-specific base noise
        module_noise = {
            'reconnaissance': 15,
            'credential_access': 60,
            'privilege_escalation': 75,
            'persistence': 65,
            'lateral_movement': 70,
            'exfiltration': 50,
            'cleanup': 40
        }

        base_noise = module_noise.get(module, 30)

        # Adjust based on environment
        if self.environment_context['has_edr']:
            base_noise += 25
        if self.environment_context['has_siem']:
            base_noise += 15

        # Technique-specific adjustments
        if 'kernel' in description or 'driver' in description:
            base_noise += 30
        if 'lsass' in description or 'memory dump' in description:
            base_noise += 25
        if 'injection' in description:
            base_noise += 20
        if 'scheduled task' in description or 'service' in description:
            base_noise += 15
        if 'registry' in description:
            base_noise += 10
        if 'enumeration' in description or 'passive' in description:
            base_noise -= 10

        # File operations on sensitive paths
        if any(path in description for path in ['/etc/shadow', 'sam', 'system32', 'sysvol']):
            base_noise += 20

        return min(100, max(0, base_noise))

    def _calculate_feasibility(self, finding: Dict, module: str) -> int:
        """Calculate how feasible exploitation is"""
        base_feasibility = 70

        description = finding.get('description', '').lower()
        severity = finding.get('severity', 'info')

        # Higher severity = higher feasibility
        severity_boost = {
            'critical': 20,
            'high': 10,
            'medium': 0,
            'low': -10,
            'info': -20
        }
        base_feasibility += severity_boost.get(severity, 0)

        # Check privilege requirements
        current_priv = self.environment_context['privilege_level']

        if 'requires admin' in description or 'requires root' in description:
            if current_priv == 'user':
                base_feasibility -= 40
            elif current_priv == 'elevated':
                base_feasibility -= 20

        # Check for verification
        if finding.get('verified', False):
            base_feasibility += 15

        confidence = finding.get('confidence_score', 80)
        if confidence >= 95:
            base_feasibility += 10
        elif confidence < 70:
            base_feasibility -= 15

        # Security controls impact
        if self.environment_context['has_edr']:
            base_feasibility -= 15

        return min(100, max(0, base_feasibility))

    def _requires_elevated_privileges(self, finding: Dict) -> bool:
        """Check if finding requires elevated privileges"""
        description = finding.get('description', '').lower()
        finding_text = finding.get('finding', '').lower()

        elevated_indicators = [
            'requires admin', 'requires root', 'requires system',
            'administrator', 'root access', 'system level',
            '/etc/shadow', 'lsass', 'sam database'
        ]

        return any(indicator in description or indicator in finding_text
                  for indicator in elevated_indicators)

    def _get_detection_likelihood(self, noise_score: int) -> str:
        """Convert noise score to detection likelihood"""
        if noise_score >= 80:
            return 'Very High'
        elif noise_score >= 60:
            return 'High'
        elif noise_score >= 40:
            return 'Moderate'
        elif noise_score >= 20:
            return 'Low'
        else:
            return 'Very Low'

    def _generate_recommendation(self, finding: Dict, module: str,
                                 impact: int, noise: int, feasibility: int) -> str:
        """Generate intelligent recommendation for operator"""

        description = finding.get('description', '').lower()
        severity = finding.get('severity', 'info')

        # High impact, low noise = RECOMMENDED
        if impact >= 70 and noise <= 40:
            return f"RECOMMENDED: High impact ({impact}), low detection risk ({noise})"

        # High impact, high noise with EDR
        if impact >= 70 and noise >= 60 and self.environment_context['has_edr']:
            return f"CAUTION: High impact but EDR present. Detection likely ({noise})"

        # Low feasibility
        if feasibility < 40:
            return f"NOT FEASIBLE: Low success probability ({feasibility}). Consider alternatives"

        # Privilege requirements not met
        if self._requires_elevated_privileges(finding):
            if self.environment_context['privilege_level'] == 'user':
                return "BLOCKED: Requires elevated privileges. Escalate first"

        # Module-specific recommendations
        if module == 'credential_access':
            if 'lsass' in description and self.environment_context['has_edr']:
                return "AVOID: LSASS access with EDR will trigger alerts. Use alternative credential sources"
            elif 'browser' in description or 'config file' in description:
                return "SAFE: Low-noise credential harvesting method"

        if module == 'privilege_escalation':
            if 'kernel' in description:
                return "HIGH RISK: Kernel exploits are noisy and may crash system"
            elif 'misconfiguration' in description:
                return "PREFERRED: Configuration-based escalation is stealthier"

        if module == 'persistence':
            if noise >= 70:
                return "NOISY: This persistence method likely monitored"
            else:
                return "VIABLE: Relatively stealthy persistence option"

        if module == 'lateral_movement':
            if feasibility >= 70:
                return f"READY: Target accessible with current credentials"
            else:
                return "BLOCKED: Additional credentials or access required"

        if module == 'exfiltration':
            if 'https' in description:
                return "STEALTHY: HTTPS blends with normal traffic"
            elif 'dns' in description:
                return "COVERT: DNS tunneling is stealthy but slow"

        # Default recommendation
        if noise >= 70:
            return f"HIGH RISK: Detection likelihood {self._get_detection_likelihood(noise)}"
        elif feasibility >= 70:
            return f"VIABLE: Feasibility {feasibility}%, Noise {noise}%"
        else:
            return f"ASSESS: Impact {impact}, Noise {noise}, Feasibility {feasibility}"

    def rank_findings(self, findings: List[Dict], module: str) -> List[Dict]:
        """
        Rank findings by actionability (impact vs noise vs feasibility)

        Returns sorted list with best findings first
        """
        scored_findings = []

        for finding in findings:
            scored = self.score_finding(finding.copy(), module)

            # Calculate composite score
            risk_data = scored['risk_analysis']

            # Weighted score: impact is most important, then feasibility, then stealth
            composite = (
                risk_data['impact_score'] * 0.4 +
                risk_data['feasibility_score'] * 0.35 +
                risk_data['stealth_score'] * 0.25
            )

            scored['composite_score'] = composite
            scored_findings.append(scored)

        # Sort by composite score (descending)
        scored_findings.sort(key=lambda x: x.get('composite_score', 0), reverse=True)

        return scored_findings

    def get_recommended_actions(self, all_results: Dict) -> List[Dict]:
        """
        Analyze all assessment results and recommend next actions

        Returns prioritized action list
        """
        recommendations = []

        # First, analyze environment from recon
        if 'reconnaissance' in all_results:
            self.analyze_environment(all_results['reconnaissance'])

        # Process each module's findings
        for module, results in all_results.items():
            if not isinstance(results, dict) or 'findings' not in results:
                continue

            findings = results['findings']
            ranked = self.rank_findings(findings, module)

            # Get top 3 actionable findings per module
            for finding in ranked[:3]:
                risk = finding.get('risk_analysis', {})

                # Only recommend if feasible and reasonably safe
                if risk.get('feasibility_score', 0) >= 50 and risk.get('opsec_safe', False):
                    recommendations.append({
                        'module': module,
                        'action': finding.get('finding', 'Unknown'),
                        'priority': finding.get('composite_score', 0),
                        'impact': risk.get('impact_score', 0),
                        'noise': risk.get('noise_score', 0),
                        'feasibility': risk.get('feasibility_score', 0),
                        'recommendation': risk.get('recommendation', ''),
                        'description': finding.get('description', '')
                    })

        # Sort by priority
        recommendations.sort(key=lambda x: x['priority'], reverse=True)

        return recommendations[:10]  # Top 10 recommendations

    def get_opsec_assessment(self) -> Dict:
        """
        Provide overall OPSEC assessment of the environment
        """
        context = self.environment_context

        threat_level = 'Low'
        if context['has_edr'] and context['has_siem']:
            threat_level = 'Critical'
        elif context['has_edr']:
            threat_level = 'High'
        elif context['has_av'] or context['has_siem']:
            threat_level = 'Moderate'

        safe_techniques = []
        risky_techniques = []

        # Build technique recommendations based on environment
        if threat_level in ['Critical', 'High']:
            safe_techniques.extend([
                'Passive enumeration',
                'Configuration file credential harvesting',
                'Token theft (existing sessions)',
                'Living-off-the-land binaries',
                'HTTPS-based exfiltration'
            ])

            risky_techniques.extend([
                'LSASS memory access',
                'Kernel exploits',
                'Process injection',
                'Suspicious scheduled tasks',
                'Large volume exfiltration'
            ])
        else:
            safe_techniques.extend([
                'Standard enumeration',
                'Credential harvesting',
                'Service-based persistence',
                'SMB lateral movement',
                'Standard exfiltration channels'
            ])

            risky_techniques.extend([
                'Kernel exploits',
                'Obvious malware deployment',
                'Destructive actions'
            ])

        return {
            'threat_level': threat_level,
            'environment_context': context,
            'safe_techniques': safe_techniques,
            'risky_techniques': risky_techniques,
            'recommendations': self._get_overall_recommendations(threat_level, context)
        }

    def _get_overall_recommendations(self, threat_level: str, context: Dict) -> List[str]:
        """Generate overall OPSEC recommendations"""
        recs = []

        if context['has_edr']:
            recs.append("EDR detected: Avoid memory manipulation and process injection")
            recs.append("Use living-off-the-land techniques and legitimate tools")

        if context['has_siem']:
            recs.append("SIEM detected: Minimize noisy enumeration and suspicious commands")
            recs.append("Blend actions with normal user behavior")

        if context['privilege_level'] == 'user':
            recs.append("Running as unprivileged user: Focus on user-level techniques first")
            recs.append("Prioritize privilege escalation to expand capabilities")

        if context['is_domain_joined']:
            recs.append("Domain-joined host: Lateral movement opportunities likely available")
            recs.append("Domain credentials may provide broader access")

        if threat_level == 'Low':
            recs.append("Low security posture: More aggressive techniques viable")
        elif threat_level in ['High', 'Critical']:
            recs.append("High security posture: Prioritize stealth over speed")
            recs.append("Consider long-term persistence over immediate exploitation")

        return recs


if __name__ == '__main__':
    # Test the risk scorer
    scorer = RiskScorer()

    # Simulate recon results with EDR
    recon_results = {
        'findings': [
            {
                'severity': 'info',
                'finding': 'CrowdStrike Falcon EDR detected',
                'description': 'Endpoint protection: CrowdStrike Falcon EDR is running'
            },
            {
                'severity': 'info',
                'finding': 'Domain-joined system',
                'description': 'System is joined to CORP.LOCAL domain'
            }
        ]
    }

    context = scorer.analyze_environment(recon_results)
    print("Environment Context:", context)

    # Score a finding
    test_finding = {
        'severity': 'high',
        'finding': 'LSASS memory accessible',
        'description': 'LSASS process memory can be read to extract credentials'
    }

    scored = scorer.score_finding(test_finding, 'credential_access')
    print("\nScored Finding:", scored['risk_analysis'])

    # OPSEC assessment
    opsec = scorer.get_opsec_assessment()
    print("\nOPSEC Assessment:", opsec['threat_level'])
    print("Safe Techniques:", opsec['safe_techniques'][:3])
