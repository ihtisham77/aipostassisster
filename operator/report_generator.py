#!/usr/bin/env python3
"""
Report Generation Module - PRODUCTION ENHANCED
Generates comprehensive security assessment reports with confidence scoring and professional formatting
"""

import json
from datetime import datetime
from collections import defaultdict, Counter
import os
import sys

# Import intelligence modules
try:
    from risk_scorer import RiskScorer
    from attack_path_generator import AttackPathGenerator
except ImportError:
    # Fallback if modules not available
    RiskScorer = None
    AttackPathGenerator = None


# Terminal color codes for enhanced output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    # Severity colors
    CRITICAL = '\033[91m\033[1m'  # Bold Red
    HIGH = '\033[91m'  # Red
    MEDIUM = '\033[93m'  # Yellow
    LOW = '\033[94m'  # Blue
    INFO = '\033[37m'  # White/Gray


class ReportGenerator:
    """Generate professional security assessment reports with enhanced features"""

    def __init__(self, agent_data, results_data, enable_intelligence=True):
        """
        Initialize report generator

        Args:
            agent_data: Agent information dict
            results_data: List of assessment results from the agent
            enable_intelligence: Enable AI-powered analysis (risk scoring, attack paths)
        """
        self.agent = agent_data
        self.results = results_data
        self.findings_by_severity = defaultdict(list)
        self.findings_by_module = defaultdict(list)
        self.findings_by_confidence = defaultdict(list)
        self.statistics = {}

        # Intelligence features
        self.enable_intelligence = enable_intelligence and (RiskScorer is not None)
        self.risk_scorer = None
        self.attack_path_generator = None
        self.intelligence_data = {}

        self._process_results()

        # Initialize intelligence if enabled
        if self.enable_intelligence:
            self._initialize_intelligence()

    def _process_results(self):
        """Process and categorize all findings with confidence scoring"""
        total_findings = 0
        severity_counts = Counter()
        module_counts = Counter()
        confidence_counts = Counter()
        verified_count = 0

        for result in self.results:
            module_name = result.get('module', 'unknown')
            results_data = result.get('results', {})
            findings = results_data.get('findings', [])

            module_counts[module_name] += len(findings)

            for finding in findings:
                severity = finding.get('severity', 'info')
                severity_counts[severity] += 1
                total_findings += 1

                # Process confidence scoring
                confidence_score = finding.get('confidence_score', 0)
                confidence_level = finding.get('confidence_level', 'unknown')
                verified = finding.get('verified', False)

                if verified:
                    verified_count += 1

                confidence_counts[confidence_level] += 1

                # Add metadata to finding
                finding['module'] = module_name
                finding['timestamp'] = result.get('timestamp', 'N/A')

                # Categorize by severity
                self.findings_by_severity[severity].append(finding)

                # Categorize by module
                self.findings_by_module[module_name].append(finding)

                # Categorize by confidence
                self.findings_by_confidence[confidence_level].append(finding)

        self.statistics = {
            'total_findings': total_findings,
            'severity_counts': dict(severity_counts),
            'module_counts': dict(module_counts),
            'confidence_counts': dict(confidence_counts),
            'verified_findings': verified_count,
            'modules_run': len(module_counts),
            'critical_findings': severity_counts.get('critical', 0),
            'high_findings': severity_counts.get('high', 0),
            'medium_findings': severity_counts.get('medium', 0),
            'low_findings': severity_counts.get('low', 0),
            'info_findings': severity_counts.get('info', 0)
        }

    def calculate_risk_score(self):
        """Calculate overall risk score (0-100) with confidence weighting"""
        weights = {
            'critical': 10,
            'high': 5,
            'medium': 2,
            'low': 0.5,
            'info': 0
        }

        score = 0
        for severity, weight in weights.items():
            findings = self.findings_by_severity.get(severity, [])
            for finding in findings:
                # Weight by confidence score
                confidence = finding.get('confidence_score', 100) / 100
                score += weight * confidence

        # Normalize to 0-100 scale
        # Assume 50+ points = 100 risk score
        risk_score = min(100, int((score / 50) * 100))

        return risk_score

    def get_risk_level(self, risk_score):
        """Get risk level based on score"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"

    def generate_executive_summary(self):
        """Generate executive summary with confidence metrics"""
        risk_score = self.calculate_risk_score()
        risk_level = self.get_risk_level(risk_score)

        summary = {
            'assessment_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target_system': self.agent.get('hostname', 'Unknown'),
            'platform': self.agent.get('platform', 'Unknown'),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'total_findings': self.statistics['total_findings'],
            'critical_findings': self.statistics['critical_findings'],
            'high_findings': self.statistics['high_findings'],
            'verified_findings': self.statistics['verified_findings'],
            'modules_assessed': self.statistics['modules_run'],
            'key_concerns': self._get_key_concerns(),
            'confidence_summary': {
                'verified': self.statistics['confidence_counts'].get('verified', 0),
                'high': self.statistics['confidence_counts'].get('high', 0),
                'medium': self.statistics['confidence_counts'].get('medium', 0),
                'low': self.statistics['confidence_counts'].get('low', 0)
            }
        }

        return summary

    def _get_key_concerns(self):
        """Identify top 5 key security concerns (prioritize high-confidence findings)"""
        concerns = []

        # Critical findings first (sorted by confidence)
        critical = sorted(
            self.findings_by_severity.get('critical', []),
            key=lambda x: x.get('confidence_score', 0),
            reverse=True
        )
        for finding in critical[:3]:
            concerns.append({
                'severity': 'CRITICAL',
                'issue': finding.get('finding', 'N/A'),
                'module': finding.get('module', 'N/A'),
                'confidence': finding.get('confidence_score', 0),
                'confidence_level': finding.get('confidence_level', 'unknown')
            })

        # Then high severity if we need more
        if len(concerns) < 5:
            high = sorted(
                self.findings_by_severity.get('high', []),
                key=lambda x: x.get('confidence_score', 0),
                reverse=True
            )
            for finding in high[:5-len(concerns)]:
                concerns.append({
                    'severity': 'HIGH',
                    'issue': finding.get('finding', 'N/A'),
                    'module': finding.get('module', 'N/A'),
                    'confidence': finding.get('confidence_score', 0),
                    'confidence_level': finding.get('confidence_level', 'unknown')
                })

        return concerns

    def _initialize_intelligence(self):
        """Initialize intelligent analysis modules"""
        try:
            # Organize results by module for intelligence analysis
            module_results = {}
            for result in self.results:
                module_name = result.get('module', 'unknown')
                module_results[module_name] = result.get('results', {})

            # Initialize risk scorer
            self.risk_scorer = RiskScorer()

            # Analyze environment from reconnaissance
            if 'reconnaissance' in module_results:
                self.risk_scorer.analyze_environment(module_results['reconnaissance'])

            # Score all findings
            for severity in self.findings_by_severity:
                for i, finding in enumerate(self.findings_by_severity[severity]):
                    module = finding.get('module', 'unknown')
                    scored_finding = self.risk_scorer.score_finding(finding, module)
                    self.findings_by_severity[severity][i] = scored_finding

            # Generate attack paths
            if AttackPathGenerator:
                self.attack_path_generator = AttackPathGenerator(module_results, self.risk_scorer)

                self.intelligence_data = {
                    'opsec_assessment': self.risk_scorer.get_opsec_assessment(),
                    'recommended_actions': self.risk_scorer.get_recommended_actions(module_results),
                    'attack_paths': self.attack_path_generator.generate_attack_paths(max_paths=5),
                    'quick_wins': self.attack_path_generator.get_quick_wins(),
                    'critical_risks': self.attack_path_generator.get_critical_risks()
                }

        except Exception as e:
            print(f"Warning: Intelligence analysis failed: {e}")
            self.enable_intelligence = False

    def get_recommended_actions(self):
        """Get AI-recommended next actions"""
        if not self.enable_intelligence:
            return []
        return self.intelligence_data.get('recommended_actions', [])

    def get_attack_paths(self):
        """Get generated attack paths"""
        if not self.enable_intelligence:
            return []
        return self.intelligence_data.get('attack_paths', [])

    def get_quick_wins(self):
        """Get quick win opportunities"""
        if not self.enable_intelligence:
            return []
        return self.intelligence_data.get('quick_wins', [])

    def get_opsec_assessment(self):
        """Get OPSEC assessment"""
        if not self.enable_intelligence:
            return {}
        return self.intelligence_data.get('opsec_assessment', {})

    def print_console_report(self):
        """Print a beautiful color-coded report to console"""
        exec_summary = self.generate_executive_summary()

        # Header
        print("\n" + "="*80)
        print(f"{Colors.BOLD}{Colors.HEADER}╔═══════════════════════════════════════════════════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}║          C2 SECURITY ASSESSMENT FRAMEWORK - COMPREHENSIVE REPORT              ║{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}╚═══════════════════════════════════════════════════════════════════════════════╝{Colors.ENDC}")
        print("="*80 + "\n")

        # Executive Summary
        print(f"{Colors.BOLD}{Colors.OKCYAN}█ EXECUTIVE SUMMARY{Colors.ENDC}\n")
        print(f"  Target System:     {Colors.BOLD}{exec_summary['target_system']}{Colors.ENDC}")
        print(f"  Platform:          {exec_summary['platform']}")
        print(f"  Assessment Date:   {exec_summary['assessment_date']}")
        print(f"  Modules Assessed:  {exec_summary['modules_assessed']}")

        # Risk Score with color
        risk_color = self._get_color_for_risk(exec_summary['risk_level'])
        print(f"\n  {Colors.BOLD}Overall Risk Level: {risk_color}{exec_summary['risk_level']} ({exec_summary['risk_score']}/100){Colors.ENDC}")

        # Visual risk meter
        filled = int(exec_summary['risk_score'] / 5)
        empty = 20 - filled
        print(f"  Risk Meter: [{risk_color}{'█' * filled}{Colors.ENDC}{'░' * empty}] {exec_summary['risk_score']}%\n")

        # Statistics Grid
        print(f"{Colors.BOLD}{Colors.OKCYAN}█ FINDINGS SUMMARY{Colors.ENDC}\n")
        print(f"  ╔════════════════════════════════════════════════════════════════╗")
        print(f"  ║ {Colors.BOLD}Total Findings: {self.statistics['total_findings']:<47}{Colors.ENDC}║")
        print(f"  ╠════════════════════════════════════════════════════════════════╣")

        # Severity breakdown with colors
        print(f"  ║ {Colors.CRITICAL}● CRITICAL:{Colors.ENDC}    {self.statistics['critical_findings']:<48}║")
        print(f"  ║ {Colors.HIGH}● HIGH:{Colors.ENDC}        {self.statistics['high_findings']:<48}║")
        print(f"  ║ {Colors.MEDIUM}● MEDIUM:{Colors.ENDC}      {self.statistics['medium_findings']:<48}║")
        print(f"  ║ {Colors.LOW}● LOW:{Colors.ENDC}         {self.statistics['low_findings']:<48}║")
        print(f"  ║ {Colors.INFO}● INFO:{Colors.ENDC}        {self.statistics['info_findings']:<48}║")
        print(f"  ╠════════════════════════════════════════════════════════════════╣")
        print(f"  ║ {Colors.OKGREEN}✓ Verified Findings:{Colors.ENDC} {self.statistics['verified_findings']:<42}║")
        print(f"  ╚════════════════════════════════════════════════════════════════╝\n")

        # Confidence Distribution
        print(f"{Colors.BOLD}{Colors.OKCYAN}█ CONFIDENCE DISTRIBUTION{Colors.ENDC}\n")
        conf_summary = exec_summary['confidence_summary']
        print(f"  {Colors.OKGREEN}● Verified (95-100%):{Colors.ENDC}  {conf_summary['verified']}")
        print(f"  {Colors.OKBLUE}● High (75-94%):{Colors.ENDC}       {conf_summary['high']}")
        print(f"  {Colors.WARNING}● Medium (50-74%):{Colors.ENDC}     {conf_summary['medium']}")
        print(f"  {Colors.FAIL}● Low (0-49%):{Colors.ENDC}         {conf_summary['low']}\n")

        # Key Concerns
        if exec_summary['key_concerns']:
            print(f"{Colors.BOLD}{Colors.WARNING}█ TOP SECURITY CONCERNS{Colors.ENDC}\n")
            for i, concern in enumerate(exec_summary['key_concerns'], 1):
                severity_color = self._get_color_for_severity(concern['severity'])
                conf_badge = self._get_confidence_badge(concern['confidence_level'])
                print(f"  {i}. {severity_color}[{concern['severity']}]{Colors.ENDC} {concern['issue']}")
                print(f"     Module: {concern['module']} │ {conf_badge}")
                print()

        # Module Summary
        print(f"{Colors.BOLD}{Colors.OKCYAN}█ MODULE ASSESSMENT SUMMARY{Colors.ENDC}\n")
        print(f"  {'Module':<30} {'Findings':<10} {'Status':<10}")
        print(f"  {'-'*60}")
        for module, count in sorted(self.statistics['module_counts'].items()):
            print(f"  {module:<30} {count:<10} {Colors.OKGREEN}✓ Complete{Colors.ENDC}")

        # Intelligence Sections (if enabled)
        if self.enable_intelligence:
            self._print_intelligence_sections()

        print("\n" + "="*80)
        print(f"\n{Colors.BOLD}💾 Generate full reports with:{Colors.ENDC}")
        print(f"   report {self.agent.get('agent_id', 'AGENT_ID')} html    # Interactive HTML report")
        print(f"   report {self.agent.get('agent_id', 'AGENT_ID')} all     # All formats (HTML/MD/JSON)\n")

    def _get_color_for_severity(self, severity):
        """Get terminal color for severity level"""
        colors = {
            'CRITICAL': Colors.CRITICAL,
            'HIGH': Colors.HIGH,
            'MEDIUM': Colors.MEDIUM,
            'LOW': Colors.LOW,
            'INFO': Colors.INFO
        }
        return colors.get(severity.upper(), Colors.ENDC)

    def _get_color_for_risk(self, risk_level):
        """Get terminal color for risk level"""
        colors = {
            'CRITICAL': Colors.CRITICAL,
            'HIGH': Colors.FAIL,
            'MEDIUM': Colors.WARNING,
            'LOW': Colors.OKBLUE,
            'MINIMAL': Colors.OKGREEN
        }
        return colors.get(risk_level, Colors.ENDC)

    def _get_confidence_badge(self, confidence_level):
        """Get colored confidence badge"""
        badges = {
            'verified': f"{Colors.OKGREEN}✓ Verified{Colors.ENDC}",
            'high': f"{Colors.OKBLUE}◆ High Confidence{Colors.ENDC}",
            'medium': f"{Colors.WARNING}◆ Medium Confidence{Colors.ENDC}",
            'low': f"{Colors.FAIL}◆ Low Confidence{Colors.ENDC}"
        }
        return badges.get(confidence_level.lower(), f"◆ {confidence_level}")

    def _print_intelligence_sections(self):
        """Print AI-powered intelligence sections"""
        print()

        # OPSEC Assessment
        opsec = self.get_opsec_assessment()
        if opsec:
            print(f"\n{Colors.BOLD}{Colors.HEADER}█ OPSEC ASSESSMENT{Colors.ENDC}\n")

            threat_color = {
                'Low': Colors.OKGREEN,
                'Moderate': Colors.WARNING,
                'High': Colors.FAIL,
                'Critical': Colors.CRITICAL
            }.get(opsec['threat_level'], Colors.ENDC)

            print(f"  {Colors.BOLD}Threat Level: {threat_color}{opsec['threat_level']}{Colors.ENDC}\n")

            context = opsec['environment_context']
            print(f"  Environment:")
            print(f"    EDR Detected:       {'✓ Yes' if context['has_edr'] else '✗ No'}")
            print(f"    SIEM Detected:      {'✓ Yes' if context['has_siem'] else '✗ No'}")
            print(f"    Privilege Level:    {context['privilege_level'].title()}")
            print(f"    Domain Joined:      {'✓ Yes' if context['is_domain_joined'] else '✗ No'}")

            if opsec['recommendations']:
                print(f"\n  {Colors.BOLD}Key Recommendations:{Colors.ENDC}")
                for i, rec in enumerate(opsec['recommendations'][:5], 1):
                    print(f"    {i}. {rec}")

        # Quick Wins
        quick_wins = self.get_quick_wins()
        if quick_wins:
            print(f"\n{Colors.BOLD}{Colors.OKGREEN}█ QUICK WINS (Low-Hanging Fruit){Colors.ENDC}\n")
            print(f"  {Colors.BOLD}High impact, low detection risk, high feasibility{Colors.ENDC}\n")

            for i, win in enumerate(quick_wins[:5], 1):
                print(f"  {i}. {Colors.OKGREEN}[{win['phase'].upper()}]{Colors.ENDC} {win['finding']}")
                print(f"     Impact: {win['impact']}% │ Noise: {win['noise']}% │ Feasibility: {win['feasibility']}%")
                print(f"     {Colors.BOLD}→{Colors.ENDC} {win['recommendation']}")
                print()

        # Recommended Actions
        actions = self.get_recommended_actions()
        if actions:
            print(f"\n{Colors.BOLD}{Colors.OKCYAN}█ RECOMMENDED NEXT ACTIONS{Colors.ENDC}\n")
            print(f"  {Colors.BOLD}Prioritized actions based on risk/reward analysis{Colors.ENDC}\n")

            for i, action in enumerate(actions[:5], 1):
                phase_color = Colors.OKCYAN
                print(f"  {i}. {phase_color}[{action['module'].upper()}]{Colors.ENDC}")
                print(f"     {Colors.BOLD}{action['action']}{Colors.ENDC}")
                print(f"     Priority: {action['priority']:.0f} │ Impact: {action['impact']} │ Stealth: {100-action['noise']}")
                print(f"     {Colors.BOLD}→{Colors.ENDC} {action['recommendation']}")
                print()

        # Attack Paths
        attack_paths = self.get_attack_paths()
        if attack_paths:
            print(f"\n{Colors.BOLD}{Colors.HEADER}█ ATTACK PATHS{Colors.ENDC}\n")
            print(f"  {Colors.BOLD}Generated attack chains from reconnaissance to objectives{Colors.ENDC}\n")

            for i, path in enumerate(attack_paths[:3], 1):
                risk_color = {
                    'Low Risk': Colors.OKGREEN,
                    'Moderate Risk': Colors.WARNING,
                    'High Risk': Colors.FAIL,
                    'Very High Risk': Colors.CRITICAL
                }.get(path['risk_level'], Colors.ENDC)

                print(f"  {Colors.BOLD}Path {i}: {' → '.join(path['phases'])}{Colors.ENDC}")
                print(f"  Risk: {risk_color}{path['risk_level']}{Colors.ENDC} │ "
                      f"Score: {path['overall_score']:.1f}/100 │ "
                      f"Steps: {path['length']}")
                print(f"  {Colors.BOLD}→{Colors.ENDC} {path['recommendation']}\n")

                # Show first 3 steps
                for j, step in enumerate(path['steps'][:3], 1):
                    phase_color = Colors.OKCYAN
                    print(f"    {j}. {phase_color}[{step['phase'].upper()}]{Colors.ENDC} {step['action'][:60]}")

                if len(path['steps']) > 3:
                    print(f"    ... and {len(path['steps']) - 3} more steps")
                print()

    def generate_json_report(self):
        """Generate complete report in JSON format"""
        report = {
            'metadata': {
                'report_generated': datetime.now().isoformat(),
                'report_version': '3.0',
                'framework': 'C2 Security Assessment Framework - Intelligent',
                'confidence_scoring_enabled': True,
                'intelligence_enabled': self.enable_intelligence
            },
            'agent_info': self.agent,
            'executive_summary': self.generate_executive_summary(),
            'statistics': self.statistics,
            'findings_by_severity': dict(self.findings_by_severity),
            'findings_by_module': dict(self.findings_by_module),
            'findings_by_confidence': dict(self.findings_by_confidence),
            'raw_results': self.results
        }

        # Add intelligence data if enabled
        if self.enable_intelligence:
            report['intelligence'] = {
                'opsec_assessment': self.get_opsec_assessment(),
                'recommended_actions': self.get_recommended_actions(),
                'attack_paths': self.get_attack_paths(),
                'quick_wins': self.get_quick_wins()
            }

        return report

    def generate_markdown_report(self):
        """Generate professional Markdown report with confidence scoring"""
        exec_summary = self.generate_executive_summary()
        risk_score = exec_summary['risk_score']
        risk_level = exec_summary['risk_level']

        md = []

        # Header
        md.append("# 🔒 Security Assessment Report")
        md.append("")
        md.append(f"**Generated:** {exec_summary['assessment_date']}")
        md.append(f"**Framework:** C2 Security Assessment Framework v2.0 (Enhanced)")
        md.append(f"**Confidence Scoring:** Enabled")
        md.append("")
        md.append("---")
        md.append("")

        # Executive Summary
        md.append("## 📊 Executive Summary")
        md.append("")
        md.append(f"**Target System:** `{exec_summary['target_system']}`")
        md.append(f"**Platform:** {exec_summary['platform']}")
        md.append(f"**Assessment Date:** {exec_summary['assessment_date']}")
        md.append(f"**Modules Assessed:** {exec_summary['modules_assessed']}")
        md.append("")

        # Risk Assessment
        md.append(f"### 🎯 Overall Risk Assessment")
        md.append("")
        md.append(f"**Risk Level:** `{risk_level}`")
        md.append(f"**Risk Score:** {risk_score}/100")
        md.append("")

        # Risk meter visualization
        filled = '█' * (risk_score // 5)
        empty = '░' * (20 - risk_score // 5)
        md.append("```")
        md.append(f"Risk: [{filled}{empty}] {risk_score}%")
        md.append("```")
        md.append("")

        # Statistics
        md.append("### 📈 Key Statistics")
        md.append("")
        md.append(f"| Metric | Count |")
        md.append(f"|--------|-------|")
        md.append(f"| **Total Findings** | {self.statistics['total_findings']} |")
        md.append(f"| 🔴 Critical Issues | {self.statistics['critical_findings']} |")
        md.append(f"| 🟠 High Severity | {self.statistics['high_findings']} |")
        md.append(f"| 🟡 Medium Severity | {self.statistics['medium_findings']} |")
        md.append(f"| 🔵 Low Severity | {self.statistics['low_findings']} |")
        md.append(f"| ⚪ Informational | {self.statistics['info_findings']} |")
        md.append(f"| ✓ Verified Findings | {self.statistics['verified_findings']} |")
        md.append("")

        # Confidence Distribution
        md.append("### 🎯 Confidence Distribution")
        md.append("")
        md.append("| Confidence Level | Count | Description |")
        md.append("|------------------|-------|-------------|")
        conf_summary = exec_summary['confidence_summary']
        md.append(f"| ✓ Verified (95-100%) | {conf_summary['verified']} | Multi-method verification |")
        md.append(f"| ◆ High (75-94%) | {conf_summary['high']} | Strong evidence |")
        md.append(f"| ◆ Medium (50-74%) | {conf_summary['medium']} | Moderate confidence |")
        md.append(f"| ◆ Low (0-49%) | {conf_summary['low']} | Requires validation |")
        md.append("")

        # Severity Distribution Chart
        md.append("### 📊 Findings Distribution")
        md.append("")
        md.append("| Severity | Count | Percentage | Confidence Weighted |")
        md.append("|----------|-------|------------|---------------------|")
        total = self.statistics['total_findings'] or 1
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = self.statistics['severity_counts'].get(severity, 0)
            pct = (count / total) * 100

            # Calculate average confidence for this severity
            findings = self.findings_by_severity.get(severity, [])
            if findings:
                avg_conf = sum(f.get('confidence_score', 0) for f in findings) / len(findings)
            else:
                avg_conf = 0

            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}.get(severity, '•')
            md.append(f"| {emoji} {severity.capitalize()} | {count} | {pct:.1f}% | {avg_conf:.0f}% |")
        md.append("")

        # Key Concerns
        if exec_summary['key_concerns']:
            md.append("### ⚠️ Top Security Concerns")
            md.append("")
            for i, concern in enumerate(exec_summary['key_concerns'], 1):
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠'}.get(concern['severity'], '⚠️')
                conf_badge = concern['confidence_level'].upper()
                md.append(f"{i}. {emoji} **[{concern['severity']}]** {concern['issue']}")
                md.append(f"   - **Module:** {concern['module']}")
                md.append(f"   - **Confidence:** {conf_badge} ({concern['confidence']}%)")
                md.append("")

        md.append("---")
        md.append("")

        # Detailed Findings by Severity
        md.append("## 🔍 Detailed Findings")
        md.append("")

        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'info': '⚪'
        }

        for severity in severity_order:
            findings = self.findings_by_severity.get(severity, [])
            if not findings:
                continue

            icon = severity_icons.get(severity, '•')
            md.append(f"### {icon} {severity.upper()} Severity ({len(findings)} findings)")
            md.append("")

            for i, finding in enumerate(findings, 1):
                conf_score = finding.get('confidence_score', 0)
                conf_level = finding.get('confidence_level', 'unknown').upper()
                verified = "✓ Verified" if finding.get('verified', False) else ""

                md.append(f"#### {severity.upper()}-{i}: {finding.get('finding', 'N/A')}")
                md.append("")
                md.append(f"**Module:** {finding.get('module', 'N/A')}")
                md.append(f"**Confidence:** {conf_level} ({conf_score}%) {verified}")
                md.append("")
                md.append(f"**Description:**")
                md.append(f"{finding.get('description', 'N/A')}")
                md.append("")
                md.append(f"**Remediation:**")
                md.append(f"{finding.get('remediation', 'N/A')}")
                md.append("")

                # Add OS-specific info if available
                if 'os_specific' in finding:
                    md.append(f"*OS: {finding['os_specific']}*")
                    md.append("")

                md.append("---")
                md.append("")

        # Module Summary
        md.append("## 📦 Assessment Module Summary")
        md.append("")
        md.append("| Module | Findings | Average Confidence | Status |")
        md.append("|--------|----------|-------------------|--------|")

        for module, count in sorted(self.statistics['module_counts'].items()):
            module_findings = self.findings_by_module.get(module, [])
            if module_findings:
                avg_conf = sum(f.get('confidence_score', 0) for f in module_findings) / len(module_findings)
            else:
                avg_conf = 0

            md.append(f"| {module} | {count} | {avg_conf:.0f}% | ✅ Complete |")

        md.append("")

        # Recommendations
        md.append("## 💡 Recommendations")
        md.append("")
        md.append("### 🚨 Immediate Actions (Critical Priority)")
        md.append("")

        critical_findings = sorted(
            self.findings_by_severity.get('critical', []),
            key=lambda x: x.get('confidence_score', 0),
            reverse=True
        )

        if critical_findings:
            for i, finding in enumerate(critical_findings, 1):
                conf = finding.get('confidence_score', 0)
                md.append(f"{i}. {finding.get('remediation', 'N/A')} *(Confidence: {conf}%)*")
        else:
            md.append("✅ No critical issues identified")

        md.append("")
        md.append("### ⚠️ High Priority Actions")
        md.append("")

        high_findings = sorted(
            self.findings_by_severity.get('high', []),
            key=lambda x: x.get('confidence_score', 0),
            reverse=True
        )

        if high_findings:
            for i, finding in enumerate(high_findings[:5], 1):  # Top 5
                conf = finding.get('confidence_score', 0)
                md.append(f"{i}. {finding.get('remediation', 'N/A')} *(Confidence: {conf}%)*")
        else:
            md.append("✅ No high priority issues identified")

        md.append("")
        md.append("---")
        md.append("")

        # Footer
        md.append("## ℹ️ Report Information")
        md.append("")
        md.append(f"- **Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"- **Framework Version:** 2.0 (Enhanced with Confidence Scoring)")
        md.append(f"- **Agent ID:** {self.agent.get('agent_id', 'N/A')}")
        md.append(f"- **Total Assessment Time:** {len(self.results)} module executions")
        md.append("")
        md.append("---")
        md.append("")
        md.append("*This report was generated by the C2 Security Assessment Framework*")
        md.append("")
        md.append("**Enhanced Features:**")
        md.append("- ✓ Multi-method verification")
        md.append("- ✓ Confidence scoring (0-100%)")
        md.append("- ✓ OS-specific detection (Linux/Windows/macOS)")
        md.append("- ✓ Production-ready enterprise testing")
        md.append("")

        return "\n".join(md)

    def generate_html_report(self):
        """Generate enhanced professional HTML report with charts and confidence scoring"""
        exec_summary = self.generate_executive_summary()
        risk_score = exec_summary['risk_score']
        risk_level = exec_summary['risk_level']

        # Determine risk color
        risk_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#17a2b8',
            'MINIMAL': '#28a745'
        }
        risk_color = risk_colors.get(risk_level, '#6c757d')

        # Prepare chart data
        severity_data = []
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = self.statistics['severity_counts'].get(sev, 0)
            severity_data.append(f"{{name: '{sev.capitalize()}', value: {count}}}")

        confidence_data = []
        conf_summary = exec_summary['confidence_summary']
        for level, count in conf_summary.items():
            confidence_data.append(f"{{name: '{level.capitalize()}', value: {count}}}")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {exec_summary['target_system']}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 0;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            border-radius: 12px;
            overflow: hidden;
        }}

        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}

        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}

        header .subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
        }}

        .content {{
            padding: 40px;
        }}

        h2 {{
            color: #667eea;
            margin-top: 40px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            font-size: 1.8em;
        }}

        h2:first-child {{
            margin-top: 0;
        }}

        h3 {{
            color: #764ba2;
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 1.4em;
        }}

        .risk-score {{
            background: linear-gradient(135deg, {risk_color} 0%, {risk_color}dd 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            text-align: center;
            margin: 30px 0;
            box-shadow: 0 8px 16px rgba(0,0,0,0.2);
        }}

        .risk-score h2 {{
            color: white;
            border: none;
            margin: 0;
            font-size: 2em;
        }}

        .risk-score .score {{
            font-size: 5em;
            font-weight: bold;
            margin: 15px 0;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}

        .stat-card {{
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 25px;
            border-radius: 12px;
            border-left: 5px solid #667eea;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 16px rgba(0,0,0,0.15);
        }}

        .stat-card.critical {{
            border-left-color: #dc3545;
        }}

        .stat-card.high {{
            border-left-color: #fd7e14;
        }}

        .stat-card.medium {{
            border-left-color: #ffc107;
        }}

        .stat-card.low {{
            border-left-color: #17a2b8;
        }}

        .stat-card h3 {{
            margin: 0 0 10px 0;
            font-size: 0.95em;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .stat-card .value {{
            font-size: 3em;
            font-weight: bold;
            color: #212529;
        }}

        .chart-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin: 30px 0;
        }}

        .chart-box {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}

        .chart-box h3 {{
            text-align: center;
            margin-top: 0;
        }}

        .finding {{
            background: #fff;
            border: 1px solid #dee2e6;
            border-radius: 12px;
            padding: 25px;
            margin: 20px 0;
            box-shadow: 0 4px 8px rgba(0,0,0,0.08);
            transition: box-shadow 0.2s;
        }}

        .finding:hover {{
            box-shadow: 0 8px 16px rgba(0,0,0,0.12);
        }}

        .finding.critical {{
            border-left: 6px solid #dc3545;
        }}

        .finding.high {{
            border-left: 6px solid #fd7e14;
        }}

        .finding.medium {{
            border-left: 6px solid #ffc107;
        }}

        .finding.low {{
            border-left: 6px solid #17a2b8;
        }}

        .finding.info {{
            border-left: 6px solid #6c757d;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}

        .finding-title {{
            font-size: 1.3em;
            font-weight: bold;
            color: #212529;
            flex: 1;
        }}

        .badges {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}

        .severity-badge, .confidence-badge {{
            padding: 6px 16px;
            border-radius: 20px;
            color: white;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .severity-badge.critical {{
            background: #dc3545;
        }}

        .severity-badge.high {{
            background: #fd7e14;
        }}

        .severity-badge.medium {{
            background: #ffc107;
            color: #212529;
        }}

        .severity-badge.low {{
            background: #17a2b8;
        }}

        .severity-badge.info {{
            background: #6c757d;
        }}

        .confidence-badge {{
            background: #6c757d;
        }}

        .confidence-badge.verified {{
            background: #28a745;
        }}

        .confidence-badge.high {{
            background: #17a2b8;
        }}

        .confidence-badge.medium {{
            background: #ffc107;
            color: #212529;
        }}

        .confidence-badge.low {{
            background: #dc3545;
        }}

        .finding-section {{
            margin: 15px 0;
        }}

        .finding-label {{
            font-weight: bold;
            color: #495057;
            margin-bottom: 8px;
            display: block;
        }}

        .finding-content {{
            color: #212529;
            padding: 12px;
            background: #f8f9fa;
            border-radius: 8px;
            line-height: 1.7;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            border-radius: 12px;
            overflow: hidden;
        }}

        th, td {{
            padding: 15px;
            text-align: left;
        }}

        th {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.9em;
        }}

        tr:nth-child(even) {{
            background: #f8f9fa;
        }}

        tr:hover {{
            background: #e9ecef;
        }}

        .key-concern {{
            background: linear-gradient(135deg, #fff3cd 0%, #ffe9a0 100%);
            border-left: 5px solid #ffc107;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}

        footer {{
            margin-top: 60px;
            padding: 30px 40px;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            text-align: center;
            color: #6c757d;
            border-top: 3px solid #667eea;
        }}

        .progress-bar {{
            width: 100%;
            height: 40px;
            background: #e9ecef;
            border-radius: 20px;
            overflow: hidden;
            margin: 20px 0;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
        }}

        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, {risk_color} 0%, {risk_color}dd 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 1.1em;
            transition: width 0.5s ease;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }}

        .info-box {{
            background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
            border-left: 5px solid #2196f3;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }}

        @media print {{
            body {{
                background: white;
            }}
            .container {{
                box-shadow: none;
            }}
        }}

        @media (max-width: 768px) {{
            .chart-container {{
                grid-template-columns: 1fr;
            }}

            .stats-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Assessment Report</h1>
            <div class="subtitle">C2 Security Assessment Framework v2.0 - Enhanced with Confidence Scoring</div>
            <div class="subtitle" style="margin-top: 10px;">Generated: {exec_summary['assessment_date']}</div>
        </header>

        <div class="content">
            <section id="executive-summary">
                <h2>📊 Executive Summary</h2>

                <div class="info-box">
                    <strong>Target System:</strong> {exec_summary['target_system']}<br>
                    <strong>Platform:</strong> {exec_summary['platform']}<br>
                    <strong>Assessment Date:</strong> {exec_summary['assessment_date']}<br>
                    <strong>Modules Assessed:</strong> {exec_summary['modules_assessed']}<br>
                    <strong>Verified Findings:</strong> {exec_summary['verified_findings']} out of {self.statistics['total_findings']} total
                </div>

                <div class="risk-score">
                    <h2>Overall Risk Assessment</h2>
                    <div class="score">{risk_score}/100</div>
                    <h3>{risk_level} RISK</h3>
                </div>

                <div class="progress-bar">
                    <div class="progress-fill" style="width: {risk_score}%;">
                        Risk Score: {risk_score}%
                    </div>
                </div>

                <h3>📈 Key Statistics</h3>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total Findings</h3>
                        <div class="value">{self.statistics['total_findings']}</div>
                    </div>
                    <div class="stat-card critical">
                        <h3>🔴 Critical</h3>
                        <div class="value">{self.statistics['critical_findings']}</div>
                    </div>
                    <div class="stat-card high">
                        <h3>🟠 High</h3>
                        <div class="value">{self.statistics['high_findings']}</div>
                    </div>
                    <div class="stat-card medium">
                        <h3>🟡 Medium</h3>
                        <div class="value">{self.statistics['medium_findings']}</div>
                    </div>
                    <div class="stat-card low">
                        <h3>🔵 Low</h3>
                        <div class="value">{self.statistics['low_findings']}</div>
                    </div>
                    <div class="stat-card">
                        <h3>⚪ Info</h3>
                        <div class="value">{self.statistics['info_findings']}</div>
                    </div>
                </div>

                <h3>📊 Interactive Charts</h3>
                <div class="chart-container">
                    <div class="chart-box">
                        <h3>Findings by Severity</h3>
                        <canvas id="severityChart"></canvas>
                    </div>
                    <div class="chart-box">
                        <h3>Confidence Distribution</h3>
                        <canvas id="confidenceChart"></canvas>
                    </div>
                </div>
"""

        # Key Concerns
        if exec_summary['key_concerns']:
            html += """
                <h3>⚠️ Top Security Concerns</h3>
"""
            for i, concern in enumerate(exec_summary['key_concerns'], 1):
                html += f"""
                <div class="key-concern">
                    <strong>{i}. [{concern['severity']}]</strong> {concern['issue']}<br>
                    <small>Module: {concern['module']} | Confidence: {concern['confidence_level'].upper()} ({concern['confidence']}%)</small>
                </div>
"""

        html += """
            </section>

            <section id="detailed-findings">
                <h2>🔍 Detailed Findings</h2>
"""

        # Detailed findings by severity
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'info': '⚪'
        }

        for severity in severity_order:
            findings = self.findings_by_severity.get(severity, [])
            if not findings:
                continue

            icon = severity_icons.get(severity, '•')
            html += f"""
                <h3>{icon} {severity.upper()} Severity ({len(findings)} findings)</h3>
"""

            for i, finding in enumerate(findings, 1):
                conf_score = finding.get('confidence_score', 0)
                conf_level = finding.get('confidence_level', 'unknown')
                verified = finding.get('verified', False)

                html += f"""
                <div class="finding {severity}">
                    <div class="finding-header">
                        <div class="finding-title">{finding.get('finding', 'N/A')}</div>
                        <div class="badges">
                            <div class="severity-badge {severity}">{severity.upper()}</div>
                            <div class="confidence-badge {conf_level}">{conf_level.upper()} {conf_score}%</div>
                            {'<div class="confidence-badge verified">✓ VERIFIED</div>' if verified else ''}
                        </div>
                    </div>
                    <div class="finding-section">
                        <span class="finding-label">Module:</span>
                        <div class="finding-content">{finding.get('module', 'N/A')}</div>
                    </div>
                    <div class="finding-section">
                        <span class="finding-label">Description:</span>
                        <div class="finding-content">{finding.get('description', 'N/A').replace(chr(10), '<br>')}</div>
                    </div>
                    <div class="finding-section">
                        <span class="finding-label">Remediation:</span>
                        <div class="finding-content">{finding.get('remediation', 'N/A').replace(chr(10), '<br>')}</div>
                    </div>
"""
                if 'os_specific' in finding:
                    html += f"""
                    <div class="finding-section">
                        <span class="finding-label">Operating System:</span>
                        <div class="finding-content">{finding['os_specific']}</div>
                    </div>
"""
                html += """
                </div>
"""

        html += """
            </section>

            <section id="module-summary">
                <h2>📦 Assessment Module Summary</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Module</th>
                            <th>Findings</th>
                            <th>Avg Confidence</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
"""

        for module, count in sorted(self.statistics['module_counts'].items()):
            module_findings = self.findings_by_module.get(module, [])
            if module_findings:
                avg_conf = sum(f.get('confidence_score', 0) for f in module_findings) / len(module_findings)
            else:
                avg_conf = 0

            html += f"""
                        <tr>
                            <td>{module}</td>
                            <td>{count}</td>
                            <td>{avg_conf:.0f}%</td>
                            <td>✅ Complete</td>
                        </tr>
"""

        html += """
                    </tbody>
                </table>
            </section>
        </div>

        <footer>
            <h3>ℹ️ Report Information</h3>
            <p><strong>Report Generated:</strong> """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
            <p><strong>Framework Version:</strong> 2.0 (Enhanced with Confidence Scoring)</p>
            <p><strong>Agent ID:</strong> """ + self.agent.get('agent_id', 'N/A') + """</p>
            <p><strong>Total Modules Executed:</strong> """ + str(len(self.results)) + """</p>
            <p style="margin-top: 20px;"><em>This report was generated by the C2 Security Assessment Framework</em></p>
            <p style="margin-top: 10px;">
                <strong>Enhanced Features:</strong><br>
                ✓ Multi-method verification &nbsp;|&nbsp;
                ✓ Confidence scoring (0-100%) &nbsp;|&nbsp;
                ✓ OS-specific detection &nbsp;|&nbsp;
                ✓ Production-ready testing
            </p>
        </footer>
    </div>

    <script>
        // Severity Distribution Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [""" + str(self.statistics['critical_findings']) + """,
                           """ + str(self.statistics['high_findings']) + """,
                           """ + str(self.statistics['medium_findings']) + """,
                           """ + str(self.statistics['low_findings']) + """,
                           """ + str(self.statistics['info_findings']) + """],
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14',
                        '#ffc107',
                        '#17a2b8',
                        '#6c757d'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Confidence Distribution Chart
        const confidenceCtx = document.getElementById('confidenceChart').getContext('2d');
        new Chart(confidenceCtx, {
            type: 'bar',
            data: {
                labels: ['Verified', 'High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Findings',
                    data: [""" + str(conf_summary['verified']) + """,
                           """ + str(conf_summary['high']) + """,
                           """ + str(conf_summary['medium']) + """,
                           """ + str(conf_summary['low']) + """],
                    backgroundColor: [
                        '#28a745',
                        '#17a2b8',
                        '#ffc107',
                        '#dc3545'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
"""

        return html

    def save_report(self, output_dir, format='all'):
        """
        Save report to file(s)

        Args:
            output_dir: Directory to save reports
            format: 'json', 'markdown', 'html', or 'all'

        Returns:
            Dict with paths to generated reports
        """
        os.makedirs(output_dir, exist_ok=True)

        agent_id = self.agent.get('agent_id', 'unknown')[:8]
        hostname = self.agent.get('hostname', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        base_filename = f"report_{hostname}_{agent_id}_{timestamp}"

        saved_files = {}

        if format in ['json', 'all']:
            json_path = os.path.join(output_dir, f"{base_filename}.json")
            with open(json_path, 'w') as f:
                json.dump(self.generate_json_report(), f, indent=2)
            saved_files['json'] = json_path
            print(f"{Colors.OKGREEN}[+] JSON report saved: {json_path}{Colors.ENDC}")

        if format in ['markdown', 'md', 'all']:
            md_path = os.path.join(output_dir, f"{base_filename}.md")
            with open(md_path, 'w') as f:
                f.write(self.generate_markdown_report())
            saved_files['markdown'] = md_path
            print(f"{Colors.OKGREEN}[+] Markdown report saved: {md_path}{Colors.ENDC}")

        if format in ['html', 'all']:
            html_path = os.path.join(output_dir, f"{base_filename}.html")
            with open(html_path, 'w') as f:
                f.write(self.generate_html_report())
            saved_files['html'] = html_path
            print(f"{Colors.OKGREEN}[+] HTML report saved: {html_path}{Colors.ENDC}")

        return saved_files


def generate_report_from_server(server_url, agent_id, output_dir="reports", format='all'):
    """
    Fetch data from server and generate report

    Args:
        server_url: URL of the operator server
        agent_id: ID of the agent to generate report for
        output_dir: Directory to save reports
        format: Report format ('json', 'markdown', 'html', or 'all')

    Returns:
        Dict with paths to generated reports or None on error
    """
    import requests

    try:
        # Fetch agent data
        agents_response = requests.get(f"{server_url}/api/agents", timeout=10)
        if agents_response.status_code != 200:
            print(f"{Colors.FAIL}[!] Failed to fetch agents: {agents_response.status_code}{Colors.ENDC}")
            return None

        agents = agents_response.json().get('agents', [])
        agent_data = None

        for agent in agents:
            if agent['agent_id'] == agent_id:
                agent_data = agent
                break

        if not agent_data:
            print(f"{Colors.FAIL}[!] Agent {agent_id} not found{Colors.ENDC}")
            return None

        # Fetch results
        results_response = requests.get(f"{server_url}/api/results/{agent_id}", timeout=10)
        if results_response.status_code != 200:
            print(f"{Colors.FAIL}[!] Failed to fetch results: {results_response.status_code}{Colors.ENDC}")
            return None

        results_data = results_response.json().get('results', [])

        if not results_data:
            print(f"{Colors.WARNING}[!] No results found for agent {agent_id}{Colors.ENDC}")
            return None

        # Generate report
        generator = ReportGenerator(agent_data, results_data)

        # Show console summary if format is 'all' or 'console'
        if format in ['all', 'console']:
            generator.print_console_report()

        # Save files if not console-only
        if format != 'console':
            saved_files = generator.save_report(output_dir, format)
            return saved_files

        return {'console': 'displayed'}

    except Exception as e:
        print(f"{Colors.FAIL}[!] Error generating report: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 3:
        print(f"""
{Colors.BOLD}{Colors.HEADER}C2 Security Assessment Framework - Report Generator{Colors.ENDC}

Usage: python report_generator.py <server_url> <agent_id> [format] [output_dir]

Formats:
  - console   : Color-coded terminal output only
  - json      : Machine-readable JSON report
  - markdown  : GitHub-flavored markdown report
  - html      : Interactive HTML report with charts
  - all       : Generate all formats + console output (default)

Examples:
  python report_generator.py http://localhost:8542 abc123 console
  python report_generator.py http://localhost:8542 abc123 html reports/
  python report_generator.py http://localhost:8542 abc123 all reports/
        """)
        sys.exit(1)

    server_url = sys.argv[1]
    agent_id = sys.argv[2]
    format_type = sys.argv[3] if len(sys.argv) > 3 else 'all'
    output_dir = sys.argv[4] if len(sys.argv) > 4 else 'reports'

    print(f"\n{Colors.BOLD}[*] Generating report for agent: {agent_id}{Colors.ENDC}")
    print(f"{Colors.BOLD}[*] Format: {format_type}{Colors.ENDC}\n")

    result = generate_report_from_server(server_url, agent_id, output_dir, format_type)

    if result:
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}[+] Report generation complete!{Colors.ENDC}")
        if format_type != 'console':
            print(f"{Colors.BOLD}[*] Files saved in: {output_dir}/{Colors.ENDC}\n")
    else:
        print(f"\n{Colors.FAIL}[!] Report generation failed{Colors.ENDC}")
