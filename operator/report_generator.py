#!/usr/bin/env python3
"""
Report Generation Module
Generates comprehensive security assessment reports from agent findings
"""

import json
from datetime import datetime
from collections import defaultdict, Counter
import os


class ReportGenerator:
    """Generate professional security assessment reports"""

    def __init__(self, agent_data, results_data):
        """
        Initialize report generator

        Args:
            agent_data: Agent information dict
            results_data: List of assessment results from the agent
        """
        self.agent = agent_data
        self.results = results_data
        self.findings_by_severity = defaultdict(list)
        self.findings_by_module = defaultdict(list)
        self.statistics = {}

        self._process_results()

    def _process_results(self):
        """Process and categorize all findings"""
        total_findings = 0
        severity_counts = Counter()
        module_counts = Counter()

        for result in self.results:
            module_name = result.get('module', 'unknown')
            results_data = result.get('results', {})
            findings = results_data.get('findings', [])

            module_counts[module_name] += len(findings)

            for finding in findings:
                severity = finding.get('severity', 'info')
                severity_counts[severity] += 1
                total_findings += 1

                # Add metadata to finding
                finding['module'] = module_name
                finding['timestamp'] = result.get('timestamp', 'N/A')

                # Categorize by severity
                self.findings_by_severity[severity].append(finding)

                # Categorize by module
                self.findings_by_module[module_name].append(finding)

        self.statistics = {
            'total_findings': total_findings,
            'severity_counts': dict(severity_counts),
            'module_counts': dict(module_counts),
            'modules_run': len(module_counts),
            'critical_findings': severity_counts.get('critical', 0),
            'high_findings': severity_counts.get('high', 0),
            'medium_findings': severity_counts.get('medium', 0),
            'low_findings': severity_counts.get('low', 0),
            'info_findings': severity_counts.get('info', 0)
        }

    def calculate_risk_score(self):
        """Calculate overall risk score (0-100)"""
        weights = {
            'critical': 10,
            'high': 5,
            'medium': 2,
            'low': 0.5,
            'info': 0
        }

        score = 0
        for severity, weight in weights.items():
            count = self.statistics['severity_counts'].get(severity, 0)
            score += count * weight

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
        """Generate executive summary"""
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
            'modules_assessed': self.statistics['modules_run'],
            'key_concerns': self._get_key_concerns()
        }

        return summary

    def _get_key_concerns(self):
        """Identify top 3-5 key security concerns"""
        concerns = []

        # Critical findings first
        critical = self.findings_by_severity.get('critical', [])
        for finding in critical[:3]:
            concerns.append({
                'severity': 'CRITICAL',
                'issue': finding.get('finding', 'N/A'),
                'module': finding.get('module', 'N/A')
            })

        # Then high severity if we need more
        if len(concerns) < 5:
            high = self.findings_by_severity.get('high', [])
            for finding in high[:5-len(concerns)]:
                concerns.append({
                    'severity': 'HIGH',
                    'issue': finding.get('finding', 'N/A'),
                    'module': finding.get('module', 'N/A')
                })

        return concerns

    def generate_json_report(self):
        """Generate complete report in JSON format"""
        report = {
            'metadata': {
                'report_generated': datetime.now().isoformat(),
                'report_version': '1.0',
                'framework': 'C2 Security Assessment Framework'
            },
            'agent_info': self.agent,
            'executive_summary': self.generate_executive_summary(),
            'statistics': self.statistics,
            'findings_by_severity': dict(self.findings_by_severity),
            'findings_by_module': dict(self.findings_by_module),
            'raw_results': self.results
        }

        return report

    def generate_markdown_report(self):
        """Generate professional Markdown report"""
        exec_summary = self.generate_executive_summary()
        risk_score = exec_summary['risk_score']
        risk_level = exec_summary['risk_level']

        md = []

        # Header
        md.append("# Security Assessment Report")
        md.append("")
        md.append(f"**Generated:** {exec_summary['assessment_date']}")
        md.append(f"**Framework:** C2 Security Assessment Framework v1.0")
        md.append("")
        md.append("---")
        md.append("")

        # Executive Summary
        md.append("## Executive Summary")
        md.append("")
        md.append(f"**Target System:** {exec_summary['target_system']}")
        md.append(f"**Platform:** {exec_summary['platform']}")
        md.append(f"**Assessment Date:** {exec_summary['assessment_date']}")
        md.append("")
        md.append(f"### Overall Risk Assessment")
        md.append("")
        md.append(f"**Risk Level:** {risk_level}")
        md.append(f"**Risk Score:** {risk_score}/100")
        md.append("")

        # Risk meter visualization
        md.append("```")
        md.append(f"Risk Score: [{'=' * (risk_score // 5)}{'.' * (20 - risk_score // 5)}] {risk_score}%")
        md.append("```")
        md.append("")

        # Statistics
        md.append("### Key Statistics")
        md.append("")
        md.append(f"- **Total Findings:** {self.statistics['total_findings']}")
        md.append(f"- **Critical Issues:** {self.statistics['critical_findings']}")
        md.append(f"- **High Severity Issues:** {self.statistics['high_findings']}")
        md.append(f"- **Medium Severity Issues:** {self.statistics['medium_findings']}")
        md.append(f"- **Low Severity Issues:** {self.statistics['low_findings']}")
        md.append(f"- **Informational Items:** {self.statistics['info_findings']}")
        md.append(f"- **Modules Assessed:** {self.statistics['modules_run']}")
        md.append("")

        # Severity Distribution Chart
        md.append("### Findings Distribution")
        md.append("")
        md.append("| Severity | Count | Percentage |")
        md.append("|----------|-------|------------|")
        total = self.statistics['total_findings'] or 1
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = self.statistics['severity_counts'].get(severity, 0)
            pct = (count / total) * 100
            md.append(f"| {severity.capitalize()} | {count} | {pct:.1f}% |")
        md.append("")

        # Key Concerns
        if exec_summary['key_concerns']:
            md.append("### Key Security Concerns")
            md.append("")
            for i, concern in enumerate(exec_summary['key_concerns'], 1):
                md.append(f"{i}. **[{concern['severity']}]** {concern['issue']}")
                md.append(f"   - Module: {concern['module']}")
                md.append("")

        md.append("---")
        md.append("")

        # Detailed Findings by Severity
        md.append("## Detailed Findings")
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
                md.append(f"#### {severity.upper()}-{i}: {finding.get('finding', 'N/A')}")
                md.append("")
                md.append(f"**Module:** {finding.get('module', 'N/A')}")
                md.append("")
                md.append(f"**Description:**")
                md.append(f"{finding.get('description', 'N/A')}")
                md.append("")
                md.append(f"**Remediation:**")
                md.append(f"{finding.get('remediation', 'N/A')}")
                md.append("")
                md.append("---")
                md.append("")

        # Module Summary
        md.append("## Assessment Module Summary")
        md.append("")
        md.append("| Module | Findings | Status |")
        md.append("|--------|----------|--------|")

        for module, count in self.statistics['module_counts'].items():
            status = "✅ Complete"
            md.append(f"| {module} | {count} | {status} |")

        md.append("")

        # Recommendations
        md.append("## Recommendations")
        md.append("")
        md.append("### Immediate Actions (Critical Priority)")
        md.append("")

        critical_findings = self.findings_by_severity.get('critical', [])
        if critical_findings:
            for finding in critical_findings:
                md.append(f"- {finding.get('remediation', 'N/A')}")
        else:
            md.append("- No critical issues identified")

        md.append("")
        md.append("### High Priority Actions")
        md.append("")

        high_findings = self.findings_by_severity.get('high', [])
        if high_findings:
            for finding in high_findings[:5]:  # Top 5
                md.append(f"- {finding.get('remediation', 'N/A')}")
        else:
            md.append("- No high priority issues identified")

        md.append("")
        md.append("---")
        md.append("")

        # Footer
        md.append("## Report Information")
        md.append("")
        md.append(f"- **Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"- **Framework Version:** 1.0")
        md.append(f"- **Agent ID:** {self.agent.get('agent_id', 'N/A')}")
        md.append("")
        md.append("---")
        md.append("")
        md.append("*This report was generated by the C2 Security Assessment Framework*")
        md.append("")

        return "\n".join(md)

    def generate_html_report(self):
        """Generate professional HTML report"""
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

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {exec_summary['target_system']}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}

        header {{
            border-bottom: 4px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}

        h1 {{
            color: #007bff;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        h2 {{
            color: #0056b3;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e9ecef;
        }}

        h3 {{
            color: #495057;
            margin-top: 20px;
            margin-bottom: 10px;
        }}

        .metadata {{
            color: #6c757d;
            font-size: 0.9em;
            margin-bottom: 20px;
        }}

        .risk-score {{
            background: linear-gradient(135deg, {risk_color} 0%, {risk_color}dd 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin: 30px 0;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}

        .risk-score h2 {{
            color: white;
            border: none;
            margin: 0;
            font-size: 2em;
        }}

        .risk-score .score {{
            font-size: 4em;
            font-weight: bold;
            margin: 10px 0;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}

        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
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
            margin: 0;
            font-size: 0.9em;
            color: #6c757d;
        }}

        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #212529;
        }}

        .finding {{
            background: #fff;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }}

        .finding.critical {{
            border-left: 5px solid #dc3545;
        }}

        .finding.high {{
            border-left: 5px solid #fd7e14;
        }}

        .finding.medium {{
            border-left: 5px solid #ffc107;
        }}

        .finding.low {{
            border-left: 5px solid #17a2b8;
        }}

        .finding.info {{
            border-left: 5px solid #6c757d;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}

        .finding-title {{
            font-size: 1.2em;
            font-weight: bold;
            color: #212529;
        }}

        .severity-badge {{
            padding: 5px 15px;
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

        .finding-section {{
            margin: 10px 0;
        }}

        .finding-label {{
            font-weight: bold;
            color: #495057;
            margin-bottom: 5px;
        }}

        .finding-content {{
            color: #212529;
            padding-left: 20px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}

        th {{
            background: #007bff;
            color: white;
            font-weight: bold;
        }}

        tr:hover {{
            background: #f8f9fa;
        }}

        .key-concern {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }}

        footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #e9ecef;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
        }}

        .progress-bar {{
            width: 100%;
            height: 30px;
            background: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }}

        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, {risk_color} 0%, {risk_color}dd 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            transition: width 0.3s ease;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Assessment Report</h1>
            <div class="metadata">
                <p><strong>Generated:</strong> {exec_summary['assessment_date']}</p>
                <p><strong>Framework:</strong> C2 Security Assessment Framework v1.0</p>
            </div>
        </header>

        <section id="executive-summary">
            <h2>Executive Summary</h2>
            <p><strong>Target System:</strong> {exec_summary['target_system']}</p>
            <p><strong>Platform:</strong> {exec_summary['platform']}</p>
            <p><strong>Assessment Date:</strong> {exec_summary['assessment_date']}</p>

            <div class="risk-score">
                <h2>Overall Risk Assessment</h2>
                <div class="score">{risk_score}/100</div>
                <h3>{risk_level} RISK</h3>
            </div>

            <div class="progress-bar">
                <div class="progress-fill" style="width: {risk_score}%;">
                    {risk_score}%
                </div>
            </div>

            <h3>Key Statistics</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Total Findings</h3>
                    <div class="value">{self.statistics['total_findings']}</div>
                </div>
                <div class="stat-card critical">
                    <h3>Critical</h3>
                    <div class="value">{self.statistics['critical_findings']}</div>
                </div>
                <div class="stat-card high">
                    <h3>High</h3>
                    <div class="value">{self.statistics['high_findings']}</div>
                </div>
                <div class="stat-card medium">
                    <h3>Medium</h3>
                    <div class="value">{self.statistics['medium_findings']}</div>
                </div>
                <div class="stat-card low">
                    <h3>Low</h3>
                    <div class="value">{self.statistics['low_findings']}</div>
                </div>
                <div class="stat-card">
                    <h3>Info</h3>
                    <div class="value">{self.statistics['info_findings']}</div>
                </div>
            </div>
"""

        # Key Concerns
        if exec_summary['key_concerns']:
            html += """
            <h3>Key Security Concerns</h3>
"""
            for concern in exec_summary['key_concerns']:
                html += f"""
            <div class="key-concern">
                <strong>[{concern['severity']}]</strong> {concern['issue']}<br>
                <small>Module: {concern['module']}</small>
            </div>
"""

        html += """
        </section>

        <section id="detailed-findings">
            <h2>Detailed Findings</h2>
"""

        # Detailed findings by severity
        severity_order = ['critical', 'high', 'medium', 'low', 'info']

        for severity in severity_order:
            findings = self.findings_by_severity.get(severity, [])
            if not findings:
                continue

            html += f"""
            <h3>{severity.upper()} Severity ({len(findings)} findings)</h3>
"""

            for i, finding in enumerate(findings, 1):
                html += f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">{finding.get('finding', 'N/A')}</div>
                    <div class="severity-badge {severity}">{severity.upper()}</div>
                </div>
                <div class="finding-section">
                    <div class="finding-label">Module:</div>
                    <div class="finding-content">{finding.get('module', 'N/A')}</div>
                </div>
                <div class="finding-section">
                    <div class="finding-label">Description:</div>
                    <div class="finding-content">{finding.get('description', 'N/A')}</div>
                </div>
                <div class="finding-section">
                    <div class="finding-label">Remediation:</div>
                    <div class="finding-content">{finding.get('remediation', 'N/A')}</div>
                </div>
            </div>
"""

        html += """
        </section>

        <section id="module-summary">
            <h2>Assessment Module Summary</h2>
            <table>
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Findings</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
"""

        for module, count in self.statistics['module_counts'].items():
            html += f"""
                    <tr>
                        <td>{module}</td>
                        <td>{count}</td>
                        <td>✅ Complete</td>
                    </tr>
"""

        html += """
                </tbody>
            </table>
        </section>

        <footer>
            <p><strong>Report Generated:</strong> """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
            <p><strong>Agent ID:</strong> """ + self.agent.get('agent_id', 'N/A') + """</p>
            <p><em>This report was generated by the C2 Security Assessment Framework</em></p>
        </footer>
    </div>
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
            print(f"[+] JSON report saved: {json_path}")

        if format in ['markdown', 'all']:
            md_path = os.path.join(output_dir, f"{base_filename}.md")
            with open(md_path, 'w') as f:
                f.write(self.generate_markdown_report())
            saved_files['markdown'] = md_path
            print(f"[+] Markdown report saved: {md_path}")

        if format in ['html', 'all']:
            html_path = os.path.join(output_dir, f"{base_filename}.html")
            with open(html_path, 'w') as f:
                f.write(self.generate_html_report())
            saved_files['html'] = html_path
            print(f"[+] HTML report saved: {html_path}")

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
            print(f"[!] Failed to fetch agents: {agents_response.status_code}")
            return None

        agents = agents_response.json().get('agents', [])
        agent_data = None

        for agent in agents:
            if agent['agent_id'] == agent_id:
                agent_data = agent
                break

        if not agent_data:
            print(f"[!] Agent {agent_id} not found")
            return None

        # Fetch results
        results_response = requests.get(f"{server_url}/api/results/{agent_id}", timeout=10)
        if results_response.status_code != 200:
            print(f"[!] Failed to fetch results: {results_response.status_code}")
            return None

        results_data = results_response.json().get('results', [])

        if not results_data:
            print(f"[!] No results found for agent {agent_id}")
            return None

        # Generate report
        generator = ReportGenerator(agent_data, results_data)
        saved_files = generator.save_report(output_dir, format)

        return saved_files

    except Exception as e:
        print(f"[!] Error generating report: {e}")
        return None


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 3:
        print("Usage: python report_generator.py <server_url> <agent_id> [format] [output_dir]")
        print("Formats: json, markdown, html, all (default: all)")
        print("Example: python report_generator.py http://localhost:8542 abc123 all reports/")
        sys.exit(1)

    server_url = sys.argv[1]
    agent_id = sys.argv[2]
    format_type = sys.argv[3] if len(sys.argv) > 3 else 'all'
    output_dir = sys.argv[4] if len(sys.argv) > 4 else 'reports'

    print(f"[*] Generating report for agent: {agent_id}")
    print(f"[*] Format: {format_type}")

    result = generate_report_from_server(server_url, agent_id, output_dir, format_type)

    if result:
        print("\n[+] Report generation complete!")
        print(f"[*] Files saved in: {output_dir}/")
    else:
        print("\n[!] Report generation failed")
