"""
Attack Path Generation System
Builds actionable attack chains from assessment findings
"""

import json
from typing import Dict, List, Any, Tuple, Set
from collections import defaultdict


class AttackPathGenerator:
    """
    Generates attack paths by connecting findings across assessment phases
    """

    # Phase dependencies (what each phase enables)
    PHASE_DEPENDENCIES = {
        'reconnaissance': ['credential_access', 'privilege_escalation', 'lateral_movement'],
        'credential_access': ['privilege_escalation', 'lateral_movement', 'exfiltration'],
        'privilege_escalation': ['persistence', 'credential_access', 'lateral_movement', 'exfiltration'],
        'persistence': ['lateral_movement', 'exfiltration'],
        'lateral_movement': ['reconnaissance', 'credential_access', 'privilege_escalation'],
        'exfiltration': ['cleanup'],
        'cleanup': []
    }

    def __init__(self, all_results: Dict, risk_scorer=None):
        """
        Initialize with full assessment results

        Args:
            all_results: Dict of {module_name: results}
            risk_scorer: Optional RiskScorer instance for risk-aware paths
        """
        self.all_results = all_results
        self.risk_scorer = risk_scorer
        self.attack_graph = defaultdict(list)
        self.paths = []

    def build_attack_graph(self) -> Dict:
        """
        Build attack graph from all findings

        Returns graph structure connecting phases
        """
        graph = {
            'nodes': [],  # Each finding is a node
            'edges': [],  # Connections between findings
            'phases': {}  # Findings grouped by phase
        }

        node_id = 0

        # Create nodes for each finding
        for module, results in self.all_results.items():
            if not isinstance(results, dict) or 'findings' not in results:
                continue

            phase_nodes = []

            for finding in results['findings']:
                node = {
                    'id': node_id,
                    'phase': module,
                    'finding': finding.get('finding', 'Unknown'),
                    'severity': finding.get('severity', 'info'),
                    'description': finding.get('description', ''),
                    'risk_analysis': finding.get('risk_analysis', {})
                }

                graph['nodes'].append(node)
                phase_nodes.append(node_id)
                node_id += 1

            graph['phases'][module] = phase_nodes

        # Create edges based on phase dependencies and finding relationships
        self._create_edges(graph)

        return graph

    def _create_edges(self, graph: Dict):
        """Create edges connecting related findings"""

        nodes = graph['nodes']

        for i, source_node in enumerate(nodes):
            source_phase = source_node['phase']
            source_desc = source_node['description'].lower()
            source_finding = source_node['finding'].lower()

            # Check phase dependencies
            next_phases = self.PHASE_DEPENDENCIES.get(source_phase, [])

            for j, target_node in enumerate(nodes):
                if i == j:
                    continue

                target_phase = target_node['phase']
                target_desc = target_node['description'].lower()
                target_finding = target_node['finding'].lower()

                # Edge weight (strength of relationship)
                weight = 0

                # Phase dependency edge
                if target_phase in next_phases:
                    weight += 30

                # Specific relationships
                weight += self._calculate_relationship_weight(
                    source_node, target_node,
                    source_desc, target_desc
                )

                if weight > 0:
                    graph['edges'].append({
                        'source': source_node['id'],
                        'target': target_node['id'],
                        'weight': weight,
                        'relationship': self._describe_relationship(source_node, target_node)
                    })

    def _calculate_relationship_weight(self, source: Dict, target: Dict,
                                       source_desc: str, target_desc: str) -> int:
        """Calculate relationship strength between two findings"""
        weight = 0

        source_phase = source['phase']
        target_phase = target['phase']

        # Credential → Privilege Escalation
        if source_phase == 'credential_access' and target_phase == 'privilege_escalation':
            if 'admin' in source_desc or 'sudo' in source_desc or 'password' in source_desc:
                weight += 40

        # Credential → Lateral Movement
        if source_phase == 'credential_access' and target_phase == 'lateral_movement':
            if any(k in source_desc for k in ['ssh', 'rdp', 'smb', 'winrm', 'credential']):
                weight += 50

        # Privilege Escalation → Persistence
        if source_phase == 'privilege_escalation' and target_phase == 'persistence':
            if 'admin' in source_desc or 'root' in source_desc:
                weight += 45

        # Privilege Escalation → Credential Access
        if source_phase == 'privilege_escalation' and target_phase == 'credential_access':
            if 'lsass' in target_desc or 'sam' in target_desc or '/etc/shadow' in target_desc:
                weight += 40

        # Reconnaissance → Any phase
        if source_phase == 'reconnaissance':
            if 'network' in source_desc and target_phase == 'lateral_movement':
                weight += 25
            if 'user' in source_desc and target_phase == 'credential_access':
                weight += 20
            if 'service' in source_desc and target_phase == 'privilege_escalation':
                weight += 25

        # Any → Exfiltration
        if target_phase == 'exfiltration':
            if 'database' in source_desc or 'credential' in source_desc or 'sensitive' in source_desc:
                weight += 35
            if source_phase == 'lateral_movement':
                weight += 30

        # Exfiltration → Cleanup
        if source_phase == 'exfiltration' and target_phase == 'cleanup':
            weight += 40

        return weight

    def _describe_relationship(self, source: Dict, target: Dict) -> str:
        """Describe the relationship between two findings"""
        source_phase = source['phase']
        target_phase = target['phase']

        relationships = {
            ('reconnaissance', 'credential_access'): 'Enables credential hunting',
            ('reconnaissance', 'privilege_escalation'): 'Reveals escalation vectors',
            ('reconnaissance', 'lateral_movement'): 'Identifies movement targets',
            ('credential_access', 'privilege_escalation'): 'Credentials enable escalation',
            ('credential_access', 'lateral_movement'): 'Credentials enable movement',
            ('credential_access', 'exfiltration'): 'Credentials are valuable data',
            ('privilege_escalation', 'persistence'): 'Admin rights enable persistence',
            ('privilege_escalation', 'credential_access'): 'Admin access to credential stores',
            ('privilege_escalation', 'exfiltration'): 'Admin access to all data',
            ('persistence', 'lateral_movement'): 'Persistent access enables exploration',
            ('lateral_movement', 'reconnaissance'): 'New host requires recon',
            ('lateral_movement', 'exfiltration'): 'Access to additional data sources',
            ('exfiltration', 'cleanup'): 'Remove exfiltration traces'
        }

        return relationships.get((source_phase, target_phase), 'Related finding')

    def generate_attack_paths(self, max_paths: int = 10) -> List[Dict]:
        """
        Generate ranked attack paths from initial access to objectives

        Returns list of attack path dictionaries
        """
        graph = self.build_attack_graph()

        paths = []

        # Start from reconnaissance findings
        recon_nodes = [n for n in graph['nodes'] if n['phase'] == 'reconnaissance']

        # For each recon node, find paths to objectives
        for start_node in recon_nodes:
            self._find_paths_from_node(
                start_node,
                graph,
                current_path=[start_node],
                visited=set([start_node['id']]),
                paths=paths,
                max_depth=6
            )

        # Rank paths
        ranked_paths = self._rank_paths(paths)

        return ranked_paths[:max_paths]

    def _find_paths_from_node(self, current_node: Dict, graph: Dict,
                              current_path: List[Dict], visited: Set[int],
                              paths: List[List[Dict]], max_depth: int):
        """Recursively find paths through the attack graph"""

        if len(current_path) >= max_depth:
            # Save this path
            paths.append(current_path.copy())
            return

        # Find outgoing edges
        outgoing = [e for e in graph['edges'] if e['source'] == current_node['id']]

        if not outgoing:
            # End of path
            if len(current_path) >= 3:  # Minimum viable path
                paths.append(current_path.copy())
            return

        # Follow edges
        for edge in outgoing:
            target_id = edge['target']

            if target_id in visited:
                continue

            target_node = next((n for n in graph['nodes'] if n['id'] == target_id), None)

            if target_node:
                current_path.append(target_node)
                visited.add(target_id)

                self._find_paths_from_node(
                    target_node, graph,
                    current_path, visited,
                    paths, max_depth
                )

                current_path.pop()
                visited.remove(target_id)

    def _rank_paths(self, paths: List[List[Dict]]) -> List[Dict]:
        """
        Rank attack paths by value and feasibility

        Returns sorted list of path dictionaries
        """
        ranked = []

        for path_nodes in paths:
            # Calculate path metrics
            path_score = self._score_path(path_nodes)

            path_dict = {
                'steps': [],
                'phases': [],
                'total_impact': path_score['total_impact'],
                'avg_feasibility': path_score['avg_feasibility'],
                'avg_stealth': path_score['avg_stealth'],
                'overall_score': path_score['overall_score'],
                'length': len(path_nodes),
                'risk_level': path_score['risk_level'],
                'recommendation': path_score['recommendation']
            }

            for i, node in enumerate(path_nodes):
                phase = node['phase']
                step = {
                    'step_number': i + 1,
                    'phase': phase,
                    'action': node['finding'],
                    'description': node['description'],
                    'severity': node['severity']
                }

                if 'risk_analysis' in node:
                    step['risk_analysis'] = node['risk_analysis']

                path_dict['steps'].append(step)

                if phase not in path_dict['phases']:
                    path_dict['phases'].append(phase)

            ranked.append(path_dict)

        # Sort by overall score
        ranked.sort(key=lambda x: x['overall_score'], reverse=True)

        return ranked

    def _score_path(self, path_nodes: List[Dict]) -> Dict:
        """Score an attack path"""

        total_impact = 0
        total_feasibility = 0
        total_stealth = 0
        count = len(path_nodes)

        for node in path_nodes:
            risk = node.get('risk_analysis', {})

            total_impact += risk.get('impact_score', 50)
            total_feasibility += risk.get('feasibility_score', 50)
            total_stealth += risk.get('stealth_score', 50)

        avg_impact = total_impact / count if count > 0 else 0
        avg_feasibility = total_feasibility / count if count > 0 else 0
        avg_stealth = total_stealth / count if count > 0 else 0

        # Weighted overall score
        overall_score = (
            avg_impact * 0.4 +
            avg_feasibility * 0.35 +
            avg_stealth * 0.25
        )

        # Determine risk level
        if avg_stealth >= 70:
            risk_level = 'Low Risk'
        elif avg_stealth >= 50:
            risk_level = 'Moderate Risk'
        elif avg_stealth >= 30:
            risk_level = 'High Risk'
        else:
            risk_level = 'Very High Risk'

        # Generate recommendation
        if overall_score >= 75:
            recommendation = 'RECOMMENDED: High-value path with good feasibility and stealth'
        elif overall_score >= 60:
            recommendation = 'VIABLE: Balanced path worth considering'
        elif avg_feasibility < 50:
            recommendation = 'CHALLENGING: Low feasibility, requires preparation'
        elif avg_stealth < 40:
            recommendation = 'RISKY: High detection likelihood, use with caution'
        else:
            recommendation = 'ASSESS: Review individual steps carefully'

        return {
            'total_impact': avg_impact,
            'avg_feasibility': avg_feasibility,
            'avg_stealth': avg_stealth,
            'overall_score': overall_score,
            'risk_level': risk_level,
            'recommendation': recommendation
        }

    def get_quick_wins(self) -> List[Dict]:
        """
        Identify quick win opportunities (high impact, low noise, high feasibility)

        Returns list of individual findings that are immediate opportunities
        """
        quick_wins = []

        for module, results in self.all_results.items():
            if not isinstance(results, dict) or 'findings' not in results:
                continue

            for finding in results['findings']:
                risk = finding.get('risk_analysis', {})

                impact = risk.get('impact_score', 0)
                noise = risk.get('noise_score', 100)
                feasibility = risk.get('feasibility_score', 0)

                # Quick win criteria
                if impact >= 60 and noise <= 40 and feasibility >= 70:
                    quick_wins.append({
                        'phase': module,
                        'finding': finding.get('finding', 'Unknown'),
                        'description': finding.get('description', ''),
                        'impact': impact,
                        'noise': noise,
                        'feasibility': feasibility,
                        'recommendation': risk.get('recommendation', ''),
                        'why_quick_win': f'High impact ({impact}), Low noise ({noise}), High feasibility ({feasibility})'
                    })

        # Sort by impact
        quick_wins.sort(key=lambda x: x['impact'], reverse=True)

        return quick_wins

    def get_critical_risks(self) -> List[Dict]:
        """
        Identify critical security risks that should be prioritized

        Returns list of critical findings
        """
        critical_risks = []

        for module, results in self.all_results.items():
            if not isinstance(results, dict) or 'findings' not in results:
                continue

            for finding in results['findings']:
                severity = finding.get('severity', 'info')
                risk = finding.get('risk_analysis', {})

                # Critical risk criteria
                if severity in ['critical', 'high'] and risk.get('feasibility_score', 0) >= 60:
                    critical_risks.append({
                        'phase': module,
                        'severity': severity,
                        'finding': finding.get('finding', 'Unknown'),
                        'description': finding.get('description', ''),
                        'impact': risk.get('impact_score', 0),
                        'feasibility': risk.get('feasibility_score', 0),
                        'detection_likelihood': risk.get('detection_likelihood', 'Unknown'),
                        'recommendation': finding.get('remediation', '')
                    })

        # Sort by impact
        critical_risks.sort(key=lambda x: x['impact'], reverse=True)

        return critical_risks

    def export_attack_graph(self, output_format: str = 'json') -> str:
        """
        Export attack graph for visualization

        Args:
            output_format: 'json' or 'dot' (Graphviz)

        Returns formatted graph string
        """
        graph = self.build_attack_graph()

        if output_format == 'json':
            return json.dumps(graph, indent=2)

        elif output_format == 'dot':
            # Generate Graphviz DOT format
            dot = ['digraph AttackGraph {']
            dot.append('  rankdir=LR;')
            dot.append('  node [shape=box];')

            # Add nodes
            for node in graph['nodes']:
                label = f"{node['phase']}\\n{node['finding'][:40]}"
                color = self._get_severity_color(node['severity'])
                dot.append(f'  node{node["id"]} [label="{label}", color={color}];')

            # Add edges
            for edge in graph['edges']:
                weight = edge['weight']
                style = 'solid' if weight >= 40 else 'dashed'
                dot.append(f'  node{edge["source"]} -> node{edge["target"]} [style={style}, label="{weight}"];')

            dot.append('}')

            return '\n'.join(dot)

        return ''

    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            'critical': 'red',
            'high': 'orange',
            'medium': 'yellow',
            'low': 'lightblue',
            'info': 'gray'
        }
        return colors.get(severity, 'gray')


if __name__ == '__main__':
    # Test attack path generation
    test_results = {
        'reconnaissance': {
            'findings': [
                {
                    'finding': 'Domain-joined Windows workstation',
                    'description': 'System is joined to CORP.LOCAL domain',
                    'severity': 'info',
                    'risk_analysis': {'impact_score': 60, 'feasibility_score': 100, 'stealth_score': 95}
                }
            ]
        },
        'credential_access': {
            'findings': [
                {
                    'finding': 'Saved domain credentials found',
                    'description': 'Windows Credential Manager contains domain credentials',
                    'severity': 'high',
                    'risk_analysis': {'impact_score': 80, 'feasibility_score': 85, 'stealth_score': 70}
                }
            ]
        },
        'lateral_movement': {
            'findings': [
                {
                    'finding': 'SMB access to file server',
                    'description': 'Domain credentials grant access to \\\\fileserver\\share',
                    'severity': 'high',
                    'risk_analysis': {'impact_score': 85, 'feasibility_score': 90, 'stealth_score': 75}
                }
            ]
        }
    }

    generator = AttackPathGenerator(test_results)

    # Generate attack paths
    paths = generator.generate_attack_paths(max_paths=5)
    print(f"Generated {len(paths)} attack paths\n")

    if paths:
        print("Top Attack Path:")
        print(f"  Phases: {' → '.join(paths[0]['phases'])}")
        print(f"  Score: {paths[0]['overall_score']:.1f}")
        print(f"  Risk: {paths[0]['risk_level']}")
        print(f"  Steps: {paths[0]['length']}")

    # Get quick wins
    quick_wins = generator.get_quick_wins()
    print(f"\n{len(quick_wins)} Quick Win(s) identified")
