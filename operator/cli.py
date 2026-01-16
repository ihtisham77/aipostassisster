#!/usr/bin/env python3
"""
C2 Operator CLI
Command-line interface for interacting with C2 agents
"""

import requests
import json
import sys
import os
from datetime import datetime

# Add current directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_generator import AgentGenerator
from config import get_config
from report_generator import generate_report_from_server
from module_registry import get_compatible_modules, get_module_list_formatted, get_modules_by_priority, MODULES

class OperatorCLI:
    def __init__(self, server_url):
        self.server_url = server_url.rstrip('/')

    def list_agents(self):
        """List all registered agents"""
        try:
            response = requests.get(f"{self.server_url}/api/agents", timeout=10)

            if response.status_code == 200:
                data = response.json()
                agents = data.get('agents', [])

                if not agents:
                    print("\n[*] No agents registered")
                    return

                print("\n╔═══════════════════════════════════════════════════════════════════════╗")
                print("║                          REGISTERED AGENTS                            ║")
                print("╚═══════════════════════════════════════════════════════════════════════╝\n")

                for agent in agents:
                    # Determine OS type
                    platform = agent['platform']
                    if 'Windows' in platform:
                        os_icon = "🪟"
                        os_type = "Windows"
                    elif 'Linux' in platform:
                        os_icon = "🐧"
                        os_type = "Linux"
                    elif 'Darwin' in platform or 'Mac' in platform:
                        os_icon = "🍎"
                        os_type = "macOS"
                    else:
                        os_icon = "💻"
                        os_type = "Unknown"

                    # Get compatible modules count
                    compatible_modules = get_compatible_modules(platform)

                    status_icon = "✅" if agent['status'] == 'active' else "⚠️"

                    print(f"Agent ID:        {agent['agent_id']}")
                    print(f"Hostname:        {agent['hostname']}")
                    print(f"Platform:        {os_icon} {platform}")
                    print(f"OS Type:         {os_type}")
                    print(f"IP Address:      {agent['ip_address']}")
                    print(f"Status:          {status_icon} {agent['status']}")
                    print(f"Last Seen:       {agent['last_seen']}")
                    print(f"Commands Run:    {agent['commands_executed']}")
                    print(f"Compatible Mods: {len(compatible_modules)}/{len(MODULES)}")
                    print("-" * 75)

                print(f"\nTotal Agents: {len(agents)}\n")

            else:
                print(f"[!] Error: {response.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"[!] Connection error: {e}")

    def get_results(self, agent_id):
        """Get assessment results for an agent"""
        try:
            response = requests.get(f"{self.server_url}/api/results/{agent_id}", timeout=10)

            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])

                if not results:
                    print(f"\n[*] No results for agent {agent_id}")
                    return

                print(f"\n╔═══════════════════════════════════════════════════════════════════════╗")
                print(f"║                    RESULTS FOR AGENT: {agent_id[:20]:<20} ║")
                print("╚═══════════════════════════════════════════════════════════════════════╝\n")

                for result in results:
                    print(f"Timestamp: {result['timestamp']}")
                    print(f"Module:    {result['module']}")
                    print(f"Results:")
                    print(json.dumps(result['results'], indent=2))
                    print("=" * 75)

            else:
                print(f"[!] Error: {response.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"[!] Connection error: {e}")

    def run_module(self, agent_id, module_name):
        """Run a security assessment module on an agent"""
        try:
            # Check if "all" modules requested
            if module_name.lower() == "all":
                return self.run_all_modules(agent_id)

            command = {
                "type": "module",
                "module": module_name
            }

            response = requests.post(
                f"{self.server_url}/api/command",
                json={"agent_id": agent_id, "command": command},
                timeout=10
            )

            if response.status_code == 200:
                print(f"[+] Module '{module_name}' queued for agent {agent_id}")
                print("[*] Results will be available shortly using 'results' command")
            else:
                print(f"[!] Error: {response.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"[!] Connection error: {e}")

    def run_all_modules(self, agent_id):
        """Run all compatible modules on an agent"""
        try:
            # Get agent info to determine OS
            response = requests.get(f"{self.server_url}/api/agents", timeout=10)
            if response.status_code != 200:
                print(f"[!] Error fetching agent info: {response.status_code}")
                return

            agents = response.json().get('agents', [])
            agent = None
            for a in agents:
                if a['agent_id'] == agent_id:
                    agent = a
                    break

            if not agent:
                print(f"[!] Agent {agent_id} not found")
                return

            # Get compatible modules for this agent's OS
            platform = agent['platform']
            compatible_modules = get_modules_by_priority(platform)

            if not compatible_modules:
                print(f"[!] No compatible modules found for {platform}")
                return

            print(f"\n[*] Running {len(compatible_modules)} modules on {agent['hostname']} ({platform})")
            print(f"[*] Modules: {', '.join(compatible_modules)}\n")

            # Queue all modules
            queued = 0
            for module_name in compatible_modules:
                command = {
                    "type": "module",
                    "module": module_name
                }

                response = requests.post(
                    f"{self.server_url}/api/command",
                    json={"agent_id": agent_id, "command": command},
                    timeout=10
                )

                if response.status_code == 200:
                    print(f"  ✓ Queued: {module_name}")
                    queued += 1
                else:
                    print(f"  ✗ Failed: {module_name}")

            print(f"\n[+] Successfully queued {queued}/{len(compatible_modules)} modules")
            print(f"[*] Agent will execute modules automatically")
            print(f"[*] Use 'results {agent_id}' to view results")
            print(f"[*] Use 'report {agent_id}' to generate comprehensive report\n")

        except requests.exceptions.RequestException as e:
            print(f"[!] Connection error: {e}")
        except Exception as e:
            print(f"[!] Error: {e}")

    def run_shell_command(self, agent_id, command):
        """Run a shell command on an agent"""
        try:
            cmd = {
                "type": "shell",
                "cmd": command
            }

            response = requests.post(
                f"{self.server_url}/api/command",
                json={"agent_id": agent_id, "command": cmd},
                timeout=10
            )

            if response.status_code == 200:
                print(f"[+] Command queued for agent {agent_id}")
                print("[*] Results will be available shortly using 'results' command")
            else:
                print(f"[!] Error: {response.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"[!] Connection error: {e}")

    def generate_agent(self, platform, operator_url=None):
        """Generate a new agent"""
        try:
            generator = AgentGenerator(operator_url)
            result = generator.generate_agent(platform)

            print(f"\n[+] Agent generated successfully!")
            print(f"[*] Agent ID:     {result['agent_id']}")
            print(f"[*] Platform:     {result['platform']}")
            print(f"[*] Operator URL: {generator.operator_url}")
            print(f"[*] Output Path:  {result['output_path']}")
            print(f"\n[*] Deploy this agent on the target {platform} system")
            print(f"[*] Run: python3 {result['output_path']}\n")

        except Exception as e:
            print(f"[!] Error generating agent: {e}")

    def show_modules(self, os_filter=None):
        """Show available security assessment modules"""
        print("\n╔═══════════════════════════════════════════════════════════════════════╗")
        print("║                    SECURITY ASSESSMENT MODULES                        ║")
        print("╚═══════════════════════════════════════════════════════════════════════╝\n")

        if os_filter:
            print(f"Showing modules compatible with: {os_filter}\n")
            modules_list = get_module_list_formatted(os_filter)
        else:
            print("Showing all modules (all operating systems)\n")
            modules_list = get_module_list_formatted()

        print(f"{'Module ID':<25} {'Description':<35} {'OS Support':<15}")
        print("-" * 75)

        for module_id, name, description, os_list in modules_list:
            print(f"{module_id:<25} {description:<35} {os_list:<15}")

        print()
        print(f"Total modules: {len(modules_list)}")
        print()
        print("Usage:")
        print("  module <agent_id> <module_name>  - Run single module")
        print("  module <agent_id> all            - Run ALL compatible modules")
        print()

    def generate_report(self, agent_id, format_type='all', output_dir='reports'):
        """Generate comprehensive security assessment report"""
        try:
            print(f"\n[*] Generating {format_type} report for agent {agent_id}...")

            result = generate_report_from_server(
                self.server_url,
                agent_id,
                output_dir,
                format_type
            )

            if result:
                print("\n[+] Report generation complete!")
                print(f"[*] Reports saved in: {output_dir}/\n")

                for format_name, file_path in result.items():
                    print(f"  - {format_name.upper()}: {file_path}")

                print()
            else:
                print("\n[!] Report generation failed")
                print("[*] Make sure the agent has completed assessments\n")

        except Exception as e:
            print(f"[!] Error generating report: {e}")

    def interactive_mode(self):
        """Run CLI in interactive mode"""
        print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║             C2 Operator CLI - Interactive Mode                ║
    ║         Security Assessment Framework v1.0                    ║
    ╚═══════════════════════════════════════════════════════════════╝

    Commands:
      agents                             - List all agents with OS info
      results <agent_id>                 - Get results for an agent
      module <agent_id> <module_name>    - Run single module (or 'all' for all modules)
      shell <agent_id> <command>         - Run shell command
      report <agent_id> [format] [dir]   - Generate report (all/json/html/md)
      generate <platform> [url]          - Generate new agent (URL optional)
      modules [os]                       - List modules (optionally filter by OS)
      help                               - Show this help
      exit                               - Exit CLI

        """)

        while True:
            try:
                cmd = input("operator> ").strip()

                if not cmd:
                    continue

                parts = cmd.split(maxsplit=2)
                command = parts[0].lower()

                if command == "exit" or command == "quit":
                    print("\n[*] Goodbye!")
                    break

                elif command == "help":
                    print("""
    Commands:
      agents                             - List all agents with OS info
      results <agent_id>                 - Get results for an agent
      module <agent_id> <module_name>    - Run single module (or 'all' for all modules)
      shell <agent_id> <command>         - Run shell command
      report <agent_id> [format] [dir]   - Generate report (all/json/html/md)
      generate <platform> [url]          - Generate new agent (URL optional)
      modules [os]                       - List modules (optionally filter by OS)
      help                               - Show this help
      exit                               - Exit CLI
                    """)

                elif command == "agents":
                    self.list_agents()

                elif command == "results":
                    if len(parts) < 2:
                        print("[!] Usage: results <agent_id>")
                        continue
                    self.get_results(parts[1])

                elif command == "module":
                    if len(parts) < 3:
                        print("[!] Usage: module <agent_id> <module_name>")
                        continue
                    self.run_module(parts[1], parts[2])

                elif command == "shell":
                    if len(parts) < 3:
                        print("[!] Usage: shell <agent_id> <command>")
                        continue
                    self.run_shell_command(parts[1], parts[2])

                elif command == "generate":
                    if len(parts) < 2:
                        print("[!] Usage: generate <platform> [operator_url]")
                        print("[!] Platform: windows or linux")
                        print("[!] URL is optional - will auto-detect if not provided")
                        continue
                    operator_url = parts[2] if len(parts) >= 3 else None
                    self.generate_agent(parts[1], operator_url)

                elif command == "modules":
                    os_filter = parts[1] if len(parts) >= 2 else None
                    self.show_modules(os_filter)

                elif command == "report":
                    if len(parts) < 2:
                        print("[!] Usage: report <agent_id> [format] [output_dir]")
                        print("[!] Formats: all, json, html, markdown")
                        continue
                    agent_id = parts[1]
                    format_type = parts[2] if len(parts) >= 3 else 'all'
                    output_dir = parts[3] if len(parts) >= 4 else 'reports'
                    self.generate_report(agent_id, format_type, output_dir)

                else:
                    print(f"[!] Unknown command: {command}")
                    print("[*] Type 'help' for available commands")

            except KeyboardInterrupt:
                print("\n[*] Use 'exit' to quit")
            except Exception as e:
                print(f"[!] Error: {e}")

def main():
    # Auto-detect server URL from config or command line
    if len(sys.argv) >= 2:
        server_url = sys.argv[1]
    else:
        # Load from config
        config = get_config()
        server_url = config.get_server_url()
        print(f"[*] Auto-detected server URL: {server_url}")
        print("[*] You can override with: python cli.py <server_url>\n")

    cli = OperatorCLI(server_url)

    # Check if server is online
    try:
        response = requests.get(f"{server_url}/api/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            print(f"[+] Connected to operator server at {server_url}")
            print(f"[*] Active agents: {health_data.get('active_agents', 0)}")
            print(f"[*] Total agents: {health_data.get('total_agents', 0)}\n")
        else:
            print(f"[!] Server returned status code: {response.status_code}")
    except requests.exceptions.RequestException:
        print(f"[!] Warning: Cannot connect to operator server at {server_url}")
        print("[*] Make sure the operator server is running")
        print("[*] Start server with: python operator/server.py\n")

    cli.interactive_mode()

if __name__ == '__main__':
    main()
