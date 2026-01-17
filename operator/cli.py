#!/usr/bin/env python3
"""
C2 Operator CLI - PRODUCTION ENHANCED
Command-line interface for interacting with C2 agents with comprehensive validation and status tracking
"""

import requests
import json
import sys
import os
import time
import re
from datetime import datetime

# Add current directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent_generator import AgentGenerator
from config import get_config
from report_generator import generate_report_from_server, Colors
from module_registry import get_compatible_modules, get_module_list_formatted, get_modules_by_priority, MODULES


class InputValidator:
    """Input validation utilities"""

    @staticmethod
    def validate_agent_id(agent_id):
        """Validate agent ID format"""
        if not agent_id:
            return False, "Agent ID cannot be empty"

        if len(agent_id) < 8:
            return False, "Agent ID must be at least 8 characters"

        # Check if it's alphanumeric with hyphens
        if not re.match(r'^[a-zA-Z0-9\-]+$', agent_id):
            return False, "Agent ID must be alphanumeric (with hyphens allowed)"

        return True, None

    @staticmethod
    def validate_module_name(module_name):
        """Validate module name"""
        if not module_name:
            return False, "Module name cannot be empty"

        if module_name.lower() == "all":
            return True, None

        # Check if module exists
        if module_name not in MODULES:
            return False, f"Module '{module_name}' not found. Use 'modules' command to see available modules"

        return True, None

    @staticmethod
    def validate_report_format(format_type):
        """Validate report format"""
        valid_formats = ['all', 'console', 'json', 'html', 'markdown', 'md']

        if format_type.lower() not in valid_formats:
            return False, f"Invalid format '{format_type}'. Valid formats: {', '.join(valid_formats)}"

        return True, None

    @staticmethod
    def validate_platform(platform):
        """Validate platform name"""
        valid_platforms = ['windows', 'linux', 'macos', 'darwin']

        if platform.lower() not in valid_platforms:
            return False, f"Invalid platform '{platform}'. Valid platforms: windows, linux, macos"

        return True, None

    @staticmethod
    def validate_url(url):
        """Validate URL format"""
        if not url:
            return True, None  # URL is optional

        # Basic URL validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or IP
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

        if not url_pattern.match(url):
            return False, "Invalid URL format. Use http://host:port or https://host:port"

        return True, None


class OperatorCLI:
    def __init__(self, server_url):
        self.server_url = server_url.rstrip('/')
        self.validator = InputValidator()

    def _validate_agent_exists(self, agent_id):
        """Check if agent exists on server"""
        try:
            response = requests.get(f"{self.server_url}/api/agents", timeout=10)
            if response.status_code == 200:
                agents = response.json().get('agents', [])
                for agent in agents:
                    if agent['agent_id'] == agent_id:
                        return True, agent
                return False, None
            else:
                return False, None
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error checking agent: {e}{Colors.ENDC}")
            return False, None

    def list_agents(self):
        """List all registered agents with enhanced display"""
        try:
            print(f"\n{Colors.BOLD}[*] Fetching registered agents...{Colors.ENDC}")
            response = requests.get(f"{self.server_url}/api/agents", timeout=10)

            if response.status_code == 200:
                data = response.json()
                agents = data.get('agents', [])

                if not agents:
                    print(f"\n{Colors.WARNING}[*] No agents registered{Colors.ENDC}")
                    print(f"{Colors.INFO}[*] Generate a new agent with: generate <platform>{Colors.ENDC}\n")
                    return

                print(f"\n{Colors.BOLD}{Colors.HEADER}╔═══════════════════════════════════════════════════════════════════════╗{Colors.ENDC}")
                print(f"{Colors.BOLD}{Colors.HEADER}║                          REGISTERED AGENTS                            ║{Colors.ENDC}")
                print(f"{Colors.BOLD}{Colors.HEADER}╚═══════════════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")

                for idx, agent in enumerate(agents, 1):
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

                    status_icon = f"{Colors.OKGREEN}✅{Colors.ENDC}" if agent['status'] == 'active' else f"{Colors.WARNING}⚠️{Colors.ENDC}"

                    print(f"{Colors.BOLD}Agent #{idx}{Colors.ENDC}")
                    print(f"  Agent ID:        {Colors.OKCYAN}{agent['agent_id']}{Colors.ENDC}")
                    print(f"  Hostname:        {agent['hostname']}")
                    print(f"  Platform:        {os_icon} {platform}")
                    print(f"  OS Type:         {os_type}")
                    print(f"  IP Address:      {agent['ip_address']}")
                    print(f"  Status:          {status_icon} {agent['status']}")
                    print(f"  Last Seen:       {agent['last_seen']}")
                    print(f"  Commands Run:    {agent['commands_executed']}")
                    print(f"  Compatible Mods: {Colors.OKGREEN}{len(compatible_modules)}{Colors.ENDC}/{len(MODULES)}")
                    print("-" * 75)

                print(f"\n{Colors.BOLD}Total Agents: {len(agents)}{Colors.ENDC}\n")
                print(f"{Colors.INFO}💡 Use 'module <agent_id> all' to run comprehensive assessment{Colors.ENDC}\n")

            else:
                print(f"{Colors.FAIL}[!] Server error: {response.status_code}{Colors.ENDC}")

        except requests.exceptions.RequestException as e:
            print(f"{Colors.FAIL}[!] Connection error: {e}{Colors.ENDC}")
            print(f"{Colors.WARNING}[*] Make sure the operator server is running{Colors.ENDC}")

    def get_results(self, agent_id):
        """Get assessment results for an agent"""
        # Validate input
        is_valid, error = self.validator.validate_agent_id(agent_id)
        if not is_valid:
            print(f"{Colors.FAIL}[!] Invalid agent ID: {error}{Colors.ENDC}")
            return

        # Check if agent exists
        exists, agent_data = self._validate_agent_exists(agent_id)
        if not exists:
            print(f"{Colors.FAIL}[!] Agent '{agent_id}' not found{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Use 'agents' command to see registered agents{Colors.ENDC}")
            return

        try:
            print(f"\n{Colors.BOLD}[*] Fetching results for agent {agent_id}...{Colors.ENDC}")
            response = requests.get(f"{self.server_url}/api/results/{agent_id}", timeout=10)

            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])

                if not results:
                    print(f"\n{Colors.WARNING}[*] No results found for agent {agent_id}{Colors.ENDC}")
                    print(f"{Colors.INFO}[*] Run modules first: module {agent_id} all{Colors.ENDC}\n")
                    return

                print(f"\n{Colors.BOLD}{Colors.OKCYAN}╔═══════════════════════════════════════════════════════════════════════╗{Colors.ENDC}")
                print(f"{Colors.BOLD}{Colors.OKCYAN}║                    RESULTS FOR AGENT: {agent_id[:20]:<20} ║{Colors.ENDC}")
                print(f"{Colors.BOLD}{Colors.OKCYAN}╚═══════════════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")

                for idx, result in enumerate(results, 1):
                    module_name = result['module']
                    findings = result['results'].get('findings', [])
                    findings_count = len(findings)

                    # Count by severity
                    critical = sum(1 for f in findings if f.get('severity') == 'critical')
                    high = sum(1 for f in findings if f.get('severity') == 'high')
                    medium = sum(1 for f in findings if f.get('severity') == 'medium')

                    print(f"{Colors.BOLD}[{idx}] Module: {module_name}{Colors.ENDC}")
                    print(f"    Timestamp: {result['timestamp']}")
                    print(f"    Findings:  {findings_count} total", end="")
                    if critical > 0:
                        print(f" | {Colors.CRITICAL}{critical} Critical{Colors.ENDC}", end="")
                    if high > 0:
                        print(f" | {Colors.HIGH}{high} High{Colors.ENDC}", end="")
                    if medium > 0:
                        print(f" | {Colors.MEDIUM}{medium} Medium{Colors.ENDC}", end="")
                    print()
                    print("=" * 75)

                print(f"\n{Colors.OKGREEN}[+] Total modules executed: {len(results)}{Colors.ENDC}")
                print(f"{Colors.INFO}💡 Generate full report with: report {agent_id} all{Colors.ENDC}\n")

            else:
                print(f"{Colors.FAIL}[!] Server error: {response.status_code}{Colors.ENDC}")

        except requests.exceptions.RequestException as e:
            print(f"{Colors.FAIL}[!] Connection error: {e}{Colors.ENDC}")

    def run_module(self, agent_id, module_name):
        """Run a security assessment module on an agent with validation and status tracking"""
        # Validate agent ID
        is_valid, error = self.validator.validate_agent_id(agent_id)
        if not is_valid:
            print(f"{Colors.FAIL}[!] Invalid agent ID: {error}{Colors.ENDC}")
            return

        # Validate module name
        is_valid, error = self.validator.validate_module_name(module_name)
        if not is_valid:
            print(f"{Colors.FAIL}[!] Invalid module: {error}{Colors.ENDC}")
            return

        # Check if agent exists
        exists, agent_data = self._validate_agent_exists(agent_id)
        if not exists:
            print(f"{Colors.FAIL}[!] Agent '{agent_id}' not found{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Use 'agents' command to see registered agents{Colors.ENDC}")
            return

        try:
            # Check if "all" modules requested
            if module_name.lower() == "all":
                return self.run_all_modules(agent_id, agent_data)

            # Check module compatibility
            platform = agent_data['platform']
            compatible_modules = get_compatible_modules(platform)

            if module_name not in compatible_modules:
                print(f"{Colors.WARNING}[!] Warning: Module '{module_name}' may not be compatible with {platform}{Colors.ENDC}")
                confirm = input(f"Continue anyway? (y/n): ").strip().lower()
                if confirm != 'y':
                    print(f"{Colors.INFO}[*] Module execution cancelled{Colors.ENDC}")
                    return

            print(f"\n{Colors.BOLD}[*] Preparing to execute module '{module_name}'...{Colors.ENDC}")

            # Verify module import
            print(f"{Colors.INFO}[*] Validating module availability...{Colors.ENDC}")
            if module_name in MODULES:
                print(f"{Colors.OKGREEN}  ✓ Module '{module_name}' imported successfully{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}  ✗ Module '{module_name}' not found in registry{Colors.ENDC}")
                return

            command = {
                "type": "module",
                "module": module_name
            }

            print(f"{Colors.INFO}[*] Queueing command for agent {agent_id}...{Colors.ENDC}")
            response = requests.post(
                f"{self.server_url}/api/command",
                json={"agent_id": agent_id, "command": command},
                timeout=10
            )

            if response.status_code == 200:
                print(f"{Colors.OKGREEN}[+] Module '{module_name}' queued successfully{Colors.ENDC}")
                print(f"{Colors.INFO}[*] Agent {agent_data['hostname']} will execute module automatically{Colors.ENDC}")
                print(f"{Colors.INFO}[*] Results will be saved to server database{Colors.ENDC}")
                print(f"{Colors.INFO}💡 Check results with: results {agent_id}{Colors.ENDC}\n")
            else:
                print(f"{Colors.FAIL}[!] Server error: {response.status_code}{Colors.ENDC}")

        except requests.exceptions.RequestException as e:
            print(f"{Colors.FAIL}[!] Connection error: {e}{Colors.ENDC}")

    def run_all_modules(self, agent_id, agent_data=None):
        """Run all compatible modules on an agent with comprehensive status tracking"""
        try:
            # Get agent data if not provided
            if not agent_data:
                exists, agent_data = self._validate_agent_exists(agent_id)
                if not exists:
                    print(f"{Colors.FAIL}[!] Agent '{agent_id}' not found{Colors.ENDC}")
                    return

            # Get compatible modules for this agent's OS
            platform = agent_data['platform']
            compatible_modules = get_modules_by_priority(platform)

            if not compatible_modules:
                print(f"{Colors.FAIL}[!] No compatible modules found for {platform}{Colors.ENDC}")
                return

            print(f"\n{Colors.BOLD}{Colors.HEADER}╔═══════════════════════════════════════════════════════════════════════╗{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.HEADER}║              COMPREHENSIVE SECURITY ASSESSMENT EXECUTION              ║{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.HEADER}╚═══════════════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")

            print(f"{Colors.BOLD}Target Information:{Colors.ENDC}")
            print(f"  Hostname:      {agent_data['hostname']}")
            print(f"  Platform:      {platform}")
            print(f"  Agent ID:      {agent_id}")
            print(f"  Modules:       {len(compatible_modules)}")
            print()

            print(f"{Colors.BOLD}{Colors.OKCYAN}[Phase 1] Module Import Validation{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Validating all modules are available...{Colors.ENDC}\n")

            # Validate all modules
            all_valid = True
            for module_name in compatible_modules:
                if module_name in MODULES:
                    print(f"  {Colors.OKGREEN}✓{Colors.ENDC} {module_name:<30} imported successfully")
                else:
                    print(f"  {Colors.FAIL}✗{Colors.ENDC} {module_name:<30} NOT FOUND")
                    all_valid = False

            if not all_valid:
                print(f"\n{Colors.FAIL}[!] Some modules failed validation. Aborting.{Colors.ENDC}")
                return

            print(f"\n{Colors.OKGREEN}[+] All {len(compatible_modules)} modules validated successfully{Colors.ENDC}\n")

            print(f"{Colors.BOLD}{Colors.OKCYAN}[Phase 2] Command Queue{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Queueing modules for execution...{Colors.ENDC}\n")

            # Queue all modules with status tracking
            queued = []
            failed = []

            for idx, module_name in enumerate(compatible_modules, 1):
                command = {
                    "type": "module",
                    "module": module_name
                }

                try:
                    response = requests.post(
                        f"{self.server_url}/api/command",
                        json={"agent_id": agent_id, "command": command},
                        timeout=10
                    )

                    if response.status_code == 200:
                        print(f"  [{idx}/{len(compatible_modules)}] {Colors.OKGREEN}✓{Colors.ENDC} Queued: {module_name}")
                        queued.append(module_name)
                    else:
                        print(f"  [{idx}/{len(compatible_modules)}] {Colors.FAIL}✗{Colors.ENDC} Failed: {module_name} (HTTP {response.status_code})")
                        failed.append(module_name)

                except Exception as e:
                    print(f"  [{idx}/{len(compatible_modules)}] {Colors.FAIL}✗{Colors.ENDC} Error: {module_name} ({str(e)})")
                    failed.append(module_name)

            print(f"\n{Colors.BOLD}{Colors.OKCYAN}[Phase 3] Execution Status{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Successfully queued: {len(queued)}/{len(compatible_modules)} modules{Colors.ENDC}")

            if failed:
                print(f"{Colors.FAIL}[!] Failed to queue: {len(failed)} modules{Colors.ENDC}")
                for module in failed:
                    print(f"    - {module}")

            print(f"\n{Colors.BOLD}{Colors.OKCYAN}[Phase 4] Results Collection{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Agent will execute modules automatically{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Results will be saved to server database{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Results file: SQLite database on operator server{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Execution time: ~{len(queued) * 2} seconds (estimated){Colors.ENDC}\n")

            print(f"{Colors.BOLD}{Colors.OKGREEN}═══════════════════════════════════════════════════════════════════════{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.OKGREEN}                    ASSESSMENT QUEUED SUCCESSFULLY                    {Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.OKGREEN}═══════════════════════════════════════════════════════════════════════{Colors.ENDC}\n")

            print(f"{Colors.BOLD}Next Steps:{Colors.ENDC}")
            print(f"  1. Wait for agent to execute modules (~30-60 seconds)")
            print(f"  2. Check results: {Colors.OKCYAN}results {agent_id}{Colors.ENDC}")
            print(f"  3. Generate report: {Colors.OKCYAN}report {agent_id} all{Colors.ENDC}")
            print(f"\n{Colors.INFO}💡 Tip: Use 'report {agent_id} console' for quick terminal view{Colors.ENDC}\n")

        except requests.exceptions.RequestException as e:
            print(f"{Colors.FAIL}[!] Connection error: {e}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Unexpected error: {e}{Colors.ENDC}")
            import traceback
            traceback.print_exc()

    def run_shell_command(self, agent_id, command):
        """Run a shell command on an agent"""
        # Validate agent ID
        is_valid, error = self.validator.validate_agent_id(agent_id)
        if not is_valid:
            print(f"{Colors.FAIL}[!] Invalid agent ID: {error}{Colors.ENDC}")
            return

        # Check if agent exists
        exists, agent_data = self._validate_agent_exists(agent_id)
        if not exists:
            print(f"{Colors.FAIL}[!] Agent '{agent_id}' not found{Colors.ENDC}")
            return

        if not command or not command.strip():
            print(f"{Colors.FAIL}[!] Command cannot be empty{Colors.ENDC}")
            return

        try:
            cmd = {
                "type": "shell",
                "cmd": command
            }

            print(f"\n{Colors.INFO}[*] Queueing shell command for agent {agent_id}...{Colors.ENDC}")
            response = requests.post(
                f"{self.server_url}/api/command",
                json={"agent_id": agent_id, "command": cmd},
                timeout=10
            )

            if response.status_code == 200:
                print(f"{Colors.OKGREEN}[+] Command queued successfully{Colors.ENDC}")
                print(f"{Colors.INFO}[*] Command: {command}{Colors.ENDC}")
                print(f"{Colors.INFO}💡 Check results with: results {agent_id}{Colors.ENDC}\n")
            else:
                print(f"{Colors.FAIL}[!] Server error: {response.status_code}{Colors.ENDC}")

        except requests.exceptions.RequestException as e:
            print(f"{Colors.FAIL}[!] Connection error: {e}{Colors.ENDC}")

    def generate_agent(self, platform, operator_url=None):
        """Generate a new agent"""
        # Validate platform
        is_valid, error = self.validator.validate_platform(platform)
        if not is_valid:
            print(f"{Colors.FAIL}[!] {error}{Colors.ENDC}")
            return

        # Validate URL if provided
        if operator_url:
            is_valid, error = self.validator.validate_url(operator_url)
            if not is_valid:
                print(f"{Colors.FAIL}[!] {error}{Colors.ENDC}")
                return

        try:
            print(f"\n{Colors.BOLD}[*] Generating {platform} agent...{Colors.ENDC}")
            generator = AgentGenerator(operator_url)
            result = generator.generate_agent(platform)

            print(f"\n{Colors.OKGREEN}{Colors.BOLD}[+] Agent generated successfully!{Colors.ENDC}")
            print(f"\n{Colors.BOLD}Agent Information:{Colors.ENDC}")
            print(f"  Agent ID:      {Colors.OKCYAN}{result['agent_id']}{Colors.ENDC}")
            print(f"  Platform:      {result['platform']}")
            print(f"  Operator URL:  {generator.operator_url}")
            print(f"  Output Path:   {result['output_path']}")
            print(f"\n{Colors.BOLD}Deployment Instructions:{Colors.ENDC}")
            print(f"  1. Transfer {result['output_path']} to target {platform} system")
            print(f"  2. Run: python3 {os.path.basename(result['output_path'])}")
            print(f"  3. Agent will register automatically with operator server\n")

        except Exception as e:
            print(f"{Colors.FAIL}[!] Error generating agent: {e}{Colors.ENDC}")
            import traceback
            traceback.print_exc()

    def show_modules(self, os_filter=None):
        """Show available security assessment modules"""
        print(f"\n{Colors.BOLD}{Colors.HEADER}╔═══════════════════════════════════════════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}║                    SECURITY ASSESSMENT MODULES                        ║{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}╚═══════════════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")

        if os_filter:
            # Validate OS filter
            is_valid, error = self.validator.validate_platform(os_filter)
            if not is_valid:
                print(f"{Colors.WARNING}[!] {error}{Colors.ENDC}")
                print(f"{Colors.INFO}[*] Showing all modules instead{Colors.ENDC}\n")
                os_filter = None
            else:
                print(f"{Colors.INFO}Showing modules compatible with: {os_filter}{Colors.ENDC}\n")
                modules_list = get_module_list_formatted(os_filter)
        else:
            print(f"{Colors.INFO}Showing all modules (all operating systems){Colors.ENDC}\n")
            modules_list = get_module_list_formatted()

        print(f"{Colors.BOLD}{'Module ID':<25} {'Description':<35} {'OS Support':<15}{Colors.ENDC}")
        print("-" * 75)

        for module_id, name, description, os_list in modules_list:
            print(f"{module_id:<25} {description:<35} {os_list:<15}")

        print()
        print(f"{Colors.BOLD}Total modules: {len(modules_list)}{Colors.ENDC}")
        print()
        print(f"{Colors.BOLD}Usage:{Colors.ENDC}")
        print(f"  module <agent_id> <module_name>  - Run single module")
        print(f"  module <agent_id> all            - Run ALL compatible modules")
        print()

    def generate_report(self, agent_id, format_type='all', output_dir='reports'):
        """Generate comprehensive security assessment report with validation"""
        # Validate agent ID
        is_valid, error = self.validator.validate_agent_id(agent_id)
        if not is_valid:
            print(f"{Colors.FAIL}[!] Invalid agent ID: {error}{Colors.ENDC}")
            return

        # Validate format
        is_valid, error = self.validator.validate_report_format(format_type)
        if not is_valid:
            print(f"{Colors.FAIL}[!] {error}{Colors.ENDC}")
            return

        # Check if agent exists
        exists, agent_data = self._validate_agent_exists(agent_id)
        if not exists:
            print(f"{Colors.FAIL}[!] Agent '{agent_id}' not found{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Use 'agents' command to see registered agents{Colors.ENDC}")
            return

        # Check if agent has results
        try:
            response = requests.get(f"{self.server_url}/api/results/{agent_id}", timeout=10)
            if response.status_code == 200:
                results = response.json().get('results', [])
                if not results:
                    print(f"{Colors.WARNING}[!] No assessment results found for agent {agent_id}{Colors.ENDC}")
                    print(f"{Colors.INFO}[*] Run modules first: module {agent_id} all{Colors.ENDC}")
                    return
            else:
                print(f"{Colors.FAIL}[!] Error fetching results: {response.status_code}{Colors.ENDC}")
                return
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error checking results: {e}{Colors.ENDC}")
            return

        try:
            print(f"\n{Colors.BOLD}{Colors.OKCYAN}╔═══════════════════════════════════════════════════════════════════════╗{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.OKCYAN}║                     REPORT GENERATION IN PROGRESS                     ║{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.OKCYAN}╚═══════════════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")

            print(f"{Colors.INFO}[*] Target Agent: {agent_id}{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Hostname: {agent_data['hostname']}{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Platform: {agent_data['platform']}{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Format: {format_type}{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Output Directory: {output_dir}{Colors.ENDC}\n")

            print(f"{Colors.INFO}[*] Processing assessment data...{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Calculating risk scores...{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Analyzing findings...{Colors.ENDC}\n")

            result = generate_report_from_server(
                self.server_url,
                agent_id,
                output_dir,
                format_type
            )

            if result and format_type != 'console':
                print(f"\n{Colors.OKGREEN}{Colors.BOLD}[+] Report generation complete!{Colors.ENDC}")
                print(f"\n{Colors.BOLD}Generated Reports:{Colors.ENDC}")

                for format_name, file_path in result.items():
                    print(f"  {Colors.OKGREEN}✓{Colors.ENDC} {format_name.upper():<10} {file_path}")

                print(f"\n{Colors.INFO}💡 Open HTML report in browser for best experience{Colors.ENDC}\n")
            elif result and format_type == 'console':
                # Console report already printed by generate_report_from_server
                pass
            else:
                print(f"\n{Colors.FAIL}[!] Report generation failed{Colors.ENDC}")
                print(f"{Colors.INFO}[*] Check that agent has completed assessments{Colors.ENDC}\n")

        except Exception as e:
            print(f"{Colors.FAIL}[!] Error generating report: {e}{Colors.ENDC}")
            import traceback
            traceback.print_exc()

    def interactive_mode(self):
        """Run CLI in interactive mode with enhanced help"""
        print(f"""
{Colors.BOLD}{Colors.HEADER}    ╔═══════════════════════════════════════════════════════════════╗{Colors.ENDC}
{Colors.BOLD}{Colors.HEADER}    ║             C2 Operator CLI - Interactive Mode                ║{Colors.ENDC}
{Colors.BOLD}{Colors.HEADER}    ║         Security Assessment Framework v2.0                    ║{Colors.ENDC}
{Colors.BOLD}{Colors.HEADER}    ╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}

    {Colors.BOLD}Commands:{Colors.ENDC}
      {Colors.OKCYAN}agents{Colors.ENDC}                             - List all agents with OS info
      {Colors.OKCYAN}results <agent_id>{Colors.ENDC}                 - Get results summary for an agent
      {Colors.OKCYAN}module <agent_id> <module_name>{Colors.ENDC}    - Run single module (or 'all')
      {Colors.OKCYAN}shell <agent_id> <command>{Colors.ENDC}         - Run shell command
      {Colors.OKCYAN}report <agent_id> [format] [dir]{Colors.ENDC}   - Generate report (console/json/html/md/all)
      {Colors.OKCYAN}generate <platform> [url]{Colors.ENDC}          - Generate new agent
      {Colors.OKCYAN}modules [os]{Colors.ENDC}                       - List modules (filter by OS)
      {Colors.OKCYAN}help{Colors.ENDC}                               - Show this help
      {Colors.OKCYAN}exit{Colors.ENDC}                               - Exit CLI

    {Colors.BOLD}Examples:{Colors.ENDC}
      module abc123 all              - Run all compatible modules
      report abc123 console          - Quick terminal view
      report abc123 all              - Generate all report formats
      generate linux                 - Generate Linux agent

        """)

        while True:
            try:
                cmd = input(f"{Colors.BOLD}{Colors.OKCYAN}operator>{Colors.ENDC} ").strip()

                if not cmd:
                    continue

                parts = cmd.split(maxsplit=2)
                command = parts[0].lower()

                if command == "exit" or command == "quit":
                    print(f"\n{Colors.OKGREEN}[*] Goodbye!{Colors.ENDC}")
                    break

                elif command == "help":
                    print(f"""
    {Colors.BOLD}Commands:{Colors.ENDC}
      {Colors.OKCYAN}agents{Colors.ENDC}                             - List all agents with OS info
      {Colors.OKCYAN}results <agent_id>{Colors.ENDC}                 - Get results summary for an agent
      {Colors.OKCYAN}module <agent_id> <module_name>{Colors.ENDC}    - Run single module (or 'all')
      {Colors.OKCYAN}shell <agent_id> <command>{Colors.ENDC}         - Run shell command
      {Colors.OKCYAN}report <agent_id> [format] [dir]{Colors.ENDC}   - Generate report (console/json/html/md/all)
      {Colors.OKCYAN}generate <platform> [url]{Colors.ENDC}          - Generate new agent
      {Colors.OKCYAN}modules [os]{Colors.ENDC}                       - List modules (filter by OS)
      {Colors.OKCYAN}help{Colors.ENDC}                               - Show this help
      {Colors.OKCYAN}exit{Colors.ENDC}                               - Exit CLI
                    """)

                elif command == "agents":
                    self.list_agents()

                elif command == "results":
                    if len(parts) < 2:
                        print(f"{Colors.FAIL}[!] Usage: results <agent_id>{Colors.ENDC}")
                        continue
                    self.get_results(parts[1])

                elif command == "module":
                    if len(parts) < 3:
                        print(f"{Colors.FAIL}[!] Usage: module <agent_id> <module_name>{Colors.ENDC}")
                        print(f"{Colors.INFO}[*] Example: module abc123 all{Colors.ENDC}")
                        continue
                    self.run_module(parts[1], parts[2])

                elif command == "shell":
                    if len(parts) < 3:
                        print(f"{Colors.FAIL}[!] Usage: shell <agent_id> <command>{Colors.ENDC}")
                        continue
                    self.run_shell_command(parts[1], parts[2])

                elif command == "generate":
                    if len(parts) < 2:
                        print(f"{Colors.FAIL}[!] Usage: generate <platform> [operator_url]{Colors.ENDC}")
                        print(f"{Colors.INFO}[*] Platform: windows or linux{Colors.ENDC}")
                        print(f"{Colors.INFO}[*] URL is optional - will auto-detect if not provided{Colors.ENDC}")
                        continue
                    operator_url = parts[2] if len(parts) >= 3 else None
                    self.generate_agent(parts[1], operator_url)

                elif command == "modules":
                    os_filter = parts[1] if len(parts) >= 2 else None
                    self.show_modules(os_filter)

                elif command == "report":
                    if len(parts) < 2:
                        print(f"{Colors.FAIL}[!] Usage: report <agent_id> [format] [output_dir]{Colors.ENDC}")
                        print(f"{Colors.INFO}[*] Formats: console, json, html, markdown, all (default: all){Colors.ENDC}")
                        continue

                    # Parse arguments carefully
                    agent_id = parts[1]

                    # Get format and output_dir from remaining parts
                    remaining_parts = parts[2].split() if len(parts) >= 3 else []
                    format_type = remaining_parts[0] if len(remaining_parts) >= 1 else 'all'
                    output_dir = remaining_parts[1] if len(remaining_parts) >= 2 else 'reports'

                    self.generate_report(agent_id, format_type, output_dir)

                else:
                    print(f"{Colors.FAIL}[!] Unknown command: {command}{Colors.ENDC}")
                    print(f"{Colors.INFO}[*] Type 'help' for available commands{Colors.ENDC}")

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[*] Use 'exit' to quit{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
                import traceback
                traceback.print_exc()


def main():
    # Auto-detect server URL from config or command line
    if len(sys.argv) >= 2:
        server_url = sys.argv[1]
    else:
        # Load from config
        config = get_config()
        server_url = config.get_server_url()
        print(f"{Colors.INFO}[*] Auto-detected server URL: {server_url}{Colors.ENDC}")
        print(f"{Colors.INFO}[*] You can override with: python cli.py <server_url>{Colors.ENDC}\n")

    cli = OperatorCLI(server_url)

    # Check if server is online
    print(f"{Colors.BOLD}[*] Connecting to operator server...{Colors.ENDC}")
    try:
        response = requests.get(f"{server_url}/api/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            print(f"{Colors.OKGREEN}[+] Connected to operator server at {server_url}{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Active agents: {health_data.get('active_agents', 0)}{Colors.ENDC}")
            print(f"{Colors.INFO}[*] Total agents: {health_data.get('total_agents', 0)}{Colors.ENDC}\n")
        else:
            print(f"{Colors.WARNING}[!] Server returned status code: {response.status_code}{Colors.ENDC}")
    except requests.exceptions.RequestException:
        print(f"{Colors.FAIL}[!] ERROR: Cannot connect to operator server at {server_url}{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Make sure the operator server is running{Colors.ENDC}")
        print(f"{Colors.INFO}[*] Start server with: python operator/server.py{Colors.ENDC}\n")
        sys.exit(1)

    cli.interactive_mode()


if __name__ == '__main__':
    main()
