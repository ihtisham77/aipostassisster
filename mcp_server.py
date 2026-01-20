#!/usr/bin/env python3
"""
MCP Server for C2 Security Assessment Framework
Exposes framework functionality to LLMs via Model Context Protocol
"""

import os
import sys
import json
import subprocess
import time
import psutil
import requests
from typing import Optional, List, Dict, Any
from mcp import FastMCP

# Add operator directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'operator'))
from config import get_config
from agent_generator import AgentGenerator
from module_registry import MODULES, get_all_modules, get_compatible_modules

# Initialize FastMCP server
mcp = FastMCP("C2 Security Assessment Framework")

# Configuration
config = get_config()
DEFAULT_OPERATOR_URL = f"http://{config.get_local_ip()}:{config.get('server', 'port')}"
OPERATOR_PORT = config.get("server", "port") or 8542


class C2FrameworkClient:
    """Client for interacting with C2 operator server"""

    def __init__(self, base_url: str = None):
        self.base_url = base_url or DEFAULT_OPERATOR_URL

    def _make_request(self, method: str, endpoint: str, data: dict = None) -> dict:
        """Make HTTP request to operator server"""
        url = f"{self.base_url}{endpoint}"
        try:
            if method == "GET":
                response = requests.get(url, timeout=10)
            elif method == "POST":
                response = requests.post(url, json=data, timeout=10)
            else:
                return {"error": f"Unsupported method: {method}"}

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}: {response.text}"}
        except requests.exceptions.ConnectionError:
            return {"error": f"Cannot connect to operator server at {self.base_url}. Is the server running?"}
        except Exception as e:
            return {"error": str(e)}

    def health_check(self) -> dict:
        """Check if operator server is healthy"""
        return self._make_request("GET", "/api/health")

    def list_agents(self) -> dict:
        """Get list of all registered agents"""
        return self._make_request("GET", "/api/agents")

    def get_results(self, agent_id: str) -> dict:
        """Get assessment results for an agent"""
        return self._make_request("GET", f"/api/results/{agent_id}")

    def send_command(self, agent_id: str, command: dict) -> dict:
        """Send command to an agent"""
        return self._make_request("POST", "/api/command", {
            "agent_id": agent_id,
            "command": command
        })

    def add_module(self, module_data: dict) -> dict:
        """Add a custom module to the framework"""
        return self._make_request("POST", "/api/mcp/add_module", module_data)

    def get_capabilities(self) -> dict:
        """Get framework capabilities"""
        return self._make_request("GET", "/api/mcp/capabilities")


# Initialize client
client = C2FrameworkClient()


def is_operator_server_running() -> bool:
    """Check if operator server is running"""
    result = client.health_check()
    return "error" not in result and result.get("status") == "online"


def start_operator_server_subprocess() -> dict:
    """Start operator server in background subprocess"""
    server_script = os.path.join(os.path.dirname(__file__), 'operator', 'server.py')

    if not os.path.exists(server_script):
        return {
            "success": False,
            "error": f"Server script not found: {server_script}"
        }

    try:
        # Start server in background
        process = subprocess.Popen(
            [sys.executable, server_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True
        )

        # Wait for server to start (max 10 seconds)
        for _ in range(10):
            time.sleep(1)
            if is_operator_server_running():
                return {
                    "success": True,
                    "message": f"Operator server started successfully",
                    "url": DEFAULT_OPERATOR_URL,
                    "pid": process.pid
                }

        return {
            "success": False,
            "error": "Server started but health check failed after 10 seconds"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to start server: {str(e)}"
        }


# ============================================================================
#                              MCP TOOLS
# ============================================================================

@mcp.tool()
def get_framework_status() -> str:
    """
    Get the current status of the C2 Security Assessment Framework.

    Returns:
        JSON string with framework status including:
        - Server status (online/offline)
        - Number of active agents
        - Available modules
        - Server URL
    """
    result = {
        "framework": "C2 Security Assessment Framework",
        "version": "1.0",
        "server_url": DEFAULT_OPERATOR_URL
    }

    # Check server status
    health = client.health_check()
    if "error" in health:
        result["server_status"] = "offline"
        result["error"] = health["error"]
    else:
        result["server_status"] = "online"
        result["active_agents"] = health.get("active_agents", 0)
        result["total_agents"] = health.get("total_agents", 0)

    # Get available modules
    result["available_modules"] = get_all_modules()
    result["total_modules"] = len(MODULES)

    return json.dumps(result, indent=2)


@mcp.tool()
def start_operator_server() -> str:
    """
    Start the C2 operator server if it's not already running.

    This command checks if the operator server is running, and if not,
    starts it automatically in the background.

    Returns:
        JSON string with server startup status and connection information
    """
    # Check if already running
    if is_operator_server_running():
        return json.dumps({
            "success": True,
            "message": "Operator server is already running",
            "url": DEFAULT_OPERATOR_URL,
            "status": "online"
        }, indent=2)

    # Start server
    result = start_operator_server_subprocess()
    return json.dumps(result, indent=2)


@mcp.tool()
def generate_agent(platform: str, operator_url: Optional[str] = None) -> str:
    """
    Generate a new agent for the specified platform.

    This creates a custom agent script that can be deployed on target systems
    to perform security assessments.

    Args:
        platform: Target platform ('windows' or 'linux')
        operator_url: Optional custom operator URL (defaults to auto-detected URL)

    Returns:
        JSON string with agent generation details including:
        - Agent ID
        - Platform
        - Output file path
        - Deployment instructions
    """
    try:
        # Validate platform
        platform_lower = platform.lower()
        if platform_lower not in ['windows', 'linux']:
            return json.dumps({
                "success": False,
                "error": f"Unsupported platform: {platform}. Use 'windows' or 'linux'"
            }, indent=2)

        # Generate agent
        generator = AgentGenerator(operator_url)
        agent_info = generator.generate_agent(platform_lower)

        result = {
            "success": True,
            "agent_id": agent_info["agent_id"],
            "platform": agent_info["platform"],
            "output_path": agent_info["output_path"],
            "operator_url": operator_url or DEFAULT_OPERATOR_URL,
            "generated_at": agent_info["generated_at"],
            "deployment_instructions": [
                f"1. Transfer the agent file to the target {platform} system",
                f"2. Ensure Python 3.x is installed on the target",
                f"3. Copy the 'modules' directory to the same location as the agent",
                f"4. Run the agent: python {os.path.basename(agent_info['output_path'])}",
                f"5. The agent will automatically register with the operator server"
            ]
        }

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)


@mcp.tool()
def list_agents() -> str:
    """
    List all registered agents and their status.

    Returns:
        JSON string with array of agent information including:
        - Agent ID
        - Hostname
        - Platform (OS)
        - IP address
        - Last seen timestamp
        - Status (active/inactive)
        - Commands executed count
    """
    result = client.list_agents()

    if "error" in result:
        return json.dumps({
            "success": False,
            "error": result["error"]
        }, indent=2)

    agents = result.get("agents", [])

    return json.dumps({
        "success": True,
        "total_agents": len(agents),
        "agents": agents
    }, indent=2)


@mcp.tool()
def run_assessment(agent_id: str, modules: Optional[str] = "all") -> str:
    """
    Run security assessment modules on a specific agent.

    This queues assessment modules to be executed by the agent. The agent will
    automatically retrieve and execute the modules on its next check-in.

    Args:
        agent_id: The unique identifier of the target agent
        modules: Comma-separated list of module names, or 'all' for all compatible modules
                Available modules: reconnaissance, credential_access, privilege_escalation,
                persistence, lateral_movement, exfiltration, cleanup

    Returns:
        JSON string with assessment execution status and queued modules
    """
    try:
        # First, get agent information to determine platform
        agents_response = client.list_agents()
        if "error" in agents_response:
            return json.dumps({
                "success": False,
                "error": agents_response["error"]
            }, indent=2)

        # Find the agent
        agent = None
        for a in agents_response.get("agents", []):
            if a["agent_id"] == agent_id:
                agent = a
                break

        if not agent:
            return json.dumps({
                "success": False,
                "error": f"Agent not found: {agent_id}"
            }, indent=2)

        # Determine which modules to run
        if modules.lower() == "all":
            module_list = get_compatible_modules(agent["platform"])
        else:
            module_list = [m.strip() for m in modules.split(",")]

        # Queue modules
        queued = []
        failed = []

        for module_name in module_list:
            # Validate module exists
            if module_name not in MODULES:
                failed.append({
                    "module": module_name,
                    "reason": "Module not found"
                })
                continue

            # Send command
            command_result = client.send_command(agent_id, {
                "type": "module",
                "module": module_name
            })

            if "error" in command_result:
                failed.append({
                    "module": module_name,
                    "reason": command_result["error"]
                })
            else:
                queued.append(module_name)

        return json.dumps({
            "success": True,
            "agent_id": agent_id,
            "platform": agent["platform"],
            "queued_modules": queued,
            "queued_count": len(queued),
            "failed_modules": failed,
            "failed_count": len(failed),
            "message": f"Queued {len(queued)} modules for execution. Agent will execute them on next check-in."
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)


@mcp.tool()
def get_assessment_results(agent_id: str) -> str:
    """
    Retrieve assessment results from a specific agent.

    Returns all assessment results that have been received from the agent,
    including findings from each executed module.

    Args:
        agent_id: The unique identifier of the agent

    Returns:
        JSON string with assessment results including:
        - Module execution results
        - Findings with severity levels
        - Confidence scores
        - Timestamps
    """
    result = client.get_results(agent_id)

    if "error" in result:
        return json.dumps({
            "success": False,
            "error": result["error"]
        }, indent=2)

    results = result.get("results", [])

    # Summarize results
    summary = {
        "total_modules_executed": len(results),
        "modules": {}
    }

    for result_entry in results:
        module = result_entry.get("module")
        if module not in summary["modules"]:
            summary["modules"][module] = {
                "executions": 0,
                "total_findings": 0
            }
        summary["modules"][module]["executions"] += 1

        # Count findings
        findings = result_entry.get("results", {}).get("findings", [])
        summary["modules"][module]["total_findings"] += len(findings)

    return json.dumps({
        "success": True,
        "agent_id": agent_id,
        "summary": summary,
        "results": results
    }, indent=2)


@mcp.tool()
def generate_report(agent_id: str, format_type: str = "console") -> str:
    """
    Generate a security assessment report for an agent.

    Creates a comprehensive report from all assessment results collected
    from the specified agent. Reports include risk scoring, confidence analysis,
    and detailed findings.

    Args:
        agent_id: The unique identifier of the agent
        format_type: Report format ('console', 'json', 'html', or 'markdown')

    Returns:
        JSON string with report generation status and file path (if applicable)
    """
    try:
        # Get agent data
        agents_response = client.list_agents()
        if "error" in agents_response:
            return json.dumps({
                "success": False,
                "error": agents_response["error"]
            }, indent=2)

        agent = None
        for a in agents_response.get("agents", []):
            if a["agent_id"] == agent_id:
                agent = a
                break

        if not agent:
            return json.dumps({
                "success": False,
                "error": f"Agent not found: {agent_id}"
            }, indent=2)

        # Get results
        results_response = client.get_results(agent_id)
        if "error" in results_response:
            return json.dumps({
                "success": False,
                "error": results_response["error"]
            }, indent=2)

        results = results_response.get("results", [])

        if not results:
            return json.dumps({
                "success": False,
                "error": "No assessment results available for this agent"
            }, indent=2)

        # Generate report using report generator
        from report_generator import ReportGenerator

        generator = ReportGenerator(agent, results)

        report_files = []
        format_lower = format_type.lower()

        if format_lower in ['console', 'all']:
            # Print console report
            print("\n" + "="*80)
            generator.print_console_report()
            print("="*80 + "\n")

        if format_lower in ['json', 'all']:
            report_path = generator.generate_json_report()
            report_files.append({"format": "json", "path": report_path})

        if format_lower in ['html', 'all']:
            report_path = generator.generate_html_report()
            report_files.append({"format": "html", "path": report_path})

        if format_lower in ['markdown', 'md', 'all']:
            report_path = generator.generate_markdown_report()
            report_files.append({"format": "markdown", "path": report_path})

        return json.dumps({
            "success": True,
            "agent_id": agent_id,
            "format": format_type,
            "report_files": report_files,
            "message": f"Report generated successfully in {format_type} format"
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)


@mcp.tool()
def add_custom_module(
    module_name: str,
    module_code: str,
    description: str,
    platforms: str = "Linux,Windows"
) -> str:
    """
    Add a custom post-exploitation module to the framework.

    This allows you to dynamically add new assessment modules without modifying
    the core framework. The module will be available for execution on compatible agents.

    Args:
        module_name: Unique identifier for the module (snake_case, e.g., 'custom_check')
        module_code: Python code for the module (must define a 'run_assessment' function)
        description: Human-readable description of what the module does
        platforms: Comma-separated list of compatible platforms (e.g., 'Linux,Windows')

    Returns:
        JSON string with module addition status

    Example module_code structure:
        ```python
        def run_assessment():
            findings = []
            # Your assessment logic here
            findings.append({
                "severity": "high",
                "title": "Finding title",
                "description": "Details...",
                "confidence_score": 85,
                "evidence": ["proof1", "proof2"]
            })
            return {"findings": findings}
        ```
    """
    try:
        # Validate module name
        if not module_name or not module_name.replace('_', '').isalnum():
            return json.dumps({
                "success": False,
                "error": "Invalid module name. Use snake_case with letters, numbers, and underscores only"
            }, indent=2)

        # Check if module already exists
        if module_name in MODULES:
            return json.dumps({
                "success": False,
                "error": f"Module '{module_name}' already exists"
            }, indent=2)

        # Validate module code has required function
        if "def run_assessment" not in module_code:
            return json.dumps({
                "success": False,
                "error": "Module code must define a 'run_assessment' function"
            }, indent=2)

        # Parse platforms
        platform_list = [p.strip() for p in platforms.split(",")]

        # Create module file
        modules_dir = os.path.join(os.path.dirname(__file__), 'agent', 'modules')
        module_file = os.path.join(modules_dir, f"{module_name}.py")

        if os.path.exists(module_file):
            return json.dumps({
                "success": False,
                "error": f"Module file already exists: {module_file}"
            }, indent=2)

        # Write module file with header
        module_content = f'''"""
{description}

Custom module dynamically added via MCP
"""

import platform

{module_code}

if __name__ == '__main__':
    results = run_assessment()
    import json
    print(json.dumps(results, indent=2))
'''

        with open(module_file, 'w') as f:
            f.write(module_content)

        # Update module registry
        MODULES[module_name] = {
            "name": module_name.replace('_', ' ').title(),
            "description": description,
            "os": platform_list,
            "priority": 5,
            "custom": True
        }

        # Update registry file
        registry_file = os.path.join(os.path.dirname(__file__), 'operator', 'module_registry.py')
        with open(registry_file, 'r') as f:
            registry_content = f.read()

        # Add new module to MODULES dict
        import_pos = registry_content.find('MODULES = {')
        if import_pos != -1:
            # Insert before the closing brace
            closing_pos = registry_content.rfind('}', import_pos)
            new_entry = f'''    "{module_name}": {{
        "name": "{module_name.replace('_', ' ').title()}",
        "description": "{description}",
        "os": {platform_list},
        "priority": 5
    }},
'''
            updated_content = registry_content[:closing_pos] + new_entry + registry_content[closing_pos:]

            with open(registry_file, 'w') as f:
                f.write(updated_content)

        return json.dumps({
            "success": True,
            "module_name": module_name,
            "description": description,
            "platforms": platform_list,
            "module_file": module_file,
            "message": f"Custom module '{module_name}' added successfully. It will be available for execution on {', '.join(platform_list)} agents."
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)


@mcp.tool()
def get_available_modules(platform: Optional[str] = None) -> str:
    """
    List all available security assessment modules.

    Args:
        platform: Optional platform filter ('windows' or 'linux')
                 If not specified, returns all modules

    Returns:
        JSON string with list of available modules and their details
    """
    if platform:
        module_names = get_compatible_modules(platform)
    else:
        module_names = get_all_modules()

    modules_info = []
    for module_name in module_names:
        info = MODULES[module_name]
        modules_info.append({
            "id": module_name,
            "name": info["name"],
            "description": info["description"],
            "platforms": info["os"],
            "priority": info["priority"],
            "custom": info.get("custom", False)
        })

    return json.dumps({
        "success": True,
        "platform_filter": platform,
        "total_modules": len(modules_info),
        "modules": modules_info
    }, indent=2)


@mcp.tool()
def execute_shell_command(agent_id: str, command: str) -> str:
    """
    Execute a shell command on a specific agent.

    WARNING: This executes arbitrary commands on the target system.
    Only use for authorized security assessments.

    Args:
        agent_id: The unique identifier of the target agent
        command: Shell command to execute

    Returns:
        JSON string with command execution status
    """
    try:
        # Send shell command
        result = client.send_command(agent_id, {
            "type": "shell",
            "cmd": command
        })

        if "error" in result:
            return json.dumps({
                "success": False,
                "error": result["error"]
            }, indent=2)

        return json.dumps({
            "success": True,
            "agent_id": agent_id,
            "command": command,
            "message": "Command queued for execution. Results will be available via get_assessment_results()"
        }, indent=2)

    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)


# ============================================================================
#                              MAIN
# ============================================================================

if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║       MCP Server - C2 Security Assessment Framework           ║
    ║                                                               ║
    ║  This MCP server enables LLM interaction with the C2          ║
    ║  Security Assessment Framework for authorized testing.        ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    # Check if operator server is running
    if is_operator_server_running():
        print(f"[+] Operator server is running at {DEFAULT_OPERATOR_URL}")
    else:
        print(f"[!] Operator server is not running at {DEFAULT_OPERATOR_URL}")
        print("[*] LLMs can start it using the 'start_operator_server' tool")

    print("\n[*] Available MCP Tools:")
    print("  - get_framework_status: Check framework status")
    print("  - start_operator_server: Start the C2 operator server")
    print("  - generate_agent: Generate agents for target systems")
    print("  - list_agents: List all registered agents")
    print("  - run_assessment: Execute assessment modules")
    print("  - get_assessment_results: Retrieve results")
    print("  - generate_report: Create assessment reports")
    print("  - add_custom_module: Add custom assessment modules")
    print("  - get_available_modules: List available modules")
    print("  - execute_shell_command: Run shell commands on agents")

    print("\n[*] Starting MCP server...")
    mcp.run()
