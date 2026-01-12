# C2 Security Assessment Framework

A comprehensive Command and Control (C2) framework for security testing and assessment. This framework allows security professionals to test system configurations and identify security weaknesses across Windows and Linux environments.

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED USE ONLY**

This tool is designed for:
- Authorized penetration testing engagements
- Security research in controlled environments
- CTF competitions and security training
- Defensive security testing with proper authorization

**DO NOT use this tool without explicit written authorization from system owners.**

Unauthorized access to computer systems is illegal. Users are responsible for ensuring compliance with all applicable laws and regulations.

## 🎯 Features

### Operator Server
- REST API for agent management
- Real-time agent tracking
- Command queuing and execution
- Result collection and storage
- Multi-agent coordination

### Agent Capabilities
- Cross-platform support (Windows & Linux)
- Lightweight and stealthy operation
- Modular security assessment framework
- Automatic check-in mechanism
- Configurable intervals

### Security Assessment Modules

1. **Privilege Escalation** - Identifies privilege escalation vectors
   - SUID/SGID binaries
   - Sudo misconfigurations
   - Writable service files
   - Kernel vulnerabilities
   - Dangerous capabilities

2. **Persistence** - Detects persistence mechanisms
   - Cron jobs
   - Systemd services and timers
   - Startup scripts
   - Profile modifications
   - SSH authorized_keys

3. **Credential Harvesting** - Finds exposed credentials
   - History files
   - Configuration files
   - Environment variables
   - SSH keys
   - Browser data
   - Database credentials

4. **Internal Reconnaissance** - Gathers system intelligence
   - System information
   - Network configuration
   - User enumeration
   - Running processes
   - Installed software
   - Network connections

5. **Lateral Movement** - Identifies lateral movement paths
   - SSH configurations
   - Saved credentials
   - Network shares
   - Trust relationships
   - Cloud metadata access

6. **Data Access** - Locates sensitive data
   - Sensitive files
   - Database files
   - Backup files
   - World-readable files
   - Home directory access

7. **Data Exfiltration** - Tests exfiltration channels
   - Network egress
   - External storage
   - Cloud storage tools
   - Transfer utilities
   - Firewall rules

8. **C2 Communication** - Analyzes C2 capabilities
   - Network connectivity
   - Proxy configuration
   - DNS capabilities
   - Alternative protocols
   - Monitoring detection

9. **Covering Tracks** - Evaluates forensic exposure
   - System logs
   - Shell history
   - Authentication logs
   - Log permissions
   - Audit systems

## 📁 Project Structure

```
.
├── operator/
│   ├── server.py           # Main operator server
│   ├── agent_generator.py  # Agent generation
│   └── cli.py             # Operator CLI interface
├── agent/
│   └── modules/           # Security assessment modules
│       ├── privilege_escalation.py
│       ├── persistence.py
│       ├── credential_harvesting.py
│       ├── reconnaissance.py
│       ├── lateral_movement.py
│       ├── data_access.py
│       ├── data_exfiltration.py
│       ├── c2_comms.py
│       └── covering_tracks.py
├── templates/             # Agent templates
│   ├── agent_template_linux.py
│   └── agent_template_windows.py
├── generated_agents/      # Generated agent output
└── requirements.txt       # Python dependencies
```

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd aipostassisster

# Install dependencies
pip install -r requirements.txt
```

### 2. Start the Operator Server

```bash
python3 operator/server.py
```

The server will start on `http://0.0.0.0:5000`

### 3. Generate Agents

#### Linux Agent
```bash
cd operator
python3 agent_generator.py linux http://<your-operator-ip>:5000
```

#### Windows Agent
```bash
cd operator
python3 agent_generator.py windows http://<your-operator-ip>:5000
```

Generated agents will be in the `generated_agents/` directory.

### 4. Deploy Agents

Transfer the generated agent to your target system and execute:

```bash
# On Linux target
python3 agent_linux_<id>.py

# On Windows target (requires Python)
python agent_windows_<id>.py
```

### 5. Use the Operator CLI

```bash
python3 operator/cli.py http://localhost:5000
```

## 💻 CLI Commands

```
operator> agents                              # List all agents
operator> results <agent_id>                  # View agent results
operator> module <agent_id> <module_name>     # Run assessment module
operator> shell <agent_id> <command>          # Execute shell command
operator> generate <platform> <url>           # Generate new agent
operator> modules                             # List available modules
operator> help                                # Show help
operator> exit                                # Exit CLI
```

## 📊 Example Usage

### List Active Agents
```
operator> agents

╔═══════════════════════════════════════════════════════════════════════╗
║                          REGISTERED AGENTS                            ║
╚═══════════════════════════════════════════════════════════════════════╝

Agent ID:        a1b2c3d4-e5f6-7890-abcd-ef1234567890
Hostname:        web-server-01
Platform:        Linux 5.4.0
IP Address:      192.168.1.100
Status:          active
Last Seen:       2026-01-12T10:30:45
Commands Run:    3
```

### Run Security Assessment
```
operator> module a1b2c3d4-e5f6-7890-abcd-ef1234567890 privilege_escalation

[+] Module 'privilege_escalation' queued for agent a1b2c3d4-e5f6-7890-abcd-ef1234567890
[*] Results will be available shortly using 'results' command
```

### View Results
```
operator> results a1b2c3d4-e5f6-7890-abcd-ef1234567890

╔═══════════════════════════════════════════════════════════════════════╗
║                    RESULTS FOR AGENT: a1b2c3d4-e5f6   ║
╚═══════════════════════════════════════════════════════════════════════╝

Timestamp: 2026-01-12T10:31:00
Module:    privilege_escalation
Results:
{
  "module": "privilege_escalation",
  "platform": "Linux",
  "findings": [
    {
      "severity": "high",
      "finding": "Dangerous SUID binary: /usr/bin/find",
      "description": "find with SUID bit can be exploited for privilege escalation",
      "remediation": "Remove SUID bit: chmod u-s /usr/bin/find"
    }
  ]
}
```

## 🔧 Configuration

### Agent Configuration

Edit agent templates in `templates/` to customize:
- Check-in interval (default: 30 seconds)
- Operator URL
- SSL verification settings

### Server Configuration

Edit `operator/server.py` to configure:
- Server port (default: 5000)
- Inactive agent timeout (default: 5 minutes)
- Logging settings

## 🛡️ Security Considerations

1. **Network Security**: Use HTTPS in production environments
2. **Authentication**: Implement authentication for operator server
3. **Encryption**: Encrypt agent communications
4. **Logging**: Enable comprehensive logging for audit trails
5. **Cleanup**: Remove agents after assessment completion

## 📝 Assessment Modules

### Running Individual Modules

Each module can be run independently:

```python
# Example: Run privilege escalation check
from modules import privilege_escalation

results = privilege_escalation.check()
print(results)
```

### Module Output Format

All modules return results in the following format:

```python
{
    "module": "module_name",
    "platform": "Linux/Windows",
    "findings": [
        {
            "severity": "high/medium/low/info",
            "finding": "Description of finding",
            "description": "Detailed information",
            "remediation": "How to fix"
        }
    ]
}
```

## 🔍 Troubleshooting

### Agent Not Connecting

1. Verify operator server is running
2. Check firewall rules allow port 5000
3. Verify agent has correct operator URL
4. Check network connectivity

### No Results Received

1. Wait 30-60 seconds for agent check-in
2. Verify agent is still running
3. Check operator server logs
4. Verify command was queued successfully

### Module Errors

1. Check agent has required permissions
2. Verify Python dependencies are installed
3. Review module-specific requirements
4. Check agent logs for detailed errors

## 📚 Advanced Usage

### Custom Modules

Create custom assessment modules by following this template:

```python
def check():
    """
    Your custom assessment logic
    """
    results = {
        "module": "custom_module",
        "platform": platform.system(),
        "findings": []
    }

    # Add your checks here

    return results
```

### API Integration

The operator server provides a REST API:

- `POST /api/register` - Agent registration
- `POST /api/checkin` - Agent check-in
- `POST /api/results` - Submit results
- `POST /api/command` - Queue command
- `GET /api/agents` - List agents
- `GET /api/results/<agent_id>` - Get results
- `GET /api/health` - Health check

### Compiled Agents

Compile agents to standalone executables:

```bash
pip install pyinstaller
python3 operator/agent_generator.py linux http://operator:5000
python3 operator/agent_generator.py --compile <agent.py> linux
```

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Code follows existing patterns
- New modules include documentation
- All changes are tested
- Security best practices are followed

## 📄 License

This project is for educational and authorized security testing purposes only.

## 🙏 Acknowledgments

Built for security professionals and penetration testers to assess system security configurations and identify vulnerabilities in authorized environments.

---

**Remember**: Always obtain proper authorization before conducting security assessments. Unauthorized access is illegal and unethical.
