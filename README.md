# C2 Security Assessment Framework

A comprehensive Command and Control (C2) framework for security testing and assessment. This framework allows security professionals to test system configurations and identify security weaknesses across Windows and Linux environments.

## 🆕 What's New in v1.2

### 🤖 MCP Integration - LLM-Powered Security Testing (NEW!)

The framework now supports **Model Context Protocol (MCP)**, enabling AI-powered security assessments through Large Language Models like Claude!

**Key Features:**
- **🎙️ Natural Language Control**: Interact with the framework using conversational commands
- **🤖 Automatic Agent Generation**: LLMs can generate and deploy agents automatically
- **🧩 Dynamic Module Addition**: Add custom assessment modules on-the-fly through LLM interaction
- **📊 Intelligent Reporting**: AI-assisted report generation and analysis
- **🚀 Auto-Start Capability**: Operator server starts automatically when needed

**Quick Start with MCP:**
```bash
# Run setup script
./setup_mcp.sh  # Linux/Mac
setup_mcp.bat   # Windows

# Start MCP server
python3 mcp_server.py

# Configure your LLM client and start testing with natural language!
```

**See [MCP_INTEGRATION.md](MCP_INTEGRATION.md) for complete documentation.**
**See [USE_CASES.md](USE_CASES.md) for real-world usage scenarios.**

### Major Improvements

1. **🎯 Simplified Workflow**
   - Auto-detection of server IP and port
   - No need to specify URLs manually
   - Just run `python3 agent_generator.py linux` or `python3 cli.py`

2. **📊 Professional Report Generation**
   - Comprehensive HTML, Markdown, and JSON reports
   - Executive summary with risk scoring (0-100)
   - Visual charts and severity indicators
   - Actionable remediation recommendations
   - Professional design suitable for stakeholder review

3. **⚙️ Configuration System**
   - Multi-layered configuration (CLI > ENV > config.json > defaults)
   - Environment variable support
   - Centralized config.json file
   - Easy customization without code changes

4. **🔒 Input Validation**
   - All API endpoints validate inputs
   - UUID format checking
   - String length limits
   - Required field validation
   - Proper error messages and HTTP status codes

5. **🔧 Enhanced Usability**
   - New default port: 8542 (less conflicts)
   - Better error messages
   - Improved CLI help system
   - Auto-detection of network configuration

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

The server will start on `http://0.0.0.0:8542` (new default port)

**Output:**
```
╔═══════════════════════════════════════╗
║     C2 Operator Server v1.0           ║
║   Security Assessment Framework       ║
╚═══════════════════════════════════════╝

[*] Starting operator server on http://0.0.0.0:8542
[*] Local IP: 192.168.1.100
[*] External URL: http://192.168.1.100:8542
[*] Use operator CLI to interact with agents
[*] Inactive agent timeout: 300s
```

### 3. Generate Agents (Simplified!)

**No need to specify URL anymore!** Auto-detection handles it:

```bash
# Linux Agent
python3 operator/agent_generator.py linux

# Windows Agent
python3 operator/agent_generator.py windows
```

The generator automatically detects the server IP and port. Generated agents will be in the `generated_agents/` directory.

**Optional:** Override URL if needed:
```bash
python3 operator/agent_generator.py linux http://<custom-ip>:8542
```

### 4. Deploy Agents

Transfer the generated agent to your target system and execute:

```bash
# On Linux target
python3 agent_linux_<id>.py

# On Windows target (requires Python)
python agent_windows_<id>.py
```

### 5. Use the Operator CLI (Simplified!)

**Simply run:**
```bash
python3 operator/cli.py
```

The CLI automatically connects to the server. No URL needed!

**Optional:** Connect to custom server:
```bash
python3 operator/cli.py http://<server-ip>:8542
```

## 💻 CLI Commands

```
operator> agents                               # List all agents
operator> results <agent_id>                   # View agent results
operator> module <agent_id> <module_name>      # Run assessment module
operator> shell <agent_id> <command>           # Execute shell command
operator> report <agent_id> [format] [dir]     # Generate professional report (NEW!)
operator> generate <platform> [url]            # Generate new agent (URL optional)
operator> modules                              # List available modules
operator> help                                 # Show help
operator> exit                                 # Exit CLI
```

### Report Formats

Generate comprehensive security reports in multiple formats:

- `all` - JSON, Markdown, and HTML (default)
- `json` - Structured data format
- `html` - Professional web report
- `markdown` - Documentation-friendly format

**Example:**
```
operator> report abc123def456 all reports/
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

## 📊 Professional Report Generation (NEW!)

Generate comprehensive, professional security assessment reports with a single command!

### Features

- **Executive Summary** - Risk score, key statistics, critical findings
- **Risk Assessment** - Overall risk level (0-100 score) with visual indicators
- **Detailed Findings** - Organized by severity with remediation steps
- **Multiple Formats** - JSON, Markdown, and HTML reports
- **Professional Design** - Clean, readable HTML reports with charts
- **Actionable Recommendations** - Prioritized remediation guidance

### Generate Reports

```bash
# From CLI
operator> report <agent_id>

# From command line
python3 operator/report_generator.py http://localhost:8542 <agent_id>
```

### Report Contents

1. **Executive Summary**
   - Target system information
   - Overall risk score and level
   - Total findings by severity
   - Key security concerns (top 5)

2. **Statistics Dashboard**
   - Findings distribution chart
   - Severity breakdown
   - Module coverage
   - Assessment timeline

3. **Detailed Findings**
   - Critical issues (prioritized)
   - High severity issues
   - Medium and low issues
   - Informational findings
   - Each with description and remediation

4. **Recommendations**
   - Immediate actions (critical)
   - High priority actions
   - Medium priority actions
   - Long-term improvements

### Sample Report Output

```
reports/
├── report_webserver_abc123de_20260116_143022.html  # Professional web report
├── report_webserver_abc123de_20260116_143022.md    # Markdown documentation
└── report_webserver_abc123de_20260116_143022.json  # Structured data
```

**Open HTML report in browser for best experience!**

---

## 🔧 Configuration

### Automatic Configuration (NEW!)

The framework now features automatic configuration with multiple sources:

**Priority Order:**
1. Command-line arguments (highest)
2. Environment variables
3. config.json file
4. Default values (lowest)

### config.json

The framework automatically reads from `config.json`:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8542,
    "inactive_timeout": 300
  },
  "agent": {
    "checkin_interval": 30,
    "command_timeout": 30
  },
  "operator": {
    "default_server_url": "http://localhost:8542"
  }
}
```

### Environment Variables

Override configuration using environment variables:

```bash
export OPERATOR_URL="http://192.168.1.100:8542"
export OPERATOR_PORT=9000
export CHECKIN_INTERVAL=60

# Now all tools auto-detect these settings
python3 operator/agent_generator.py linux
python3 operator/cli.py
```

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

### Implemented Security Features (NEW!)

1. **Input Validation** ✅
   - UUID format validation for agent IDs
   - String length limits on all inputs
   - Required field validation
   - Data type checking
   - Command type validation
   - Malformed request rejection

2. **Error Handling** ✅
   - Descriptive error messages
   - HTTP status codes (400, 404, 500)
   - Graceful degradation
   - No information leakage

### Recommended Additional Security

1. **Network Security**: Use HTTPS in production environments (implement TLS)
2. **Authentication**: Implement API key or OAuth for operator server
3. **Encryption**: Encrypt agent communications (implement E2E encryption)
4. **Logging**: Enable comprehensive logging for audit trails
5. **Cleanup**: Remove agents after assessment completion
6. **Access Control**: Restrict operator CLI access
7. **Report Security**: Secure report storage (contains sensitive data)

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
