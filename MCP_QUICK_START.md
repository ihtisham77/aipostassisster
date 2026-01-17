# MCP Quick Start Guide

## 🚀 5-Minute Setup

### Prerequisites
- Python 3.8+
- pip package manager
- Git (for updates)

### Step 1: Install Dependencies (1 minute)

```bash
# Linux/Mac
./setup_mcp.sh

# Windows
setup_mcp.bat

# Manual installation
pip install -r requirements.txt
```

### Step 2: Configure VSCode (Optional - 1 minute)

If using VS Code with MCP support:
- The `.vscode/mcp.json` is already configured
- Install MCP extension (if available)
- Reload VSCode window

### Step 3: Start MCP Server (30 seconds)

```bash
python3 mcp_server.py
```

You should see:
```
╔═══════════════════════════════════════════════════════════════╗
║       MCP Server - C2 Security Assessment Framework           ║
╚═══════════════════════════════════════════════════════════════╝

[*] Available MCP Tools:
  - get_framework_status: Check framework status
  - start_operator_server: Start the C2 operator server
  - generate_agent: Generate agents for target systems
  - list_agents: List all registered agents
  - run_assessment: Execute assessment modules
  - get_assessment_results: Retrieve results
  - generate_report: Create assessment reports
  - add_custom_module: Add custom assessment modules
  - get_available_modules: List available modules
  - execute_shell_command: Run shell commands on agents

[*] Starting MCP server...
```

### Step 4: Configure Your LLM Client (2 minutes)

#### For Claude Desktop:

Edit your Claude config file:
- **Mac**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Add this configuration:
```json
{
  "mcpServers": {
    "c2-framework": {
      "command": "python3",
      "args": ["/full/path/to/aipostassisster/mcp_server.py"]
    }
  }
}
```

**Important**: Replace `/full/path/to/aipostassisster` with your actual path!

#### For Other MCP Clients:

Use the standard MCP connection parameters:
- **Command**: `python3`
- **Args**: `["/path/to/aipostassisster/mcp_server.py"]`
- **Working Directory**: Project root
- **Environment**: Standard Python environment

### Step 5: Test the Integration (1 minute)

Start a conversation with your LLM:

**You:** "Check the C2 framework status"

**LLM:** *[Should call `get_framework_status()` and show you the framework status]*

**You:** "Generate a Linux agent"

**LLM:** *[Should call `generate_agent("linux")` and provide the agent file]*

---

## 📝 Quick Examples

### Example 1: First Security Assessment

```
You: "I need to test a Linux system. Walk me through the process."

LLM: "I'll help you set up a security assessment. Let me start by
      checking the framework status..."

      [Calls get_framework_status()]

      "The operator server is not running. Let me start it for you..."

      [Calls start_operator_server()]

      "Great! Now I'll generate a Linux agent..."

      [Calls generate_agent("linux")]

      "Agent generated! Here's what to do:
       1. Transfer agent_linux_abc123.py to your target
       2. Copy the modules/ directory too
       3. Run: python3 agent_linux_abc123.py
       4. Come back when the agent is running"
```

### Example 2: Running Assessment

```
You: "The agent is now active on the target system."

LLM: "Perfect! Let me check the registered agents..."

      [Calls list_agents()]

      "I see your agent (ID: abc-123-def) is connected.
       Running a complete security assessment now..."

      [Calls run_assessment("abc-123-def", "all")]

      "Assessment in progress with 9 modules:
       ✓ reconnaissance
       ✓ privilege_escalation
       ✓ persistence
       ✓ credential_harvesting
       ✓ lateral_movement
       ✓ data_access
       ✓ data_exfiltration
       ✓ c2_comms
       ✓ covering_tracks

       Wait about 60 seconds for completion..."
```

### Example 3: Get Results and Report

```
You: "Show me the results."

LLM: "Let me retrieve the assessment results..."

      [Calls get_assessment_results("abc-123-def")]

      "Assessment complete! Summary:
       - 2 CRITICAL findings
       - 5 HIGH severity issues
       - 8 MEDIUM severity issues
       - 12 LOW severity findings

       Top concerns:
       1. SUID binary /usr/bin/find (privilege escalation)
       2. Exposed SSH private keys in /home/admin/.ssh

       Would you like me to generate a report?"

You: "Yes, create an HTML report."

LLM: [Calls generate_report("abc-123-def", "html")]

     "Report generated: reports/assessment_abc123_20260117.html

      The report includes:
      - Executive summary
      - Risk scoring (78/100)
      - All findings with evidence
      - Remediation steps
      - Charts and visualizations

      Ready for client delivery!"
```

---

## 🔧 Common Issues and Solutions

### Issue: "Cannot connect to operator server"

**Solution:**
```bash
# Check if server is running
python3 framework_starter.py status

# Start if needed
python3 framework_starter.py start

# Check from MCP server
python3 -c "import requests; print(requests.get('http://localhost:8542/api/health').json())"
```

### Issue: "Agent not showing up"

**Solution:**
1. Verify agent is running on target: `ps aux | grep agent`
2. Check network connectivity: `curl http://operator-ip:8542/api/health`
3. Check firewall rules allow port 8542
4. Look at agent output for errors

### Issue: "MCP tools not appearing in LLM"

**Solution:**
1. Verify MCP server is running
2. Check LLM config file has correct path
3. Restart LLM client
4. Check MCP logs for errors

### Issue: "Module execution fails"

**Solution:**
1. Check module compatibility with agent OS
2. Verify agent has required permissions
3. Check agent logs: `tail -f /tmp/agent.log` (if logging enabled)
4. Test module independently on target

---

## 📚 Next Steps

### Learn More:
- **Technical Details**: [MCP_INTEGRATION.md](MCP_INTEGRATION.md)
- **Use Cases**: [USE_CASES.md](USE_CASES.md)
- **Core Framework**: [README.md](README.md)

### Advanced Topics:
- Adding custom modules
- CI/CD integration
- Multi-tenant deployments
- Compliance reporting
- API automation

### Community:
- Report issues on GitHub
- Share your use cases
- Contribute modules
- Improve documentation

---

## 🎯 Quick Command Reference

### Framework Management
```bash
# Start operator server
python3 framework_starter.py start

# Check status
python3 framework_starter.py status

# Stop server
python3 framework_starter.py stop

# Restart server
python3 framework_starter.py restart
```

### MCP Server
```bash
# Start MCP server
python3 mcp_server.py

# Start in background (Linux/Mac)
nohup python3 mcp_server.py > mcp.log 2>&1 &

# Start in background (Windows)
start /B python mcp_server.py
```

### Manual Agent Generation
```bash
# Generate Linux agent
python3 operator/agent_generator.py linux

# Generate Windows agent
python3 operator/agent_generator.py windows

# Generate with custom URL
python3 operator/agent_generator.py linux http://custom-ip:8542
```

### Traditional CLI (Without MCP)
```bash
# Start CLI
python3 operator/cli.py

# Commands
operator> agents                    # List agents
operator> modules                   # List modules
operator> module <id> <module>      # Run module
operator> results <id>              # Get results
operator> report <id> html          # Generate report
```

---

## 🔐 Security Reminders

1. **Authorization Required**: Always get written permission
2. **Scope Definition**: Define clear boundaries
3. **Data Handling**: Secure all assessment data
4. **Clean Up**: Remove agents after testing
5. **Documentation**: Keep audit trails

---

## 📞 Support

- **Documentation**: Full docs in `MCP_INTEGRATION.md`
- **Issues**: GitHub issue tracker
- **Examples**: See `USE_CASES.md`

---

**You're ready to go!** Start your first assessment by talking to your LLM client naturally about what you want to test.
