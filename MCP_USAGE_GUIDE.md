# 🤖 MCP Server Usage Guide

## What is MCP?

**Model Context Protocol (MCP)** allows Large Language Models (like Claude) to interact with your C2 Security Assessment Framework through standardized tools. Think of it as giving Claude "superpowers" to control your security testing framework via natural language.

---

## 🚀 Quick Start

### Method 1: VSCode Integration (Recommended)

#### Prerequisites
1. **VSCode** with **Claude Dev** or **Cline** extension installed
2. **Python 3.7+** installed
3. This repository cloned

#### Setup Steps

1. **Open VSCode Settings**
   ```
   VSCode → Settings → Extensions → Claude Dev (or Cline) → MCP Servers
   ```

2. **Configuration is Already Done!**

   The `.vscode/mcp.json` file is already configured:
   ```json
   {
     "mcpServers": {
       "c2-security-framework": {
         "command": "python3",
         "args": ["mcp_server.py"],
         "cwd": "/home/user/aipostassisster"
       }
     }
   }
   ```

3. **Restart VSCode**

   Close and reopen VSCode to load the MCP server.

4. **Verify Connection**

   In Claude Dev chat, type:
   ```
   Can you see the C2 Security Assessment Framework tools?
   ```

   Claude should respond with available tools.

---

### Method 2: Standalone MCP Server

Run the server directly for testing or debugging:

```bash
cd /home/user/aipostassisster
python3 mcp_server.py
```

**Note:** Standalone mode is primarily for development. VSCode integration is recommended for production use.

---

## 🎯 What Can You Do with MCP?

The MCP server exposes your entire security framework to Claude. Here's what you can do:

### 1. **Natural Language Framework Control**

Instead of memorizing CLI commands, just tell Claude what you want:

**Traditional Way:**
```bash
python3 operator/server.py &
python3 operator/agent_generator.py linux
python3 operator/cli.py
> module abc123 all
> results abc123
```

**MCP Way (Natural Language):**
```
Claude, start the operator server and generate a Linux agent
```

Claude will:
1. Start the server
2. Generate the agent
3. Show you deployment instructions

---

### 2. **Intelligent Assessment Planning**

**You Say:**
```
I have a Windows domain workstation with CrowdStrike EDR.
What's the safest way to assess it?
```

**Claude Does:**
1. Analyzes the environment (EDR present)
2. Recommends low-noise modules
3. Suggests assessment order
4. Warns about risky techniques
5. Provides step-by-step plan

**Example Response:**
```
Given CrowdStrike EDR presence, I recommend:

1. Start with reconnaissance (passive, low noise)
2. Avoid credential_access LSASS techniques (high detection)
3. Use browser credential harvesting instead
4. Focus on privilege_escalation via misconfigurations
5. Skip process injection techniques

Would you like me to start the assessment?
```

---

### 3. **Automated Agent Management**

**You Say:**
```
List all my agents and show which ones are active
```

**Claude Does:**
```python
# Calls: list_agents()
```

**Response:**
```
You have 3 registered agents:

1. Agent: abc-123-def
   Host: DESKTOP-WIN10
   Platform: Windows 10
   Status: ✓ Active (last seen 30s ago)

2. Agent: xyz-789-ghi
   Host: ubuntu-server-01
   Platform: Linux Ubuntu 20.04
   Status: ✗ Inactive (last seen 5m ago)

3. Agent: jkl-456-mno
   Host: web-server-prod
   Platform: Linux CentOS 7
   Status: ✓ Active (last seen 15s ago)

Would you like to run assessments on any of these?
```

---

### 4. **Context-Aware Module Execution**

**You Say:**
```
Run a full security assessment on agent abc-123-def
```

**Claude Does:**
1. Checks agent platform (Windows)
2. Queues all compatible modules
3. Executes in priority order
4. Monitors progress
5. Presents results with intelligence

**Progress Updates:**
```
✓ Reconnaissance complete (12 findings)
✓ Credential Access complete (8 findings)
⚙ Privilege Escalation running...
```

---

### 5. **Intelligent Report Analysis**

**You Say:**
```
Show me the most critical findings from agent abc-123-def
```

**Claude Does:**
1. Fetches all results
2. Runs risk scoring
3. Generates attack paths
4. Identifies quick wins
5. Presents prioritized summary

**Response:**
```
🔴 CRITICAL FINDINGS (3)

1. [CREDENTIAL_ACCESS] Domain admin credentials in browser
   Impact: 95% | Noise: 20% | Feasibility: 90%
   → QUICK WIN: High-value, low-noise credential

2. [PRIVILEGE_ESCALATION] Writable service binary
   Impact: 90% | Noise: 35% | Feasibility: 85%
   → RECOMMENDED: Clean privilege escalation path

3. [LATERAL_MOVEMENT] SMB access to domain controller
   Impact: 100% | Noise: 30% | Feasibility: 95%
   → READY: Can pivot to DC with current credentials

🎯 RECOMMENDED ATTACK PATH:
   recon → harvest browser creds → escalate via service →
   pivot to DC → exfiltrate domain data → cleanup

Would you like detailed remediation steps?
```

---

### 6. **Custom Module Development**

**You Say:**
```
Help me create a custom module that checks for exposed Docker sockets
```

**Claude Does:**
1. Generates Python module code
2. Adds to framework
3. Tests the module
4. Shows how to use it

**Generated Code:**
```python
"""
Docker Socket Exposure Module
Checks for exposed Docker sockets and insecure configurations
"""

def check():
    results = {
        "module": "docker_exposure",
        "findings": []
    }

    # Check for exposed socket
    if os.path.exists('/var/run/docker.sock'):
        # Check permissions
        st = os.stat('/var/run/docker.sock')
        if st.st_mode & 0o666:
            results["findings"].append({
                "severity": "critical",
                "finding": "World-writable Docker socket",
                "description": "Docker socket is accessible by all users..."
            })

    return results
```

---

## 🛠️ Available MCP Tools

When you use the MCP server, Claude has access to these tools:

### 1. `get_framework_status`
**What it does:** Check if operator server is running

**Example:**
```
Claude, is the operator server running?
```

**Response:**
```json
{
  "server_status": "online",
  "active_agents": 2,
  "total_agents": 3,
  "available_modules": 7,
  "server_url": "http://192.168.1.100:8542"
}
```

---

### 2. `start_operator_server`
**What it does:** Start the C2 operator server

**Example:**
```
Claude, start the operator server
```

**Response:**
```
✓ Operator server started successfully
  URL: http://192.168.1.100:8542
  PID: 12345
  Status: Online
```

---

### 3. `generate_agent`
**What it does:** Generate agents for Windows or Linux

**Parameters:**
- `platform`: "windows" or "linux"
- `operator_url`: (optional) custom operator URL

**Example:**
```
Claude, generate a Windows agent
```

**Response:**
```
✓ Agent generated successfully

Agent ID: abc-123-def-456
Platform: Windows
Output: generated_agents/agent_windows_abc123.py

Deployment Instructions:
1. Transfer agent file and 'modules' directory to target
2. Run: python agent_windows_abc123.py
3. Agent will auto-register with operator server
```

---

### 4. `list_agents`
**What it does:** Show all registered agents

**Example:**
```
Claude, show me all agents
```

**Response:**
```
Total Agents: 3

1. abc-123-def
   Host: DESKTOP-WIN10
   Platform: Windows 10
   IP: 192.168.1.50
   Last Seen: 30 seconds ago
   Status: ✓ Active
   Commands: 5 executed

2. xyz-789-ghi
   Host: ubuntu-server
   Platform: Linux Ubuntu 20.04
   IP: 192.168.1.100
   Last Seen: 2 minutes ago
   Status: ⚠ Idle
   Commands: 0 executed
```

---

### 5. `run_assessment`
**What it does:** Execute security assessment modules on an agent

**Parameters:**
- `agent_id`: Target agent ID
- `modules`: "all" or comma-separated list (e.g., "reconnaissance,credential_access")

**Example:**
```
Claude, run full assessment on agent abc-123-def
```

**What Claude Does:**
1. Identifies agent platform (Windows)
2. Queues compatible modules (all 7 phases)
3. Executes in priority order:
   - Reconnaissance (priority 1)
   - Credential Access (priority 2)
   - Privilege Escalation (priority 3)
   - Persistence (priority 4)
   - Lateral Movement (priority 5)
   - Exfiltration (priority 6)
   - Cleanup (priority 7)
4. Returns results with intelligence

---

### 6. `get_assessment_results`
**What it does:** Retrieve results with intelligent analysis

**Parameters:**
- `agent_id`: Target agent ID
- `enable_intelligence`: (optional) Enable AI analysis (default: true)

**Example:**
```
Claude, analyze the assessment results for agent abc-123-def
```

**Response with Intelligence:**
```
📊 ASSESSMENT SUMMARY
═══════════════════════════════════════

Target: DESKTOP-WIN10 (Windows 10)
Risk Score: 78/100 (HIGH)
Total Findings: 42

🛡️ OPSEC ASSESSMENT
───────────────────────────────────────
Threat Level: High
EDR Detected: ✓ CrowdStrike Falcon
SIEM: ✓ Splunk
Privilege: User
Domain Joined: ✓ Yes

⚠️ Key Recommendations:
  → Avoid LSASS memory access (high detection)
  → Use browser credential harvesting instead
  → Focus on configuration-based privilege escalation

🎯 QUICK WINS (5)
───────────────────────────────────────
1. Browser credentials (Impact: 75%, Noise: 20%)
2. Saved Wi-Fi passwords (Impact: 60%, Noise: 15%)
3. Readable .env files (Impact: 70%, Noise: 25%)

📍 RECOMMENDED ACTIONS (Top 5)
───────────────────────────────────────
1. [CREDENTIAL_ACCESS] Harvest browser credentials
   Priority: 85 | Impact: 75 | Stealth: 80
   → SAFE: Low-noise credential harvesting

2. [PRIVILEGE_ESCALATION] Exploit writable service binary
   Priority: 82 | Impact: 90 | Stealth: 65
   → VIABLE: Clean privilege escalation path

3. [LATERAL_MOVEMENT] Access file server via SMB
   Priority: 80 | Impact: 85 | Stealth: 70
   → READY: Target accessible with credentials

🎯 ATTACK PATHS (Top 3)
───────────────────────────────────────
Path 1: recon → cred_access → priv_esc → lateral
  Risk: Low Risk | Score: 78/100
  Steps: 4
  → RECOMMENDED: High-value path with good stealth

Path 2: recon → cred_access → lateral → exfil
  Risk: Moderate Risk | Score: 72/100
  Steps: 4
  → VIABLE: Faster but slightly noisier

Path 3: recon → priv_esc → persistence → lateral
  Risk: High Risk | Score: 65/100
  Steps: 4
  → RISKY: Requires privilege escalation first
```

---

## 💡 Real-World Use Cases

### Use Case 1: Red Team Engagement Planning

**Scenario:** You're starting a red team engagement against a corporate network.

**Conversation with Claude:**

```
You: I need to assess a Windows domain environment.
     They have modern security controls. Plan my engagement.

Claude: I'll help you plan a stealthy engagement. Let me start
        by setting up the framework.

        [Calls: start_operator_server()]
        ✓ Operator server started

        [Calls: generate_agent("windows")]
        ✓ Windows agent generated: agent_win_abc123.py

        ENGAGEMENT PLAN:

        Phase 1: RECONNAISSANCE (Low Noise)
        ────────────────────────────────────
        Deploy agent to initial foothold
        Run reconnaissance module
        Detect: EDR, SIEM, domain config, privilege level
        Expected time: 2-3 minutes

        Phase 2: CREDENTIAL ACCESS (Context-Aware)
        ────────────────────────────────────────────
        IF EDR detected:
          → Focus on browser credentials (low noise)
          → Check config files and env vars
          → AVOID LSASS dumps (high detection)
        ELSE:
          → All credential harvesting techniques viable

        Phase 3: PRIVILEGE ESCALATION (Risk-Based)
        ──────────────────────────────────────────
        Prioritize:
          1. Service misconfigurations (stealth: 65%)
          2. Scheduled task hijacking (stealth: 55%)
          3. DLL hijacking (stealth: 50%)
        Avoid:
          → Kernel exploits (may crash system)

        Phase 4: LATERAL MOVEMENT (Strategic)
        ─────────────────────────────────────
        Map network trust relationships
        Identify high-value targets:
          → Domain controllers
          → File servers
          → Database servers

        Phase 5: DATA EXFILTRATION (Stealthy Channels)
        ──────────────────────────────────────────────
        Recommended channels:
          1. HTTPS (blends with traffic)
          2. DNS tunneling (slow but covert)
        Avoid:
          → Large volume transfers (triggers DLP)

        Phase 6: CLEANUP (Artifact Removal)
        ───────────────────────────────────
        Track all artifacts for removal
        Clear command history
        Remove persistence mechanisms

        Ready to deploy? I can walk you through each phase.
```

---

### Use Case 2: Vulnerability Assessment

**Scenario:** Quick security audit of a Linux server.

**Conversation:**

```
You: Quick security check on my Ubuntu server. Agent already deployed.

Claude: I'll run a comprehensive assessment.

        [Calls: list_agents()]
        Found agent: xyz-789-ghi (ubuntu-server, Linux)

        [Calls: run_assessment("xyz-789-ghi", "all")]
        Running all 7 assessment modules...

        ⚙ Progress:
        ✓ Reconnaissance (15 findings)
        ✓ Credential Access (8 findings)
        ✓ Privilege Escalation (12 findings)
        ✓ Persistence (5 findings)
        ✓ Lateral Movement (3 findings)
        ✓ Exfiltration (7 findings)
        ✓ Cleanup (4 findings)

        [Calls: get_assessment_results("xyz-789-ghi")]

        🔴 CRITICAL ISSUES (3):

        1. /etc/shadow is readable by current user
           → Immediate privilege escalation risk
           → Can crack password hashes

        2. Sudo misconfiguration allows NOPASSWD
           → Direct root access available
           → Command: sudo /usr/bin/find

        3. SSH keys world-readable in /home/backup/.ssh/
           → Access to other systems possible
           → Found keys for: prod-server, db-server

        🎯 ATTACK PATH:
        recon → sudo exploit → root access →
        harvest all credentials → lateral to prod servers

        ⚡ QUICK WIN:
        Exploit sudo misconfiguration for instant root
        Impact: 100% | Noise: 25% | Feasibility: 100%

        📋 REMEDIATION PRIORITY:
        1. Fix sudo configuration (CRITICAL)
        2. Secure /etc/shadow permissions (CRITICAL)
        3. Fix SSH key permissions (HIGH)
        4. Review all user home directories (MEDIUM)

        Would you like the full report in HTML format?
```

---

### Use Case 3: Continuous Monitoring

**Scenario:** Monitor multiple deployed agents.

**Conversation:**

```
You: Check status of all my deployed agents

Claude: [Calls: list_agents()]

        📊 AGENT STATUS SUMMARY
        ═══════════════════════════════════════

        Total Agents: 5
        Active: 3 ✓
        Idle: 2 ⚠

        🟢 ACTIVE AGENTS:

        1. win-agent-001 (DESKTOP-SALES)
           Platform: Windows 10
           Last seen: 15 seconds ago
           Commands executed: 12
           Latest: privilege_escalation module

        2. linux-agent-002 (web-server-01)
           Platform: Ubuntu 20.04
           Last seen: 30 seconds ago
           Commands executed: 8
           Latest: reconnaissance module

        3. win-agent-003 (DC-PRIMARY)
           Platform: Windows Server 2019
           Last seen: 45 seconds ago
           Commands executed: 15
           Latest: lateral_movement module

        ⚠️ IDLE AGENTS:

        4. linux-agent-004 (db-server)
           Last seen: 5 minutes ago
           Status: Possibly disconnected

        5. win-agent-005 (laptop-mobile)
           Last seen: 15 minutes ago
           Status: Host likely offline

        Would you like me to run assessments on the active agents?
```

---

### Use Case 4: Custom Module Development

**Scenario:** Need a specialized check for your environment.

**Conversation:**

```
You: Can you create a module that checks for exposed Kubernetes configs?

Claude: I'll create a custom Kubernetes exposure module.

        [Generates custom module code]

        ✓ Created: agent/modules/kubernetes_exposure.py

        Module capabilities:
        - Checks for ~/.kube/config exposure
        - Validates kubeconfig permissions
        - Tests cluster connectivity
        - Enumerates accessible namespaces
        - Checks RBAC misconfigurations
        - Detects privileged service accounts

        [Calls: add_custom_module()]
        ✓ Module registered in framework

        To use:
        > module <agent_id> kubernetes_exposure

        Or add to assessment workflows:
        > module <agent_id> reconnaissance,kubernetes_exposure

        Would you like me to test it on an agent?
```

---

## 🎓 Pro Tips

### 1. **Let Claude Explain as It Works**

```
You: Explain what you're doing as you run the assessment

Claude: I'll walk you through each step...

        Step 1: Starting Reconnaissance
        ├─ Checking OS and kernel version
        ├─ Enumerating users and groups
        ├─ Scanning network interfaces
        └─ Detecting security controls

        Found: CrowdStrike EDR running
        ↳ Adjusting strategy: Will use low-noise techniques

        Step 2: Credential Access (EDR-Aware)
        ├─ Scanning browser credential stores ✓ Safe
        ├─ Checking config files ✓ Safe
        ├─ Skipping LSASS dump ✗ Too noisy with EDR
        └─ Looking for plaintext credentials

        Found: 8 credentials in browser
        ↳ Including 2 domain admin accounts

        Step 3: Privilege Escalation...
```

### 2. **Ask for Recommendations**

```
You: What should I do next?

Claude: Based on current findings:

        RECOMMENDED: Harvest browser credentials first
        - Low noise (20%)
        - High impact (found admin creds)
        - Easy execution

        THEN: Exploit writable service binary
        - Moderate noise (35%)
        - Gives you SYSTEM privileges
        - No EDR alerts expected

        AVOID: LSASS memory dumps
        - High noise (90%)
        - CrowdStrike will definitely alert
        - Not worth the risk
```

### 3. **Request Specific Report Formats**

```
You: Generate an HTML report for management

Claude: [Calls: generate_report("abc-123", "html")]

        ✓ Generated: reports/report_abc123.html

        Report includes:
        - Executive summary with risk scoring
        - Visual charts and graphs
        - OPSEC assessment
        - Attack path diagrams
        - Detailed findings by severity
        - Remediation recommendations

        Open in browser: file:///.../report_abc123.html
```

### 4. **Get Contextual Help**

```
You: I'm stuck. The agent stopped responding.

Claude: Let me diagnose the issue...

        [Calls: list_agents()]

        Agent Status: Inactive (last seen 10 minutes ago)

        Possible causes:
        1. Network connectivity lost
        2. Agent process crashed
        3. Host rebooted
        4. Operator server connection issue

        Troubleshooting steps:
        1. Check operator server: [Calls: get_framework_status()]
           → Server is running (OK)
        2. Verify network connectivity to host
        3. Check if agent process is still running on target
        4. Review agent logs if accessible

        If host is still accessible, redeploy the agent.
        Would you like me to generate a new agent?
```

---

## 🔒 Security Considerations

### MCP Server Security

1. **Local Access Only**
   - MCP server runs locally on your machine
   - No external network exposure
   - Communications stay within VSCode

2. **Command Validation**
   - All tool calls are validated
   - Agent IDs must be valid UUIDs
   - Module names checked against registry

3. **No Auto-Execution**
   - MCP server requires explicit commands
   - Claude asks for confirmation on destructive actions
   - You maintain full control

4. **Audit Trail**
   - All tool calls are logged
   - Review MCP server console output
   - Track what Claude executed

---

## 🐛 Troubleshooting

### Issue: "MCP Server Not Responding"

**Solution:**
```bash
# 1. Check if server is running
ps aux | grep mcp_server.py

# 2. Check for errors
cd /home/user/aipostassisster
python3 mcp_server.py

# 3. Restart VSCode
# 4. Check .vscode/mcp.json configuration
```

### Issue: "Tools Not Available in Claude"

**Solution:**
1. Verify MCP server configuration in VSCode settings
2. Restart VSCode completely (close all windows)
3. Check Claude Dev/Cline extension is installed and enabled
4. Look for MCP connection status in extension

### Issue: "Operator Server Connection Failed"

**Solution:**
```bash
# Start operator server manually
cd /home/user/aipostassisster
python3 operator/server.py

# Verify it's running
curl http://localhost:8542/api/health
```

---

## 📚 Additional Resources

- **Main Documentation:** `README.md`
- **Intelligence Features:** `INTELLIGENT_ASSISTANT.md`
- **Module Details:** `agent/modules/`
- **API Reference:** `operator/server.py`

---

## 🎯 Summary

With MCP integration, you can:

✅ **Control the framework with natural language**
✅ **Get intelligent recommendations from Claude**
✅ **Automate complex workflows**
✅ **Receive context-aware guidance**
✅ **Generate comprehensive reports**
✅ **Develop custom modules with AI assistance**

**Start chatting with Claude:**
```
"Hey Claude, help me run a security assessment!"
```

That's it! The framework becomes your AI-powered security copilot. 🚀🔒
