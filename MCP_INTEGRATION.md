# MCP Integration Guide

## Overview

The C2 Security Assessment Framework now supports **Model Context Protocol (MCP)** integration, enabling Large Language Models (LLMs) to interact with the framework directly for authorized security testing.

## Features

- **Automatic Agent Generation**: LLMs can generate agents for target systems
- **Auto-Start Capability**: Operator server starts automatically when needed
- **Dynamic Module Addition**: Add custom post-exploitation modules on the fly
- **Natural Language Interaction**: Use conversational commands for assessments
- **Comprehensive Results**: Get assessment results and reports through MCP

## Architecture

```
┌─────────────────┐
│      LLM        │
│   (Claude)      │
└────────┬────────┘
         │ MCP Protocol
         ▼
┌─────────────────────────────────────┐
│       mcp_server.py                 │
│  (FastMCP Server)                   │
│  - Tool: generate_agent             │
│  - Tool: list_agents                │
│  - Tool: run_assessment             │
│  - Tool: get_assessment_results     │
│  - Tool: generate_report            │
│  - Tool: add_custom_module          │
│  - Tool: start_operator_server      │
└────────┬────────────────────────────┘
         │ HTTP/REST API
         ▼
┌─────────────────────────────────────┐
│   operator/server.py                │
│  (Flask API Server)                 │
│  - Agent registration               │
│  - Command queueing                 │
│  - Results collection               │
│  - Dynamic module management        │
└────────┬────────────────────────────┘
         │ Check-in/Beacon
         ▼
┌─────────────────────────────────────┐
│        Agents                       │
│  (Target Systems)                   │
│  - Windows agents                   │
│  - Linux agents                     │
│  - Module execution                 │
└─────────────────────────────────────┘
```

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the MCP Server

```bash
python mcp_server.py
```

The MCP server will:
- Check if the operator server is running
- Provide tools for LLM interaction
- Auto-start the operator server if needed

### 3. Connect Your LLM

Configure your LLM client to connect to the MCP server. For Claude Desktop, add to your configuration:

```json
{
  "mcpServers": {
    "c2-framework": {
      "command": "python",
      "args": ["/path/to/aipostassisster/mcp_server.py"]
    }
  }
}
```

### 4. Start Using with LLM

Simply ask your LLM to:
- "Check the C2 framework status"
- "Generate a Linux agent for security testing"
- "List all registered agents"
- "Run a security assessment on agent XYZ"
- "Generate an HTML report for agent XYZ"

## Available MCP Tools

### 1. `get_framework_status()`

Get current status of the C2 framework.

**Returns:**
- Server status (online/offline)
- Number of active agents
- Available modules
- Server URL

**Example:**
```python
get_framework_status()
```

### 2. `start_operator_server()`

Start the C2 operator server if not running.

**Returns:**
- Server startup status
- Server URL
- Process ID

**Example:**
```python
start_operator_server()
```

### 3. `generate_agent(platform, operator_url=None)`

Generate a new agent for deployment.

**Parameters:**
- `platform`: "windows" or "linux"
- `operator_url`: Optional custom operator URL

**Returns:**
- Agent ID
- Output file path
- Deployment instructions

**Example:**
```python
generate_agent("linux")
generate_agent("windows", "http://192.168.1.100:8542")
```

### 4. `list_agents()`

List all registered agents.

**Returns:**
- Array of agent information
- Agent IDs, hostnames, platforms
- Last seen timestamps
- Status (active/inactive)

**Example:**
```python
list_agents()
```

### 5. `run_assessment(agent_id, modules="all")`

Execute security assessment modules on an agent.

**Parameters:**
- `agent_id`: Target agent's unique identifier
- `modules`: "all" or comma-separated list of module names

**Available modules:**
- reconnaissance
- privilege_escalation
- persistence
- credential_harvesting
- lateral_movement
- data_access
- data_exfiltration
- c2_comms
- covering_tracks

**Returns:**
- Queued modules list
- Queue status
- Execution message

**Example:**
```python
run_assessment("abc-123-def", "all")
run_assessment("abc-123-def", "reconnaissance,privilege_escalation")
```

### 6. `get_assessment_results(agent_id)`

Retrieve assessment results from an agent.

**Parameters:**
- `agent_id`: Agent's unique identifier

**Returns:**
- Complete assessment results
- Findings with severity levels
- Confidence scores
- Timestamps

**Example:**
```python
get_assessment_results("abc-123-def")
```

### 7. `generate_report(agent_id, format_type="console")`

Generate a comprehensive security report.

**Parameters:**
- `agent_id`: Agent's unique identifier
- `format_type`: "console", "json", "html", "markdown", or "all"

**Returns:**
- Report file paths
- Generation status
- Report summary

**Example:**
```python
generate_report("abc-123-def", "html")
generate_report("abc-123-def", "all")
```

### 8. `add_custom_module(module_name, module_code, description, platforms="Linux,Windows")`

Add a custom post-exploitation module dynamically.

**Parameters:**
- `module_name`: Unique identifier (snake_case)
- `module_code`: Python code with `run_assessment()` function
- `description`: Human-readable description
- `platforms`: Comma-separated platform list

**Module Code Requirements:**
```python
def run_assessment():
    findings = []

    # Your assessment logic here
    findings.append({
        "severity": "high",  # critical, high, medium, low, info
        "title": "Finding title",
        "description": "Detailed description",
        "confidence_score": 85,  # 0-100
        "evidence": ["proof1", "proof2"],
        "remediation": "How to fix this",
        "references": ["https://example.com/cve"]
    })

    return {
        "findings": findings
    }
```

**Example:**
```python
module_code = '''
def run_assessment():
    findings = []
    # Check for Docker socket exposure
    import os
    if os.path.exists('/var/run/docker.sock'):
        findings.append({
            "severity": "high",
            "title": "Docker Socket Exposed",
            "description": "Docker socket is accessible",
            "confidence_score": 100,
            "evidence": ["/var/run/docker.sock exists"]
        })
    return {"findings": findings}
'''

add_custom_module(
    "docker_exposure_check",
    module_code,
    "Check for exposed Docker socket",
    "Linux"
)
```

### 9. `get_available_modules(platform=None)`

List all available assessment modules.

**Parameters:**
- `platform`: Optional filter ("windows" or "linux")

**Returns:**
- List of modules with descriptions
- Platform compatibility
- Priority levels

**Example:**
```python
get_available_modules()
get_available_modules("linux")
```

### 10. `execute_shell_command(agent_id, command)`

Execute a shell command on an agent.

**WARNING:** Only use for authorized security assessments.

**Parameters:**
- `agent_id`: Target agent's unique identifier
- `command`: Shell command to execute

**Returns:**
- Command execution status
- Queue confirmation

**Example:**
```python
execute_shell_command("abc-123-def", "whoami")
```

## Framework Management Scripts

### framework_starter.py

Manage the operator server independently.

**Start server in background:**
```bash
python framework_starter.py start
```

**Start server in foreground:**
```bash
python framework_starter.py start --foreground
```

**Check server status:**
```bash
python framework_starter.py status
```

**Stop server:**
```bash
python framework_starter.py stop
```

**Restart server:**
```bash
python framework_starter.py restart
```

## LLM Conversation Examples

### Example 1: Initial Setup

**User:** "I need to perform a security assessment on a Linux system. Can you help me set this up?"

**LLM:** "I'll help you set up the C2 Security Assessment Framework. Let me start by checking the framework status..."

*[LLM calls `get_framework_status()`]*

**LLM:** "The operator server is not running. Let me start it for you..."

*[LLM calls `start_operator_server()`]*

**LLM:** "Great! The operator server is now running. Now I'll generate a Linux agent for you to deploy on the target system..."

*[LLM calls `generate_agent("linux")`]*

**LLM:** "Agent generated successfully! Here's what you need to do:
1. Transfer the agent file to your target Linux system
2. Copy the 'modules' directory to the same location
3. Run: python agent_linux_abc12345.py
4. Once the agent checks in, I can run the security assessment"

### Example 2: Running Assessment

**User:** "The agent is now running. Can you perform a comprehensive security assessment?"

**LLM:** "Perfect! Let me first check which agents are connected..."

*[LLM calls `list_agents()`]*

**LLM:** "I can see your Linux agent (ID: abc-123-def) is active. I'll now run all compatible security assessment modules..."

*[LLM calls `run_assessment("abc-123-def", "all")`]*

**LLM:** "I've queued 9 security modules for execution:
- reconnaissance
- privilege_escalation
- persistence
- credential_harvesting
- lateral_movement
- data_access
- data_exfiltration
- c2_comms
- covering_tracks

The agent will execute these automatically. Give it about 30-60 seconds to complete..."

### Example 3: Custom Module Addition

**User:** "Can you add a check for exposed API keys in environment variables?"

**LLM:** "I'll create a custom module to check for exposed API keys in environment variables..."

*[LLM calls `add_custom_module()` with appropriate code]*

**LLM:** "Custom module 'api_key_exposure' has been added successfully! Would you like me to run it on your agent?"

### Example 4: Results and Reporting

**User:** "Please show me the assessment results."

**LLM:** "Let me retrieve the assessment results..."

*[LLM calls `get_assessment_results("abc-123-def")`]*

**LLM:** "The assessment has completed. Here's a summary:
- Total modules executed: 9
- Critical findings: 2
- High severity findings: 5
- Medium severity findings: 8
- Low severity findings: 12

Would you like me to generate a detailed report? I can create it in HTML, JSON, or Markdown format."

**User:** "Yes, generate an HTML report."

*[LLM calls `generate_report("abc-123-def", "html")`]*

**LLM:** "HTML report generated successfully! You can find it at: /path/to/report.html

The report includes:
- Executive summary with risk scoring
- Detailed findings sorted by severity
- Confidence scores for each finding
- Interactive charts and visualizations
- Remediation recommendations"

## API Endpoints (Operator Server)

The operator server exposes these endpoints for MCP integration:

### GET `/api/mcp/capabilities`

Get framework capabilities.

**Response:**
```json
{
  "framework": "C2 Security Assessment Framework",
  "version": "1.0",
  "features": {
    "agent_generation": true,
    "dynamic_modules": true,
    "multi_platform": true,
    "report_generation": true,
    "confidence_scoring": true
  },
  "supported_platforms": ["Windows", "Linux"],
  "available_modules": [...],
  "report_formats": ["console", "json", "html", "markdown"]
}
```

### POST `/api/mcp/add_module`

Add a custom module dynamically.

**Request:**
```json
{
  "module_name": "custom_check",
  "module_code": "def run_assessment(): ...",
  "description": "Custom security check",
  "platforms": ["Linux", "Windows"]
}
```

**Response:**
```json
{
  "status": "success",
  "module_name": "custom_check",
  "description": "Custom security check",
  "platforms": ["Linux", "Windows"],
  "module_file": "/path/to/module.py",
  "message": "Module added successfully"
}
```

## Security Considerations

1. **Authorization**: Only use for authorized security testing
2. **Network Isolation**: Use on isolated test networks
3. **Data Handling**: Assessment results may contain sensitive information
4. **Access Control**: Protect the operator server with appropriate access controls
5. **Audit Logging**: All MCP operations are logged for audit purposes

## Troubleshooting

### Server Won't Start

**Problem:** Operator server fails to start

**Solution:**
```bash
# Check if port 8542 is already in use
python framework_starter.py status

# Stop any existing server
python framework_starter.py stop

# Start fresh
python framework_starter.py start
```

### MCP Connection Issues

**Problem:** LLM cannot connect to MCP server

**Solution:**
1. Verify MCP server is running: `python mcp_server.py`
2. Check operator server status: `python framework_starter.py status`
3. Verify configuration in LLM client

### Agent Not Checking In

**Problem:** Generated agent doesn't appear in agent list

**Solution:**
1. Verify agent is running on target system
2. Check network connectivity to operator server
3. Verify operator URL in agent configuration
4. Check firewall rules on both systems

### Module Execution Fails

**Problem:** Assessment modules don't execute

**Solution:**
1. Check agent platform compatibility
2. Verify modules are compatible with agent OS
3. Check agent logs for errors
4. Ensure proper permissions on target system

## Advanced Usage

### Custom LLM Workflows

You can create custom workflows by chaining MCP tools:

```
1. get_framework_status()
2. start_operator_server() (if needed)
3. generate_agent(platform)
4. [User deploys agent]
5. list_agents() (verify agent checked in)
6. run_assessment(agent_id, "reconnaissance")
7. get_assessment_results(agent_id)
8. [LLM analyzes results]
9. add_custom_module() (based on findings)
10. run_assessment(agent_id, custom_module)
11. generate_report(agent_id, "html")
```

### Integration with Other Tools

The MCP server can be integrated with other security tools:

- **SIEM Integration**: Send results to SIEM via JSON export
- **Ticketing Systems**: Create tickets from high-severity findings
- **CI/CD Pipelines**: Automated security testing in pipelines
- **Custom Dashboards**: Build dashboards using the API

## Support

For issues, questions, or contributions:
- GitHub: https://github.com/ihtisham77/aipostassisster
- Documentation: See README.md for core framework details

## License

This framework is for authorized security testing only. Ensure you have proper authorization before using on any systems.
