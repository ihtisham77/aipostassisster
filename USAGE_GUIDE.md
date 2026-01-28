# C2 Security Assessment Framework - Usage Guide

## Quick Start (Simplified Workflow)

### 1. Start the Operator Server

The server now runs on port **8542** by default:

```bash
python3 operator/server.py
```

The server will display:
- Server URL (http://0.0.0.0:8542)
- Local IP address for agent connections
- Configuration status

### 2. Generate Agents (Auto-Detection)

**No need to specify URL anymore!** The agent generator automatically detects the server:

```bash
# For Windows agent
python3 operator/agent_generator.py windows

# For Linux agent
python3 operator/agent_generator.py linux
```

The generator will:
- Auto-detect the server IP and port
- Show the operator URL being used
- Create the agent in `generated_agents/` directory

**Optional:** Override the URL if needed:
```bash
python3 operator/agent_generator.py linux http://custom-server:8542
```

### 3. Use the Operator CLI (Auto-Detection)

**Simply run:**
```bash
python3 operator/cli.py
```

The CLI will:
- Automatically connect to http://localhost:8542
- Show connection status
- Display active/total agents

**Optional:** Connect to a different server:
```bash
python3 operator/cli.py http://custom-server:8542
```

---

## Configuration System

### Configuration Priority

The framework uses a multi-layered configuration system with this priority:

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **config.json file**
4. **Default values** (lowest priority)

### config.json

Located in the project root:

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

You can override configuration using environment variables:

```bash
# Set operator URL
export OPERATOR_URL="http://192.168.1.100:8542"

# Set server port
export OPERATOR_PORT=9000

# Set server host
export OPERATOR_HOST="0.0.0.0"

# Set agent checkin interval
export CHECKIN_INTERVAL=60
```

**Example:**
```bash
export OPERATOR_URL="http://192.168.1.50:8542"
python3 operator/agent_generator.py linux
# Will use 192.168.1.50:8542 automatically
```

---

## Report Generation

### Generate Reports from CLI

The framework now includes professional report generation in multiple formats:

```bash
operator> report <agent_id> [format] [output_dir]
```

**Formats:**
- `all` - Generate JSON, Markdown, and HTML reports (default)
- `json` - JSON format only
- `markdown` or `md` - Markdown format only
- `html` - HTML format only

**Examples:**

```bash
# Generate all formats
operator> report abc123def456 all reports/

# Generate only HTML report
operator> report abc123def456 html

# Generate markdown report in custom directory
operator> report abc123def456 markdown /tmp/reports
```

### Report Features

#### Executive Summary
- Overall risk score (0-100)
- Risk level (Critical, High, Medium, Low, Minimal)
- Total findings by severity
- Key security concerns (top 3-5 issues)
- Target system information

#### Statistics
- Total findings
- Severity distribution
- Module coverage
- Findings by module

#### Detailed Findings
- Organized by severity (Critical → High → Medium → Low → Info)
- Each finding includes:
  - Description
  - Module source
  - Remediation steps
  - Severity badge

#### Recommendations
- Immediate actions (critical priority)
- High priority actions
- Remediation roadmap

### Command-Line Report Generation

You can also generate reports directly:

```bash
python3 operator/report_generator.py <server_url> <agent_id> [format] [output_dir]
```

**Example:**
```bash
python3 operator/report_generator.py http://localhost:8542 abc123def456 all reports/
```

### Report Output

Reports are saved with descriptive filenames:
```
report_<hostname>_<agent_id>_<timestamp>.<format>
```

**Example:**
```
report_web-server-01_abc123de_20260116_143022.html
report_web-server-01_abc123de_20260116_143022.md
report_web-server-01_abc123de_20260116_143022.json
```

---

## CLI Commands Reference

### Connection Commands

```bash
# Auto-connect to default server
python3 operator/cli.py

# Connect to specific server
python3 operator/cli.py http://server-ip:8542
```

### Agent Management

```bash
# List all agents
operator> agents

# Check agent status and details
operator> agents
```

### Assessment Modules

```bash
# List available modules
operator> modules

# Run specific module
operator> module <agent_id> privilege_escalation
operator> module <agent_id> credential_harvesting
operator> module <agent_id> reconnaissance
```

### Shell Commands

```bash
# Execute shell command on agent
operator> shell <agent_id> whoami
operator> shell <agent_id> uname -a
operator> shell <agent_id> ps aux
```

### Results

```bash
# View assessment results
operator> results <agent_id>
```

### Report Generation

```bash
# Generate comprehensive report
operator> report <agent_id>

# Generate specific format
operator> report <agent_id> html
operator> report <agent_id> markdown

# Specify output directory
operator> report <agent_id> all /tmp/reports
```

### Agent Generation

```bash
# Generate agent (auto-detects URL)
operator> generate windows
operator> generate linux

# Generate with custom URL
operator> generate linux http://custom:8542
```

### Help & Exit

```bash
# Show help
operator> help

# Exit CLI
operator> exit
```

---

## API Reference

### Input Validation

All API endpoints now include comprehensive input validation:

#### POST /api/register
Register a new agent.

**Required Fields:**
- `agent_id` (string, UUID format)
- `hostname` (string, 1-255 chars)
- `platform` (string, 1-100 chars)

**Validation:**
- Agent ID must be valid UUID
- All strings must be within length limits
- Returns 400 on validation failure

**Example:**
```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "hostname": "web-server-01",
  "platform": "Linux 5.4.0"
}
```

#### POST /api/checkin
Agent check-in for commands.

**Required Fields:**
- `agent_id` (string, UUID format)

**Returns:**
- Pending command if available
- `null` command if no commands queued

#### POST /api/results
Submit assessment results.

**Required Fields:**
- `agent_id` (string, UUID format)
- `module` (string, 1-100 chars)
- `results` (object)

**Validation:**
- Results must be a JSON object
- Module name must be valid string

#### POST /api/command
Queue command for agent.

**Required Fields:**
- `agent_id` (string, UUID format)
- `command` (object)

**Command Object:**
```json
{
  "type": "module",
  "module": "privilege_escalation"
}
```

or

```json
{
  "type": "shell",
  "cmd": "whoami"
}
```

**Validation:**
- Command type must be 'module' or 'shell'
- Module commands must have 'module' field
- Shell commands must have 'cmd' field

#### GET /api/agents
List all registered agents.

**No parameters required.**

#### GET /api/results/<agent_id>
Get results for specific agent.

**URL Parameter:**
- `agent_id` (string)

#### GET /api/health
Server health check.

**Returns:**
```json
{
  "status": "online",
  "active_agents": 2,
  "total_agents": 5
}
```

---

## Advanced Usage

### Custom Configuration

Create a custom config file:

```bash
python3 operator/config.py
```

This creates `config.json` with default values.

Edit the file to customize:
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 9000,
    "inactive_timeout": 600
  },
  "agent": {
    "checkin_interval": 60,
    "command_timeout": 60
  },
  "operator": {
    "default_server_url": "http://myserver:9000"
  }
}
```

### Remote Server Setup

1. **Start server on remote machine:**
```bash
# On server (192.168.1.100)
python3 operator/server.py
```

2. **Configure clients:**
```bash
# Option 1: Environment variable
export OPERATOR_URL="http://192.168.1.100:8542"

# Option 2: config.json
# Edit operator/default_server_url to "http://192.168.1.100:8542"

# Option 3: Command line
python3 operator/cli.py http://192.168.1.100:8542
```

### Batch Report Generation

Generate reports for all agents:

```bash
#!/bin/bash
# Save as generate_all_reports.sh

SERVER_URL="http://localhost:8542"

# Get all agent IDs
AGENT_IDS=$(curl -s $SERVER_URL/api/agents | jq -r '.agents[].agent_id')

# Generate report for each agent
for agent_id in $AGENT_IDS; do
  echo "Generating report for $agent_id..."
  python3 operator/report_generator.py $SERVER_URL $agent_id all reports/
done

echo "All reports generated!"
```

### Automated Assessment Workflow

```bash
#!/bin/bash
# Complete assessment workflow

# 1. Start server
python3 operator/server.py &
SERVER_PID=$!
sleep 2

# 2. Generate and deploy agent
python3 operator/agent_generator.py linux
# ... deploy agent to target ...

# 3. Run assessments via CLI
python3 -c "
from operator.cli import OperatorCLI
cli = OperatorCLI('http://localhost:8542')

# Wait for agent to register
import time
time.sleep(5)

# Get agent ID
import requests
agents = requests.get('http://localhost:8542/api/agents').json()['agents']
agent_id = agents[0]['agent_id']

# Run all modules
modules = [
    'privilege_escalation',
    'persistence',
    'credential_harvesting',
    'reconnaissance',
    'lateral_movement',
    'data_access',
    'data_exfiltration',
    'c2_comms',
    'covering_tracks'
]

for module in modules:
    cli.run_module(agent_id, module)
    time.sleep(10)  # Wait for completion

# Generate report
cli.generate_report(agent_id, 'all', 'reports/')
"

# Cleanup
kill $SERVER_PID
```

---

## Troubleshooting

### Server Won't Start

**Issue:** Port 8542 already in use

**Solution:**
```bash
# Option 1: Change port in config.json
# Option 2: Use environment variable
export OPERATOR_PORT=9000
python3 operator/server.py

# Option 3: Kill process using port
lsof -ti:8542 | xargs kill -9
```

### Agent Can't Connect

**Issue:** Connection refused

**Solution:**
1. Verify server is running
2. Check firewall rules
3. Verify IP address is correct:
```bash
# On server machine
ip addr show
# Use the correct network interface IP
```

### Auto-Detection Not Working

**Issue:** Agent generator can't detect server

**Solution:**
```bash
# Manually specify URL
python3 operator/agent_generator.py linux http://192.168.1.100:8542
```

### Report Generation Fails

**Issue:** No results for agent

**Solution:**
1. Verify agent has completed assessments:
```bash
operator> results <agent_id>
```

2. Run assessment modules first:
```bash
operator> module <agent_id> reconnaissance
# Wait for completion
operator> report <agent_id>
```

### Permission Denied on Reports

**Issue:** Can't write to reports directory

**Solution:**
```bash
# Create directory with proper permissions
mkdir -p reports
chmod 755 reports

# Or specify different directory
operator> report <agent_id> all /tmp/reports
```

---

## Security Notes

### Input Validation

All API endpoints now validate:
- UUID format for agent IDs
- String length limits
- Required fields presence
- Data type correctness
- Command type validation

Invalid requests return:
- HTTP 400 (Bad Request) for validation errors
- HTTP 404 (Not Found) for missing resources
- Descriptive error messages

### Best Practices

1. **Use HTTPS in production** (currently HTTP only)
2. **Implement authentication** (not yet included)
3. **Restrict network access** to server port
4. **Rotate agent IDs** regularly
5. **Secure report storage** (contains sensitive findings)
6. **Audit all commands** sent to agents
7. **Clean up inactive agents** regularly
8. **Review reports** before sharing

---

## Next Steps

After setting up the framework:

1. **Run basic assessment:**
   - Start server
   - Generate agent
   - Deploy to test system
   - Run reconnaissance module
   - Generate report

2. **Review findings:**
   - Open HTML report in browser
   - Review risk score
   - Prioritize critical findings
   - Plan remediation

3. **Expand assessment:**
   - Run additional modules
   - Test multiple systems
   - Compare reports
   - Track improvements

4. **Customize:**
   - Adjust configuration
   - Modify checkin intervals
   - Customize report templates
   - Add custom modules (see README)

---

For more information, see:
- README.md - Project overview and features
- operator/config.py - Configuration system
- operator/report_generator.py - Report generation
- agent/modules/ - Assessment modules
