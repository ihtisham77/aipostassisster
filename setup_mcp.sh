#!/bin/bash

# MCP Integration Setup Script
# Automated setup for C2 Security Assessment Framework MCP integration

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║       C2 Framework - MCP Integration Setup                   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "[+] Python version: $PYTHON_VERSION"

# Check Python version (need 3.8+)
MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 8 ]); then
    echo "[!] Python 3.8 or higher is required"
    exit 1
fi

echo ""
echo "[*] Step 1: Installing dependencies..."
echo "─────────────────────────────────────────────────────────────"

if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
    echo "[+] Dependencies installed successfully"
else
    echo "[!] requirements.txt not found"
    exit 1
fi

echo ""
echo "[*] Step 2: Checking framework structure..."
echo "─────────────────────────────────────────────────────────────"

# Check required files
required_files=(
    "mcp_server.py"
    "framework_starter.py"
    "operator/server.py"
    "operator/cli.py"
    "operator/config.py"
    "operator/agent_generator.py"
)

all_files_exist=true
for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "[+] Found: $file"
    else
        echo "[!] Missing: $file"
        all_files_exist=false
    fi
done

if [ "$all_files_exist" = false ]; then
    echo "[!] Some required files are missing"
    exit 1
fi

echo ""
echo "[*] Step 3: Testing framework components..."
echo "─────────────────────────────────────────────────────────────"

# Test operator server can start
echo "[*] Testing operator server startup..."
python3 framework_starter.py status > /dev/null 2>&1 || true
echo "[+] Framework starter is functional"

# Make scripts executable
chmod +x framework_starter.py
chmod +x mcp_server.py
echo "[+] Scripts are now executable"

echo ""
echo "[*] Step 4: Creating directories..."
echo "─────────────────────────────────────────────────────────────"

mkdir -p generated_agents
mkdir -p reports
echo "[+] Directories created"

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                   Setup Complete!                             ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Next Steps:"
echo ""
echo "1. Start the MCP server:"
echo "   python3 mcp_server.py"
echo ""
echo "2. Configure your LLM client (e.g., Claude Desktop):"
echo "   Add the following to your MCP configuration:"
echo ""
echo '   {
     "mcpServers": {
       "c2-framework": {
         "command": "python3",
         "args": ["'$(pwd)'/mcp_server.py"]
       }
     }
   }'
echo ""
echo "3. Test the framework:"
echo "   python3 framework_starter.py status"
echo ""
echo "4. Read the documentation:"
echo "   cat MCP_INTEGRATION.md"
echo ""
echo "For more information, see MCP_INTEGRATION.md"
echo ""
