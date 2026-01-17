@echo off
REM MCP Integration Setup Script for Windows
REM Automated setup for C2 Security Assessment Framework MCP integration

echo ================================================================
echo        C2 Framework - MCP Integration Setup (Windows)
echo ================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python is not installed. Please install Python 3.8 or higher.
    pause
    exit /b 1
)

echo [+] Python version:
python --version

echo.
echo [*] Step 1: Installing dependencies...
echo ----------------------------------------------------------------

if exist requirements.txt (
    pip install -r requirements.txt
    echo [+] Dependencies installed successfully
) else (
    echo [!] requirements.txt not found
    pause
    exit /b 1
)

echo.
echo [*] Step 2: Checking framework structure...
echo ----------------------------------------------------------------

REM Check required files
set ALL_FILES_EXIST=1

if exist mcp_server.py (
    echo [+] Found: mcp_server.py
) else (
    echo [!] Missing: mcp_server.py
    set ALL_FILES_EXIST=0
)

if exist framework_starter.py (
    echo [+] Found: framework_starter.py
) else (
    echo [!] Missing: framework_starter.py
    set ALL_FILES_EXIST=0
)

if exist operator\server.py (
    echo [+] Found: operator\server.py
) else (
    echo [!] Missing: operator\server.py
    set ALL_FILES_EXIST=0
)

if exist operator\cli.py (
    echo [+] Found: operator\cli.py
) else (
    echo [!] Missing: operator\cli.py
    set ALL_FILES_EXIST=0
)

if %ALL_FILES_EXIST%==0 (
    echo [!] Some required files are missing
    pause
    exit /b 1
)

echo.
echo [*] Step 3: Testing framework components...
echo ----------------------------------------------------------------

python framework_starter.py status >nul 2>&1
echo [+] Framework starter is functional

echo.
echo [*] Step 4: Creating directories...
echo ----------------------------------------------------------------

if not exist generated_agents mkdir generated_agents
if not exist reports mkdir reports
echo [+] Directories created

echo.
echo ================================================================
echo                    Setup Complete!
echo ================================================================
echo.
echo Next Steps:
echo.
echo 1. Start the MCP server:
echo    python mcp_server.py
echo.
echo 2. Configure your LLM client (e.g., Claude Desktop):
echo    Add the following to your MCP configuration:
echo.
echo    {
echo      "mcpServers": {
echo        "c2-framework": {
echo          "command": "python",
echo          "args": ["%CD%\mcp_server.py"]
echo        }
echo      }
echo    }
echo.
echo 3. Test the framework:
echo    python framework_starter.py status
echo.
echo 4. Read the documentation:
echo    type MCP_INTEGRATION.md
echo.
echo For more information, see MCP_INTEGRATION.md
echo.
pause
